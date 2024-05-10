// TODO
// - Look at timestamp utc vs local time?
// parametrize Rank with IP address type

#![allow(non_camel_case_types)]
pub mod config;
pub mod dns;
pub mod dns_cache;
pub mod dns_helper;
pub mod dns_packet;
pub mod dns_rr;
pub mod errors;
pub mod http_server;
pub mod mysql_connection;
pub mod packet_info;
pub mod rank;
pub mod skiplist;
pub mod statistics;
pub mod tcp_connection;
pub mod tcp_data;
pub mod version;
use chrono::{DateTime, Utc};
use clap::{arg, Parser};
use colored::Colorize;
use config::parse_config;
use dns_cache::DNS_Cache;
use futures::executor::block_on;
use mysql_connection::{create_database, Mysql_connection};
use pcap::{Active, Capture, Linktype};
use regex::Regex;
use skiplist::read_skip_list;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::net::TcpStream;
use std::process::exit;
use std::str::{self, FromStr};
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc, Mutex};
use std::{thread, time};
use tcp_connection::{clean_tcp_list, TCP_Connections};
use tracing::{debug, error};
use tracing_rfc_5424::layer::Layer;
use tracing_rfc_5424::transport::UnixSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, prelude::*, reload}; // Needed to get `with()`

use crate::config::Config;
use crate::dns_packet::parse_eth;
use crate::http_server::{listen, server};
use crate::packet_info::Packet_info;
use crate::statistics::Statistics;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DNS_Protocol {
    TCP,
    UDP,
}

#[derive(Parser, Clone, Debug, PartialEq)]
struct Args {
    #[arg(short, long)]
    path: std::path::PathBuf,
}

fn packet_loop<T>(
    mut cap: Capture<T>,
    packet_queue: &Arc<Mutex<VecDeque<Option<Packet_info>>>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    stats: &Arc<Mutex<Statistics>>,
    config: &Config,
    skip_list: &[Regex],
) where
    T: pcap::Activated,
{
    let link_type = cap.get_datalink();
    if link_type != Linktype::ETHERNET {
        tracing::error!("Not ethernet {link_type:?}");
        //     return Err(Parse_error::new( errors::ParseErrorType::Invalid_IP_Version , &format!("{}", &packet[0]>>4)) .into());
        panic!("Not ethernet");
    }
    tracing::debug!("Reading pubsuf list {}", config.public_suffix_file);
    let publicsuffixlist: publicsuffix::List =
        if let Ok(c) = fs::read_to_string(&config.public_suffix_file) {
            if let Ok(d) = c.as_str().parse() {
                d
            } else {
                tracing::error!(
                    "Cannot parse public suffic file: {}",
                    config.public_suffix_file
                );
                exit(-1);
            }
        } else {
            tracing::error!("Cannot read file {}", config.public_suffix_file);
            exit(-1);
        };
    tracing::debug!("Starting loop");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let mut packet_info = Packet_info::default();
                let ts = match DateTime::<Utc>::from_timestamp(
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec as u32 * 1000,
                ) {
                    Some(x) => x,
                    None => Utc::now(), //let mut last_push = Utc::now().timestamp() as u64;
                };
                packet_info.set_timestamp(ts);
                let result = parse_eth(
                    packet.data,
                    &mut packet_info,
                    &mut stats.lock().unwrap(),
                    tcp_list,
                    config,
                    skip_list,
                    &publicsuffixlist,
                );
                match result {
                    Ok(_c) => {
                        packet_queue.lock().unwrap().push_back(Some(packet_info));
                    }
                    Err(error) => {
                        tracing::debug!("{:?}", error);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                debug!("Packet capture error: {}", pcap::Error::TimeoutExpired);
            }
            Err(e) => {
                error!("Packet capture error: {e}");
                packet_queue.lock().unwrap().push_back(None);
                break;
            }
        }
    }
}

fn load_asn_database(config: &Config) -> asn_db2::Database {
    tracing::debug!("{}", config.asn_database_file);
    //let asn_database =
    let Ok(f) = File::open(&config.asn_database_file) else {
        tracing::error!("Cannot open ASN database {} ", &config.asn_database_file);
        exit(-1);
    };
    let Ok(asn_database) = asn_db2::Database::from_reader(BufReader::new(f)) else {
        tracing::error!("Cannot read ASN database {}", &config.asn_database_file);
        exit(-1);
    };
    asn_database
}

fn poll(
    packet_queue: &Arc<Mutex<VecDeque<Option<Packet_info>>>>,
    config: &Config,
    rx: mpsc::Receiver<String>,
) {
    let mut timeout = time::Duration::from_millis(0);
    let mut output_file: Option<File> = None;
    let mut database_conn: Option<Mysql_connection> = None;
    let mut dns_cache: DNS_Cache = DNS_Cache::new(5);
    let mut last_push = Utc::now().timestamp() as u64;
    let Some(listener) = listen(&config.live_dump_host, config.live_dump_port.try_into().unwrap()) else {
        panic!("cannot listen on port")
    };
    let mut live_dump: Vec<TcpStream> = Vec::new();
    if !config.output.is_empty() && config.output != "-" {
        let mut options = OpenOptions::new();
        output_file = Some(
            options
                .append(true)
                .create(true)
                .open(&config.output)
                .expect("Cannot open file"),
        );
    }

    if !config.database.is_empty() {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));
        database_conn = Some(x);
    }
    let asn_database = load_asn_database(config);
    let Ok(_) = listener.set_nonblocking(true) else {
        panic!("cannot set non-b/locking");
    };
    loop {
        loop {
            match listener.accept() {
                Ok((socket, addr)) => {
                    debug!("New connection from {addr}");
                    live_dump.push(socket);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => error!("couldn't get client: {e:?}"),
            }
        }
        let packet_info = packet_queue.lock().unwrap().pop_front();
        match packet_info {
            Some(p) => match p {
                Some(mut p1) => {
                    p1.update_asn(&asn_database);
                    let mut x = Vec::new();
                    if !p1.dns_records.is_empty() {
                        if config.output == "-" {
                            println!("{p1}");
                        }
                        for (idx, mut stream) in (&live_dump).into_iter().enumerate() {
                            let tmp_str = &format!("{:#}", &p1);
                            match stream.write_all(&tmp_str.as_bytes()) {
                                Ok(_) => {}
                                Err(e) => {
                                    debug!("{}", e);
                                    x.push(idx);
                                }
                            }
                        }
                    }
                    for i in x {
                        debug!("Removing connection {}", i);
                        live_dump.remove(i);
                    }

                    if let Some(ref mut of) = output_file {
                        if config.output_type == "csv" {
                            of.write_all(p1.to_csv().as_bytes()).expect("Write failed");
                        } else if config.output_type == "json" {
                            of.write_all(p1.to_json().as_bytes()).expect("Write failed");
                        }
                    };
                    if let Some(ref _db) = database_conn {
                        for i in p1.dns_records {
                            dns_cache.add(&i);
                        }
                    }

                    timeout = time::Duration::from_millis(0);
                }
                None => {
                    tracing::debug!("Terminating poll()");
                    return;
                }
            },
            None => {
                thread::sleep(timeout);
                if timeout.as_millis() < 1000 {
                    timeout += time::Duration::from_millis(100);
                }
            }
        }
        let ct = Utc::now().timestamp() as u64;
        if ct > last_push + dns_cache.timeout() {
            if let Some(ref mut db) = database_conn {
                for i in dns_cache.push_all() {
                    db.insert_or_update_record(&i);
                }
                last_push = Utc::now().timestamp() as u64;
            }
        }
        match rx.try_recv() {
            Ok(_e) => {
                if let Some(ref mut db) = database_conn {
                    for i in dns_cache.push_all() {
                        db.insert_or_update_record(&i);
                    }
                }
                return;
            }
            Err(TryRecvError::Disconnected) => {
                if let Some(ref mut db) = database_conn {
                    for i in dns_cache.push_all() {
                        db.insert_or_update_record(&i);
                    }
                }
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

fn run(config: &Config, capin: Option<Capture<Active>>, pcap_path: &str) {
    let packet_queue = Arc::new(Mutex::new(VecDeque::new()));
    let tcp_list = Arc::new(Mutex::new(TCP_Connections::new()));
    let stats = Arc::new(Mutex::new(Statistics::origin(config.toplistsize)));
    let (tcp_tx, tcp_rx) = mpsc::channel();
    let (_pq_tx, pq_rx) = mpsc::channel();
    let skiplist = read_skip_list(&config.skip_list_file);
    thread::scope(|s| {
        let handle = s.spawn(|| poll(&packet_queue.clone(), config, pq_rx));
        let handle2 = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));

        if !pcap_path.is_empty() {
            let cap = Capture::from_file(pcap_path);
            match cap {
                Ok(mut c) => {
                    match c.filter(&config.filter, false) {
                        Ok(()) => {}
                        Err(e) => {
                            tracing::error!("Cannot apply filter {}: {}", config.filter, e);
                        }
                    }
                    let handle3 = s.spawn(|| {
                        packet_loop(
                            c,
                            &packet_queue.clone(),
                            &tcp_list.clone(),
                            &stats.clone(),
                            config,
                            &skiplist,
                        );
                    });
                    handle3.join().unwrap();
                    // we wait for the main threat to terminate; then cancel the tcp cleanup threat
                    let _ = tcp_tx.send(String::from_str("the end").unwrap());
                    handle.join().unwrap();
                    handle2.join().unwrap();
                }
                Err(e) => {
                    panic!("{}", format!("{e:?}").red());
                }
            }
        } else if !config.interface.is_empty() {
            tracing::debug!("Listening on interface {}", config.interface);
            let listener = listen(&config.server, config.port);
            let handle4 = s.spawn(|| {
                if let Some(l) = listener {
                    server(l, &stats.clone(), &tcp_list.clone(), &config.clone());
                }
            });
            let Some(mut cap) = capin else {
                tracing::error!("Something wrong with the capture");
                panic!("Something wrong with the capture");
            };
            tracing::debug!("Filter: {}", config.filter);
            if let Err(e) = cap.filter(&config.filter, false) {
                tracing::error!("Cannot apply filter {}: {e}", config.filter);
            }
            tracing::debug!("Ready to start packet loop");
            let handle3 = s.spawn(|| {
                packet_loop(cap, &packet_queue, &tcp_list, &stats, config, &skiplist);
            });
            handle3.join().unwrap();
            // we wait for the main threat to terminate; then cancel the tcp cleanup threat
            let _ = tcp_tx.send(String::from_str("the end").unwrap());
            handle4.join().unwrap();
            handle2.join().unwrap();
            handle.join().unwrap();
        }
    });
}

fn main() {
    let filter = filter::LevelFilter::WARN;
    let (filter, reload_handle) = reload::Layer::new(filter);
    tracing_subscriber::Registry::default()
        .with(filter)
        .with(fmt::Layer::default())
        .with(Layer::with_transport(
            UnixSocket::new("/var/run/systemd/journal/syslog").unwrap(),
        ))
        //  .with(Layer::with_transport(UdpTransport::new("127.0.0.1:514").unwrap()))
        .init();
    let mut config = Config::new();
    let mut pcap_path = String::new();
    let mut create_db: bool = false;
    parse_config(&mut config, &mut pcap_path, &mut create_db);
    if config.debug {
        let _ = reload_handle.modify(|filter| *filter = filter::LevelFilter::DEBUG);
    }

    if create_db {
        create_database(&config);
        exit(0);
    }
    let stdout = File::open("/dev/null").expect("Cannot open /dev/null");
    let stderr = File::open("/dev/null").expect("Cannot open /dev/null");
    //let stdout = File::open("/tmp/pdns.out").unwrap();
    //let stderr = File::open("/tmp/pdns.err").unwrap();
    let daemonize = daemonize::Daemonize::new()
        .pid_file("/var/run/pdns.pid") // Every method except `new` and `start`
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .working_directory("/tmp") // for default behaviour.
        .user(config.uid.as_str())
        .group(config.gid.as_str()) // Group name
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
        //.privileged_action(|| "Executed before drop privileges")
        ;
    let mut cap = None;
    if !config.interface.is_empty() {
        // do it here otherwise PCAP hangs on open if we do it after daemonizing
        cap = Some(
            Capture::from_device(config.interface.as_str())
                .unwrap()
                .timeout(1000)
                .promisc(config.promisc) // todo make a paramater
                //                .immediate_mode(true) //seems to brak on ubuntu?
                .open()
                .unwrap(),
        );
    }
    /*let mut options = OpenOptions::new();
    std::fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    );*/
    if config.daemon {
        tracing::debug!("Daemonising");
        match daemonize.start() {
            Ok(()) => {
                tracing::debug!("Daemonised");
                run(&config, cap, &pcap_path);
            }
            Err(e) => {
                tracing::error!("Error daemonising {e}");
                exit(-1);
            }
        }
    } else {
        tracing::debug!("NOT Daemonising");
        run(&config, cap, &pcap_path);
    }
}
