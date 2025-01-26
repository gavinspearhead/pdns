// TODO
// parametrize Rank with IP address type
// improve filter on livedump

#![allow(non_camel_case_types)]
pub mod config;
pub mod dns;
pub mod dns_cache;
pub mod dns_helper;
pub mod dns_packet;
pub mod dns_record;
pub mod dns_rr;
pub mod edns;
pub mod errors;
pub mod http_server;
pub mod live_dump;
pub mod mysql_connection;
pub mod network_packet;
pub mod packet_info;
pub mod rank;
pub mod skiplist;
pub mod statistics;
pub mod tcp_connection;
pub mod tcp_data;
pub mod time_stats;
pub mod util;
pub mod version;

use chrono::{DateTime, Utc};
use clap::{arg, Parser};
use config::parse_config;
use dns_cache::DNS_Cache;
use futures::executor::block_on;
use live_dump::Live_dump;
use mysql_connection::{create_database, Mysql_connection};
use packet_info::Packet_Queue;
use pcap::{Activated, Active, Capture, Linktype};
use signal_hook::flag;
use skiplist::Skip_List;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::process::exit;
use std::str::{self, FromStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::sleep;
use std::{thread, time};
use tcp_connection::{clean_tcp_list, TCP_Connections};
use tracing::{debug, error};
use tracing_rfc_5424::layer::Layer;
use tracing_rfc_5424::transport::UnixSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, prelude::*, reload};

use crate::config::Config;
use crate::http_server::listen;
use crate::network_packet::parse_eth;
use crate::packet_info::Packet_info;
use crate::statistics::Statistics;
use crate::version::{PROGNAME, VERSION};

#[derive(Parser, Clone, Debug, PartialEq)]
struct Args {
    #[arg(short, long)]
    path: std::path::PathBuf,
}

fn dump_stats(stats: &Statistics, config: &Config) -> std::io::Result<()> {
    if config.export_stats.is_empty() {
        return Ok(());
    }
    let filename_base = &config.export_stats;
    let mut count = 0;
    loop {
        let date_as_string = Utc::now().to_rfc3339();
        let filename = Path::new(filename_base).join(format!("stats-{date_as_string}.json"));
        match File::create_new(&filename) {
            Ok(f) => {
                debug!("Dumping stats to {filename:?}");
                let mut writer = BufWriter::new(f);
                serde_json::to_writer_pretty(&mut writer, stats)?;
                writer.flush()?;
                return Ok(());
            }
            Err(e) => {
                count += 1;
                if count > 5 {
                    return Err(e);
                }
            }
        }
    }
}

fn read_public_suffix_file(public_suffix_file : &str)->publicsuffix::List
{
    debug!("Reading pubsuf list {}", public_suffix_file);
    if let Ok(c) = fs::read_to_string(public_suffix_file) {
        if let Ok(d) = c.as_str().parse() {
            d
        } else {
            error!( "Cannot parse public suffic file: {public_suffix_file}" );
            exit(-1);
        }
    } else {
        error!("Cannot read file {public_suffix_file}",);
        exit(-1);
    }
}

fn packet_loop<T: Activated>(
    mut cap: Capture<T>,
    packet_queue: &Packet_Queue,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    stats: &Arc<Mutex<Statistics>>,
    config: &Config,
    skip_list: &Skip_List,
) {
    let link_type = cap.get_datalink();
    if link_type != Linktype::ETHERNET {
        error!("Not ethernet {link_type:?}");
        exit(-1);
    }
    //let publicsuffixlist: publicsuffix::List = read_public_suffix_file(config.public_suffix_file.as_str());
        
    debug!("Starting loop");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let mut packet_info = Packet_info::new();
                let ts = DateTime::<Utc>::from_timestamp(
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec as u32 * 1000,
                )
                .unwrap_or_else(Utc::now);
                packet_info.set_timestamp(ts);
                let result = parse_eth(
                    packet.data,
                    &mut packet_info,
                    &mut stats.lock().unwrap(),
                    tcp_list,
                    config,
                    skip_list,
                  //  &publicsuffixlist,
                );
                match result {
                    Ok(()) => packet_queue.push_back(Some(packet_info)),
                    Err(error) => debug!("{error:?}"),
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                debug!("Packet capture error: {}", pcap::Error::TimeoutExpired);
            }
            Err(e) => {
                error!("Packet capture error: {e}");
                packet_queue.push_back(None);
                break;
            }
        }
    }
}

fn load_asn_database(config: &Config) -> asn_db2::Database {
    debug!("ASN Database: {}", config.asn_database_file);
    let Ok(f) = File::open(&config.asn_database_file) else {
        error!("Cannot open ASN database {} ", &config.asn_database_file);
        exit(-1);
    };
    let Ok(asn_database) = asn_db2::Database::from_reader(BufReader::new(f)) else {
        error!("Cannot read ASN database {}", &config.asn_database_file);
        exit(-1);
    };
    asn_database
}

fn poll(packet_queue: &Packet_Queue, config: &Config, rx: mpsc::Receiver<String>) {
    let mut timeout = time::Duration::from_millis(0);
    let mut output_file: Option<File> = None;
    let mut dns_cache: DNS_Cache = DNS_Cache::new(5);
    let mut live_dump = Live_dump::new(&config.live_dump_host, config.live_dump_port);

    if !config.output.is_empty() && config.output != "-" {
        let mut options = OpenOptions::new();
        output_file = match options.append(true).create(true).open(&config.output) {
            Ok(x) => Some(x),
            Err(e) => {
                error!("Cannot open file {} {e}", config.output);
                exit(-1);
            }
        };
    }

    let mut database_conn = if config.database.is_empty() {
        None
    } else {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));
        Some(x)
    };
    let asn_database = load_asn_database(config);
    let publicsuffixlist: publicsuffix::List = read_public_suffix_file(config.public_suffix_file.as_str());
    let mut last_push = Utc::now().timestamp();
    loop {
        live_dump.accept();
        live_dump.read_all();
        let packet_info = packet_queue.pop_front();
        if let Some(p) = packet_info {
            if let Some(mut p1) = p {
                p1.update_asn(&asn_database);
                p1.update_public_suffix(&publicsuffixlist);
                if !p1.dns_records.is_empty() {
                    if config.output == "-" {
                        println!("{p1}");
                    }
                    live_dump.write_all(&p1);
                }

                if let Some(ref mut of) = output_file {
                    if config.output_type == "csv" {
                        if let Err(e) = of.write_all(p1.to_csv().as_bytes()) {
                            error!("Write csv output failed, {e}");
                            exit(-1);
                        }
                    } else if config.output_type == "json" {
                        if let Err(e) = of.write_all(p1.to_json().as_bytes()) {
                            error!("Write json output failed, {e}");
                            exit(-1);
                        }
                    }
                };
                if let Some(ref _db) = database_conn {
                    for dns_record in p1.dns_records {
                        dns_cache.add(dns_record);
                    }
                }
                timeout = time::Duration::from_millis(0);
            } else {
                debug!("Terminating poll()");
                return;
            }
        } else {
            sleep(timeout);
            if timeout.as_millis() < 500 {
                timeout += time::Duration::from_millis(50);
            }
        }

        let ct = Utc::now().timestamp();
        if ct > last_push + dns_cache.timeout() {
            db_insert(&mut dns_cache, &mut database_conn, &mut last_push);
        }
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => {
                db_insert(&mut dns_cache, &mut database_conn, &mut last_push);
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

fn db_insert(
    dns_cache: &mut DNS_Cache,
    database_conn: &mut Option<Mysql_connection>,
    last_push: &mut i64,
) {
    if let Some(ref mut db) = database_conn {
        for i in dns_cache.push_all() {
            db.insert_or_update_record(&i);
        }
        *last_push = Utc::now().timestamp();
    }
}

fn cleanup_task(config: &Config) {
    if config.database.is_empty() {
        return;
    }
    loop {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));
        x.clean_database(config);
        sleep(time::Duration::from_secs(24 * 3600));
    }
}

fn terminate_loop(stats: &Arc<Mutex<Statistics>>, config: &Config) {
    debug!("Starting signal loop");
    let term = Arc::new(AtomicBool::new(false));
    let kill = Arc::new(AtomicBool::new(false));
    if let Err(e) = flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term)) {
        error!("Cannot set signal handler SIGTERM {e}");
        exit(-1);
    };
    if let Err(e) = flag::register(signal_hook::consts::SIGINT, Arc::clone(&kill)) {
        error!("Cannot set signal handler SIGINT {e}");
        exit(-1);
    }
    while !term.load(Ordering::Relaxed) && !kill.load(Ordering::Relaxed) {
        sleep(time::Duration::from_millis(50));
    }
    debug!("{}", stats.lock().unwrap().queries);
    dump_stats(&stats.lock().unwrap(), config).unwrap();
    exit(0);
}

fn capture_from_file(
    config: &Config,
    pcap_path: &str,
    skiplist: &Skip_List,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    packet_queue: &Packet_Queue,
) {
    let (_pq_tx, pq_rx) = mpsc::channel();
    let (tcp_tx, tcp_rx) = mpsc::channel();
    debug!("Reading PCAP file e {pcap_path}");
    thread::scope(|s| {
        let handle1 = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));
        let handle = s.spawn(|| poll(&packet_queue.clone(), config, pq_rx));
        let cap = Capture::from_file(pcap_path);
        match cap {
            Ok(mut c) => {
                if let Err(e) = c.filter(&config.filter, false) {
                    error!("Cannot apply filter {}: {e}", config.filter);
                    exit(-2);
                }
                let handle2 = s.spawn(|| {
                    packet_loop(
                        c,
                        &packet_queue.clone(),
                        &tcp_list.clone(),
                        &stats.clone(),
                        config,
                        skiplist,
                    );
                });
                handle2.join().unwrap();
                // we wait for the main threat to terminate; then cancel the tcp cleanup threat
                let _ = tcp_tx.send(String::from_str("the end").unwrap());
                handle.join().unwrap();
                handle1.join().unwrap();
            }
            Err(e) => {
                error!("Error reading PCAP file: {e:?}");
                exit(-2);
            }
        }
    });
}

fn capture_from_interface(
    config: &Config,
    skiplist: &Skip_List,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    packet_queue: &Packet_Queue,
    cap_in: Option<Capture<Active>>,
) {
    debug!("Listening on interface {}", config.interface);
    let (_pq_tx, pq_rx) = mpsc::channel();
    let (tcp_tx, tcp_rx) = mpsc::channel();
    thread::scope(|s| {
        let handle2 = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));
        let handle = s.spawn(|| poll(&packet_queue.clone(), config, pq_rx));
        // let listener = listen(&config.http_server, config.http_port);
        let handle4 = s.spawn(|| {
            let _ = listen(&stats.clone(), &tcp_list.clone(), &config.clone());
        });
        let Some(mut cap) = cap_in else {
            error!("Something wrong with the capture");
            exit(-1);
        };
        let handle6 = s.spawn(|| cleanup_task(config));
        debug!("Filter: {}", config.filter);
        if let Err(e) = cap.filter(&config.filter, false) {
            error!("Cannot apply filter {}: {e}", config.filter);
            exit(-1);
        }
        debug!("Ready to start packet loop");
        let handle3 = s.spawn(|| {
            debug!("Starting packet loop");
            packet_loop(cap, packet_queue, tcp_list, stats, config, skiplist);
        });
        let handle5 = s.spawn(|| {
            terminate_loop(stats, config);
        });

        handle3.join().unwrap();
        // we wait for the main threat to terminate; then cancel the tcp cleanup threat
        let _ = tcp_tx.send(String::from_str("the end").unwrap());
        handle4.join().unwrap();
        handle6.join().unwrap();
        handle2.join().unwrap();
        handle.join().unwrap();
        handle5.join().unwrap();
    });
}

fn run(
    config: &Config,
    cap_in: Option<Capture<Active>>,
    pcap_path: &str,
    stats: &Arc<Mutex<Statistics>>,
) {
    let packet_queue = Packet_Queue::new();
    let tcp_list = Arc::new(Mutex::new(TCP_Connections::new(config.tcp_memory)));
    let mut skiplist = Skip_List::new();
    skiplist.read_skip_list(&config.skip_list_file);
    if !pcap_path.is_empty() {
        capture_from_file(
            config,
            pcap_path,
            &skiplist,
            stats,
            &tcp_list,
            &packet_queue,
        );
    } else if !config.interface.is_empty() {
        capture_from_interface(config, &skiplist, stats, &tcp_list, &packet_queue, cap_in);
    }
}

fn main() {
    let mut pcap_path = String::new();
    let mut config = Config::new();
    let layers = vec![fmt::Layer::default().boxed()];
    let filter = filter::LevelFilter::WARN;
    let (filter, reload_handle) = reload::Layer::new(filter);
    let (tracing_layers, reload_handle1) = reload::Layer::new(layers);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_layers)
        .init();
    parse_config(&mut config, &mut pcap_path);

    if config.debug {
        let _ = reload_handle.modify(|filter| *filter = filter::LevelFilter::DEBUG);
    }

    debug!("Config is: {:?}", config);
    if !config.log_file.is_empty() {
        debug!("Logging to {}", config.log_file);
        let _ = reload_handle1.modify(|layers| {
            let file = match OpenOptions::new()
                .append(true)
                .create(true)
                .open(&config.log_file)
            {
                Ok(f) => f,
                Err(e) => {
                    error!("Cannot create file {} {e}", config.log_file);
                    exit(-1);
                }
            };
            let layer = tracing_subscriber::fmt::layer().with_writer(file).boxed();
            (*layers).push(layer);
        });
    }

    if config.syslog {
        let _ = reload_handle1.modify(|layers| {
            (*layers).push(
                Layer::with_transport(UnixSocket::new("/var/run/systemd/journal/syslog").unwrap())
                    .boxed(),
            );
        });
    }

    debug!("Starting {PROGNAME} {VERSION}");

    if config.create_db {
        create_database(&config);
        exit(0);
    }

    let mut cap = None;
    if !config.interface.is_empty() {
        // do it here otherwise PCAP hangs on open if we do it after daemonizing
        debug!("Interface: {}", config.interface);
        cap = match Capture::from_device(config.interface.as_str())
            .unwrap()
            .timeout(1000)
            .promisc(config.promisc)
            //                .immediate_mode(true) //seems to break on ubuntu?
            .open()
        {
            Ok(x) => Some(x),
            Err(e) => {
                error!("Cannot open capture on interface '{}' {e}", &config.interface );
                exit(-1);
            }
        };
    }
    /*let mut options = OpenOptions::new();
    std::fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    );*/
    let stats = if config.import_stats.is_empty() {
        Arc::new(Mutex::new(Statistics::new(config.toplistsize)))
    } else {
        debug!("import stats from : {}", config.import_stats);
        Arc::new(Mutex::new(
            match Statistics::import(&config.import_stats, config.toplistsize) {
                Ok(x) => x,
                Err(e) => {
                    error!("Cannot import file '{}' {e}", config.import_stats);
                    exit(-1);
                }
            },
        ))
    };

    if config.daemon {
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
        .umask(0o077) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr); // Redirect stderr to `/tmp/daemon.err`. 
        debug!("Daemonising");
        match daemonize.start() {
            Ok(()) => {
                debug!("Daemonised");
                run(&config, cap, &pcap_path, &stats);
            }
            Err(e) => {
                error!("Error daemonising {e}");
                exit(-1);
            }
        }
    } else {
        debug!("NOT Daemonising");
        run(&config, cap, &pcap_path, &stats);
    }
}
