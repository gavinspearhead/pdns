// TODO
// parametrize Rank with IP address type
// improve filter on livedump

#![allow(non_camel_case_types)]
pub mod config;
pub mod dns;
pub mod dns_answers;
pub mod dns_cache;
pub mod dns_class;
pub mod dns_helper;
pub mod dns_name;
pub mod dns_opcodes;
pub mod dns_packet;
pub mod dns_protocol;
pub mod dns_record;
pub mod dns_record_trait;
pub mod dns_reply_type;
pub mod dns_rr;
pub mod dns_rr_type;
pub mod ech;
pub mod edns;
pub mod errors;
pub mod http_server;
pub mod live_dump;
pub mod mysql_connection;
pub mod network_packet;
pub mod packet_info;
pub mod packet_queue;
pub mod rank;
pub mod rr;
pub mod skiplist;
pub mod statistics;
pub mod tcp_connection;
pub mod tcp_data;
pub mod time_stats;
pub mod util;
pub mod version;

use crate::config::Config;
use crate::http_server::listen;
use crate::network_packet::parse_eth;
use crate::packet_info::Packet_info;
use crate::statistics::Statistics;
use crate::util::load_asn_database;
use crate::util::read_public_suffix_file;
use crate::version::{PROGNAME, VERSION};
use chrono::{DateTime, Utc};
use clap::{arg, Parser};
use config::parse_config;
use dns_cache::DNS_Cache;
use futures::executor::block_on;
use live_dump::Live_dump;
use mysql_connection::{create_database, Mysql_connection};
use packet_queue::Packet_Queue;
use parking_lot::Mutex;
use pcap::{Activated, Active, Capture, Linktype};
use signal_hook::iterator::Signals;
use skiplist::Skip_List;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::exit;
use std::str::{self, FromStr};
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc};
use std::thread::sleep;
use std::{io, thread, time};
use tcp_connection::{clean_tcp_list, TCP_Connections};
use tracing::{debug, error};
use tracing_rfc_5424::layer::Layer;
use tracing_rfc_5424::transport::UnixSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, prelude::*, reload};
use daemonize_me::{Daemon, Group, User};

#[derive(Parser, Clone, Debug, PartialEq)]
struct Args {
    #[arg(short, long)]
    path: std::path::PathBuf,
}

fn packet_loop<T: Activated + 'static>(cap: &mut Capture<T>, packet_queue: &Packet_Queue) {
    let link_type = cap.get_datalink();
    if link_type != Linktype::ETHERNET {
        error!("Not ethernet {link_type:?}");
        exit(-1);
    }

    debug!("Starting loop");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = DateTime::<Utc>::from_timestamp(
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec as u32 * 1000,
                )
                .unwrap_or_else(Utc::now);
                packet_queue.push_back(Some((packet.data.to_vec(), ts)));
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

fn write_output(of: &mut File, p1: &Packet_info, config: &Config) {
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
}

fn parse_dns_packet(
    packet_queue: &Packet_Queue,
    skip_list: &Skip_List,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
) -> Option<Option<Packet_info>> {
    let mut packet_info = Packet_info::new();
    if let Some(a_packet) = packet_queue.pop_front() {
        match a_packet {
            Some((packet, ts)) => {
                packet_info.set_timestamp(ts);
                let result = parse_eth(
                    &packet,
                    &mut packet_info,
                    &mut stats.lock(),
                    tcp_list,
                    config,
                    skip_list,
                );
                match result {
                    Err(error) => debug!("{error:?}"),
                    Ok(()) => return Some(Some(packet_info)),
                }
            }
            None => {
                return Some(None);
            }
        }
    }
    None
}

fn poll(
    packet_queue: &Packet_Queue,
    config: &Config,
    rx: mpsc::Receiver<String>,
    skip_list: &Skip_List,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
) {
    let mut output_file: Option<File> = None;

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
    let publicsuffixlist: publicsuffix::List = read_public_suffix_file(&config.public_suffix_file);
    let mut timeout = 50;
    let mut live_dump = Live_dump::new(&config.live_dump_host, config.live_dump_port);
    let mut dns_cache: DNS_Cache = DNS_Cache::new(15);
    let mut last_push = Utc::now().timestamp();
    loop {
        live_dump.accept();
        live_dump.read_all();

        let packet_info = parse_dns_packet(packet_queue, skip_list, stats, tcp_list, config);
        if let Some(p) = packet_info {
            if let Some(mut p1) = p {
                if !p1.dns_records.is_empty() {
                    p1.update_asn(&asn_database);
                    p1.update_public_suffix(&publicsuffixlist);
                    live_dump.write_all(&p1);
                    if config.output == "-" {
                        println!("{p1}");
                    }

                    if let Some(ref mut of) = output_file {
                        write_output(of, &p1, config);
                    }
                    if let Some(ref _db) = database_conn {
                        for dns_record in p1.dns_records {
                            dns_cache.add(dns_record);
                        }
                    }
                }
                timeout = 0;
            } else {
                debug!("Terminating poll()");
                return;
            }
        } else {
            sleep(time::Duration::from_millis(timeout as u64));
            if timeout < 1000 {
                timeout += 50;
            }
        }
        let current_time = Utc::now().timestamp();
        if current_time > last_push + timeout || dns_cache.len() > dns_cache.get_max_size() {
            //debug!("Popping packets {current_time} {last_push:#?}:{timeout:#?}");
            db_insert(&mut dns_cache, &mut database_conn, &mut last_push, false);
        }
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => {
                db_insert(&mut dns_cache, &mut database_conn, &mut last_push, true);
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
    force: bool,
) -> i64 {
    if let Some(ref mut db) = database_conn {
        let (records, timeout) = dns_cache.push_timed(force);
        for i in records {
            db.insert_or_update_record(&i);
        }
        *last_push = Utc::now().timestamp();
        return timeout;
    }
    dns_cache.timeout()
}

fn cleanup_task(config: &Config) {
    if !config.database.is_empty() {
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
}

fn terminate_loop(stats: &Arc<Mutex<Statistics>>, config: &Arc<Config>) {
    let mut signals =
        match Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register signal handler: {}", e);
                exit(-1);
            }
        };
    let stats_clone = Arc::clone(stats);
    let config_clone = Arc::clone(config); // config;
    thread::spawn(move || {
        debug!("Waiting for termination...");
        for sig in signals.forever() {
            debug!("Received signal: {:?}", sig);
            stats_clone.lock().dump_stats(&config_clone, true).unwrap();
            exit(-1);
        }
    });

    debug!("Waiting for termination...");
    thread::park(); // Keep the main thread alive
    debug!("Waiting for termination... done");
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
    let cap = Capture::from_file(pcap_path);
    match cap {
        Ok(mut c) => {
            if let Err(e) = c.filter(&config.filter, false) {
                error!("Cannot apply filter {}: {e}", config.filter);
                exit(-2);
            }
            thread::scope(|s| {
                let handle_tcp_list = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));
                let handle_poll = s.spawn(|| {
                    poll(
                        &packet_queue.clone(),
                        config,
                        pq_rx,
                        skiplist,
                        stats,
                        tcp_list,
                    )
                });
                let handle_packet_loop = s.spawn(|| {
                    packet_loop(&mut c, &packet_queue.clone());
                });
                handle_packet_loop.join().unwrap();
                // we wait for the main threat to terminate; then cancel the tcp cleanup threat
                let _ = tcp_tx.send(String::from_str("the end").unwrap());
                handle_poll.join().unwrap();
                handle_tcp_list.join().unwrap();
            });
        }
        Err(e) => {
            error!("Error reading PCAP file: {e:?}");
            exit(-2);
        }
    }
}

fn capture_from_interface(
    config: &Config,
    skiplist: &Skip_List,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    packet_queue: &Packet_Queue,
    mut cap_in: Capture<Active>,
) {
    debug!("Listening on interface {}", config.interface);
    let (_pq_tx, pq_rx) = mpsc::channel();
    let (tcp_tx, tcp_rx) = mpsc::channel();
    debug!("Filter: {}", config.filter);
    if let Err(e) = cap_in.filter(&config.filter, false) {
        error!("Cannot apply filter {}: {e}", config.filter);
        exit(-1);
    }
    let config_arc = Arc::new(config.clone());

    thread::scope(|s| {
        let handle_tcp_list = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));
        let handle_poll = s.spawn(|| {
            poll(
                &packet_queue.clone(),
                config,
                pq_rx,
                skiplist,
                stats,
                tcp_list,
            )
        });
        let handle_http = s.spawn(|| {
            let _ = listen(&stats, &tcp_list, &config);
        });
        let handle_stats_dump = s.spawn(|| stats_dump(config, &stats));
        let handle_cleanup = s.spawn(|| cleanup_task(config));
        let handle_packet_loop = s.spawn(|| {
            packet_loop(&mut cap_in, packet_queue);
        });

        terminate_loop(stats, &config_arc);
        let _ = handle_packet_loop.join();
        // we wait for the main threat to terminate; then cancel the tcp cleanup threat
        let _ = tcp_tx.send(String::from_str("the end").unwrap());
        let _ = handle_http.join();
        let _ = handle_cleanup.join();
        let _ = handle_tcp_list.join();
        let _ = handle_poll.join();
        let _ = handle_stats_dump.join();
    });
}

fn stats_dump(config: &Config, statistics: &Arc<Mutex<Statistics>>) {
    if config.stats_dump_interval > 0 {
        debug!(
            "stats interval {} to file {}",
            config.stats_dump_interval, &config.export_stats
        );
        loop {
            if let Err(e) = statistics.lock().dump_stats(config, false) {
                error!("Cannot dump stats: {e}");
            }
            sleep(time::Duration::from_secs(config.stats_dump_interval as u64));
        }
    }
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
        let Some(cap) = cap_in else {
            error!("Something wrong with the capture");
            exit(-1);
        };
        capture_from_interface(config, &skiplist, stats, &tcp_list, &packet_queue, cap);
    }
}

fn devnull() -> io::Result<File> {
    File::open("/dev/null")
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
    debug!("Config is: {:?}", config);
    if !config.interface.is_empty() {
        // do it here otherwise PCAP hangs on open if we do it after daemonizing
        debug!("Interface: {}", config.interface);
        cap = match Capture::from_device(config.interface.as_str())
            .unwrap()
            .timeout(1000)
            .promisc(config.promisc)
            .open()
        {
            Ok(x) => Some(x),
            Err(e) => {
                error!(
                    "Cannot open capture on interface '{}' {e}",
                    &config.interface
                );
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
        let daemon = Daemon::new()
            .pid_file(&config.pid_file, Some(false))
            .work_dir("/tmp")
            .user(User::try_from(&config.uid).expect("Invalid user"))
            .group(Group::try_from(&config.gid).expect("Invalid group"))
            .umask(0o077)
            .stdout(devnull().expect("Cannot open /dev/null"))
            .stderr(devnull().expect("Cannot open /dev/null"));

        match daemon.start() {
            Ok(()) => {
                debug!("Daemonised");
                run(&config, cap, &pcap_path, &stats);
            }
            Err(e) => {
                error!("Error daemonising: {}", e);
                exit(-1);
            }
        }
    } else {
        debug!("NOT Daemonising");
        run(&config, cap, &pcap_path, &stats);
    }
}
