// TODO
// - Look at timestamp utc vs local time?
// parametrize Rank with IP address type
// ASN / prefix determination

#![allow(non_camel_case_types)]
pub mod config;
pub mod dns;
pub mod dns_cache;
pub mod dns_helper;
pub mod dns_rr;
pub mod http_server;
pub mod mysql_connection;
pub mod packet_info;
pub mod rank;
pub mod skiplist;
pub mod statistics;
pub mod tcp_connection;
pub mod tcp_data;
pub mod version;
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use clap::{arg, Parser};
use colored::Colorize;
use config::parse_config;
use dns::{dns_reply_type, DNS_RR_type, DNS_record};
use dns_cache::DNS_Cache;
use dns_helper::{dns_read_u16, dns_read_u32, parse_class, parse_rrtype};
use dns_rr::{dns_parse_name, dns_parse_rdata};
use futures::executor::block_on;
use mysql_connection::{create_database, Mysql_connection};
use pcap::{Active, Capture, Linktype};
use publicsuffix::Psl;
use regex::Regex;
use skiplist::read_skip_list;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::exit;
use std::str::{self, FromStr};
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc, Mutex};
use std::{thread, time};
use syslog::Facility;
use tcp_connection::{clean_tcp_list, TCP_Connections};
use version::PROGNAME;

use crate::config::Config;
use crate::http_server::{listen, server};
use crate::packet_info::Packet_info;
use crate::statistics::Statistics;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DNS_Protocol {
    TCP,
    UDP,
}

fn match_skip_list(name: &str, skip_list: &[Regex]) -> bool {
    for i in skip_list {
        let r = i;
        if r.is_match(&name.trim_end_matches('.')) {
            return true;
        }
    }
    return false;
}

fn parse_question(
    _query: &[u8],
    _packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    _config: &Config,
    rcode: u16,
    skip_list: &[Regex],
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, offset) = dns_parse_name(packet, offset_in)?;
    if match_skip_list(&name, skip_list) {
        return Err(format!("skipped: {}", name).into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let rrtype = parse_rrtype(rrtype_val)?;
    let class_val = dns_read_u16(packet, offset + 2)?;
    let _rrtype = parse_rrtype(rrtype_val)?;
    let _class = parse_class(class_val)?;
    stats
        .qtypes
        .entry(rrtype.to_str()?)
        .and_modify(|c| *c += 1)
        .or_insert(1);
    let len = offset - offset_in;
    if rcode == 3 {
        stats.topnx.add(name);
    } else if rcode == 0 {
        stats.topdomain.add(name);
    }
    return Ok(len + 4);
}

fn parse_answer(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    config: &Config,
    publicsuffixlist: &publicsuffix::List,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;
    let rrtype_val = BigEndian::read_u16(&packet[offset..offset + 2]);
    let rrtype = parse_rrtype(rrtype_val)?;
    if rrtype == DNS_RR_type::OPT {
        return Ok(0);
    }
    if !config.rr_type.contains(&rrtype) {
        return Ok(0);
    }
    let class_val = dns_read_u16(packet, offset + 2)?;
    let class = parse_class(class_val)?;
    let ttl = dns_read_u32(packet, offset + 4)?;
    let datalen: usize = dns_read_u16(packet, offset + 8)?.into();
    let data = &packet[offset + 10..offset + 10 + datalen];
    let rdata = dns_parse_rdata(data, rrtype, packet, offset + 10)?;
    stats
        .atypes
        .entry(rrtype.to_str()?)
        .and_modify(|c| *c += 1)
        .or_insert(1);
    offset += 11;
    /*     println!(
        "Answer N: {} L:{} RR:{} C:{} TTL:{} DL:{} D:{:x?} R: {} ",
        name,
        offset,
        rrtype.to_str().unwrap(),
        class.to_str().unwrap(),
        ttl,
        datalen,
        data,
        rdata
    );*/

    let domain = publicsuffixlist.domain(name.as_bytes());
    let mut domain_str = String::new();
    //println!("{:?} == {:?}", domain, domain_str);
    match domain {
        Some(d) => {
            let x = d.trim().as_bytes().to_vec();
            domain_str = String::from_utf8(x).unwrap_or(String::new());
            //            domain_str = String::from_str(str::from_utf8(d.as_bytes()).or(Ok(""))?)?;
            //println!("{:?}", domain_str);
        }
        None => {
            log::debug!("Not found {}", name);
        }
    }

    let rec: DNS_record = DNS_record {
        rr_type: rrtype.to_str()?,
        ttl: ttl,
        class: class.to_str()?,
        //name: name.trim_end_matches('.').to_string(),
        name: name,
        rdata: rdata,
        //rdata: rdata.trim_end_matches('.').to_string(),
        count: 1,
        timestamp: packet_info.timestamp,
        domain: domain_str,
        asn: String::new(),
        asn_owner: String::new(),
        prefix: String::new(),
    };
    packet_info.add_dns_record(rec);
    offset += datalen as usize - 1;
    let len = offset - offset_in;
    return Ok(len);
}

fn parse_dns(
    packet_in: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;
    let mut _len = 0;
    let mut packet = packet_in;
    if packet_info.protocol == DNS_Protocol::TCP {
        _len = dns_read_u16(packet, offset)?;
        packet = &packet_in[2..];
    }
    let _trans_id = dns_read_u16(packet, offset)?;
    offset += 2;
    let flags = dns_read_u16(packet, offset)?;
    offset += 2;
    let qr = (flags & 0x8000) >> 15;
    let _opcode = (flags >> 11) & 0x000f;
    let tr = (flags >> 9) & 0x0001;
    let _rd = (flags >> 8) & 0x0001;
    let _ra = (flags >> 7) & 0x0001;
    let rcode = flags & 0x000f;

    if tr != 0 {
        // truncated DNS packets are skipped
        return Ok(());
    }

    let questions = dns_read_u16(packet, offset)?;
    if questions == 0 {
        // Empty questions section --> Skip it
        return Ok(());
    }

    offset += 2;
    let answers = dns_read_u16(packet, offset)?;
    offset += 2;
    let authority = dns_read_u16(packet, offset)?;
    offset += 2;
    let additional = dns_read_u16(packet, offset)?;
    offset += 2;
    stats.additional += additional as u128;
    stats.authority += authority as u128;
    stats.answers += answers as u128;
    stats.queries += questions as u128;

    if qr != 1 {
        // we ignore questions
        //stats.sources.add(&packet_info.s_addr.to_string());
        //stats.destinations.add(&packet_info.d_addr.to_string());
        stats.sources.add(packet_info.s_addr.to_string());
        stats.destinations.add(packet_info.d_addr.to_string());
        return Ok(());
    }

    stats
        .errors
        .entry(dns_reply_type(rcode)?.to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);

    for _i in 0..questions {
        let query = &packet[offset..];
        offset += parse_question(
            query,
            packet_info,
            packet,
            offset,
            stats,
            config,
            rcode,
            skip_list,
        )?;
    }
    //println!("Answers {} {} ", answers, offset);
    for _i in 0..answers {
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    //println!("Authority {} {}", authority, offset);
    for _i in 0..authority {
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    //println!("Additional {} {}", additional, offset);
    for _i in 0..additional {
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    return Ok(());
}

fn parse_tcp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 20 {
        return Err("Invalid IP header".into());
    }
    let sp: u16 = dns_read_u16(packet, 0)?;
    let dp: u16 = dns_read_u16(packet, 2)?;
    if !(dp == 53 || sp == 53 || dp == 5353 || sp == 5353) {
        return Err("Not a DNS packet".into());
    }
    //println!("TCP!!");
    let hl: u8 = (packet[12] >> 4) * 4;
    let len: u32 = (packet.len() - hl as usize) as u32;
    let flags = packet[13];
    let _wsize = dns_read_u16(packet, 14)?;
    let seqnr = dns_read_u32(packet, 4)?;

    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(len);
    //        println! ("{} {} {} {} {}  {} {:x?}", flags, hl, sp, dp , len, &packet[12]>>4, &packet[..32]);

    let Some(dnsdata) = packet.get((hl as usize)..) else {
        //println!("{} {} {} {:x?}", flags, hl, &packet[12] >> 4, &packet[..32]);
        return Err("Parse Error TCP".into());
    };
    //println!("{:x?}", dnsdata);
    //println!("{}", "2 Locking.... ".blue());
    let r = tcp_list.lock().unwrap().process_data(
        sp,
        dp,
        packet_info.s_addr,
        packet_info.d_addr,
        seqnr,
        dnsdata,
        packet_info.timestamp,
        flags,
    );
    //println!("{}", "2 UnLocking.... ".red());
    match r {
        Some(d) => {
            stats.tcp += 1;
            //println!("Parsing TCP!!");
            return parse_dns(
                &d.data(),
                packet_info,
                stats,
                config,
                skip_list,
                publicsuffixlist,
            );
        }
        None => {}
    };

    return Ok(());
}

fn parse_udp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 8 {
        return Err("Invalid UDP header".into());
    }
    let sp: u16 = dns_read_u16(packet, 0)?;
    let dp: u16 = dns_read_u16(packet, 2)?;
    let len: u16 = dns_read_u16(packet, 4)?;
    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(len as u32 - 8);

    if dp == 53 || sp == 53 || dp == 5353 || sp == 5353 {
        stats.udp += 1;
        return parse_dns(
            &packet[8..],
            packet_info,
            stats,
            config,
            skip_list,
            publicsuffixlist,
        );
    } else {
        return Err(format!("Not a dns packet {} {}", dp, sp).into());
    }
}

fn parse_ip_data(
    packet: &[u8],
    protocol: u8,
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("IP data {:x?}", &packet);
    if protocol == 6 {
        packet_info.set_protocol(DNS_Protocol::TCP);
        // TCP
        return parse_tcp(
            &packet,
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        );
    } else if protocol == 17 {
        packet_info.set_protocol(DNS_Protocol::UDP);
        //  UDP
        return parse_udp(
            &packet,
            packet_info,
            stats,
            config,
            skip_list,
            publicsuffixlist,
        );
    }
    return Ok(());
}

fn parse_ipv4(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("IPv4 {:x?}", &packet[..40]);
    if packet.len() < 20 {
        return Err("Invalid IPv6 packet".into());
    }
    if packet[0] >> 4 != 4 {
        return Err(format!("Invalid IP version {:x?}", &packet[0] >> 4).into());
    }
    let ihl: u16 = ((packet[0] & 0xf) as u16) * 4;
    let mut t: [u8; 4] = packet[12..16].try_into()?;
    let src = Ipv4Addr::from(t);
    t = packet[16..20].try_into()?;
    let dst = Ipv4Addr::from(t);
    let len: u16 = dns_read_u16(packet, 2)? - ihl;
    let next_header = packet[9] as u8;
    packet_info.set_dest_ip(std::net::IpAddr::V4(dst));
    packet_info.set_source_ip(std::net::IpAddr::V4(src));
    packet_info.set_ip_len(len);
    return parse_tunneling(
        &packet[ihl as usize..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
        publicsuffixlist,
    );
    /*parse_ip_data(
        &packet[ihl as usize..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
        publicsuffixlist,
    )?;
    return Ok(());*/
}

fn parse_tunneling(
    packet: &[u8],
    next_header: u8,
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("{}", next_header);
    if next_header == 4 {
        // IPIP
        if packet.len() < 1 {
            return Err("Packet to small".into());
        }
        let ip_ver = packet[0] >> 4;
        //println!("{}", ip_ver);
        if ip_ver == 4 {
            return parse_ipv4(
                &packet,
                packet_info,
                stats,
                tcp_list,
                config,
                skip_list,
                publicsuffixlist,
            );
        } else if ip_ver == 6 {
            return parse_ipv6(
                &packet,
                packet_info,
                stats,
                tcp_list,
                config,
                skip_list,
                publicsuffixlist,
            );
        } else {
            return Err("Unknown IP version".into());
        }
    } else {
        //println!("Normal IP data {:x?}", &packet);

        parse_ip_data(
            &packet,
            next_header,
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        )?;
        //println!("{:?}", &packet_info);
    }
    return Ok(());
}

fn parse_ipv6(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("IPv6 {:x?}", &packet[..40]);
    if packet.len() < 40 {
        return Err("Invalid IPv6 packet".into());
    }
    let mut t: [u8; 16] = packet[8..24].try_into()?;
    let src = Ipv6Addr::from(t);
    let _len: u16 = dns_read_u16(packet, 4)?;
    t = packet[24..40].try_into()?;
    let dst = Ipv6Addr::from(t);
    if packet[0] >> 4 != 6 {
        return Err(format!("Invalid IP version {:x?}", &packet[0] >> 4).into());
    }
    packet_info.set_dest_ip(std::net::IpAddr::V6(dst));
    packet_info.set_source_ip(std::net::IpAddr::V6(src));

    let next_header = packet[6];
    return parse_tunneling(
        &packet[40..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
        publicsuffixlist,
    );
}

fn parse_eth(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    packet_info.frame_len = packet.len() as _;
    let mut offset = 12;
    let mut eth_type_field = dns_read_u16(packet, offset)?;
    offset += 2;
    //println!("1 {:x}", eth_type_field);

    if eth_type_field == 0x8100 {
        // vlan tag
        // println!("VLAN");
        offset += 2;
        eth_type_field = dns_read_u16(packet, offset)?;
        // println!("2 {:x}", eth_type_field);
        // println!(" {:x?}", packet.get(12..24).unwrap());
        offset += 2;
    }

    if eth_type_field == 0x0800 {
        //   println!("IPv4");
        return parse_ipv4(
            &packet[offset..],
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        );
    } else if eth_type_field == 0x86dd {
        return parse_ipv6(
            &packet[offset..],
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        );
    } else {
        return Err(format!("Unknown packet type {:x?}", &packet[12..14]).into());
    }
}

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    path: std::path::PathBuf,
}

fn packet_loop<T: pcap::State>(
    mut cap: Capture<T>,
    packet_queue: &Arc<Mutex<VecDeque<Option<Packet_info>>>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    stats: &Arc<Mutex<Statistics>>,
    config: &Config,
    skip_list: &[Regex],
) where
    T: pcap::Activated,
{
    //    println!("{:#?}", cap.get_datalink());
    let link_type = cap.get_datalink();

    if link_type != Linktype::ETHERNET {
        log::error!("Not ethernet {:?}", link_type);
        panic!("Not ethernet");
    }
    log::debug!("Reading pubsuf list {}", config.public_suffix_file);
    let publicsuffixlist: publicsuffix::List = match fs::read_to_string(&config.public_suffix_file)
    {
        Ok(c) => match c.as_str().parse() {
            Ok(d) => d,
            Err(_) => {
                log::error!(
                    "Cannot parse public suffic file: {}",
                    config.public_suffix_file
                );
                exit(-1);
            }
        },
        Err(_) => {
            log::error!("Cannot read file {}", config.public_suffix_file);
            exit(-1);
        }
    };
    log::debug!("Starting loop");
    while let Ok(packet) = cap.next_packet() {
        log::debug!("Packet");
        //        eprintln!("{:?}", cap.stats().unwrap());
        let mut packet_info: Packet_info = Default::default();
        let ts = match DateTime::<Utc>::from_timestamp(
            packet.header.ts.tv_sec,
            packet.header.ts.tv_usec as u32 * 1000,
        ) {
            Some(x) => x,
            None => Utc::now(), //let mut last_push = Utc::now().timestamp() as u64;
        };
        packet_info.set_timestamp(ts);
        let result = parse_eth(
            &packet.data,
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
                log::debug!("{}", format!("{:?}", error));
            }
        }
    }
    packet_queue.lock().unwrap().push_back(None);
}

fn poll(
    packet_queue: &Arc<Mutex<VecDeque<Option<Packet_info>>>>,
    config: &Config,
    rx: mpsc::Receiver<String>,
) {
    //println!("Polling....");
    let mut timeout = time::Duration::from_millis(0);
    let mut output_file: Option<File> = None;
    let mut database_conn: Option<Mysql_connection> = None;
    let mut dns_cache: DNS_Cache = DNS_Cache::new(5);
    let mut last_push = Utc::now().timestamp() as u64;
    if config.output != "" && config.output != "-" {
        let mut options = OpenOptions::new();
        output_file = Some(
            options
                .append(true)
                .create(true)
                .open(&config.output)
                .expect("Cannot open file"),
        );
    }

    if config.database != "" {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));
        database_conn = Some(x);
    }
    let asn_database = match asn_db2::Database::from_reader(BufReader::new(
        match File::open(&config.asn_database_file) {
            Ok(x) => x,
            Err(e) => {
                log::error!(
                    "Cannot open asn database {} {}",
                    &config.asn_database_file,
                    e
                );
                exit(-1);
            }
        },
    )) {
        Ok(x) => x,
        Err(e) => {
            log::error!(
                "Cannot read asn database {}: {}",
                &config.asn_database_file,
                e
            );
            exit(-1);
        }
    };

    loop {
        let packet_info = packet_queue.lock().unwrap().pop_front();
        match packet_info {
            Some(p) => match p {
                Some(mut p1) => {
                    p1.update_asn(&asn_database);
                    if config.output == "-" {
                        if !p1.dns_records.is_empty() {
                            println!("{}", p1);
                        }
                    }
                    match output_file {
                        Some(ref mut of) => {
                            if config.output_type == "csv" {
                                of.write(p1.to_csv().as_str().as_bytes())
                                    .expect("Write failed");
                            } else if config.output_type == "json" {
                                of.write(p1.to_json().as_str().as_bytes())
                                    .expect("Write failed");
                            }
                        }
                        None => {}
                    };
                    match database_conn {
                        Some(ref _db) => {
                            for i in p1.dns_records {
                                dns_cache.add(&i);
                            }
                        }
                        None => {}
                    }

                    timeout = time::Duration::from_millis(0);
                }
                None => {
                    //println!("Terminating poll()");
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
        if ct > (last_push as u64) + dns_cache.timeout() {
            //println!("{} {}", dns_cache, last_push);
            match database_conn {
                Some(ref mut db) => {
                    for i in dns_cache.push_all() {
                        db.insert_or_update_record(&i);
                    }
                    last_push = Utc::now().timestamp() as u64;
                }
                None => {}
            }
        }
        match rx.try_recv() {
            Ok(_e) => {
                match database_conn {
                    Some(ref mut db) => {
                        for i in dns_cache.push_all() {
                            db.insert_or_update_record(&i);
                        }
                        return;
                    }
                    None => {}
                }
                //println!("{} {:?}", "Disconnect".yellow(), _e);
                return;
            }
            Err(TryRecvError::Disconnected) => {
                match database_conn {
                    Some(ref mut db) => {
                        for i in dns_cache.push_all() {
                            db.insert_or_update_record(&i);
                        }
                        return;
                    }
                    None => {}
                } //println!("{}", "Lost connection".yellow());
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
        //        println!("{} {:?}", "sleeping".cyan(), dur);
    }
}

fn run(config: &Config, capin: Option<Capture<Active>>, pcap_path: &str) {
    // println!("{:?}", config);
    let packet_queue = Arc::new(Mutex::new(VecDeque::new()));
    let tcp_list = Arc::new(Mutex::new(TCP_Connections::new()));
    let stats = Arc::new(Mutex::new(Statistics::origin(config.toplistsize)));
    let (tcp_tx, tcp_rx) = mpsc::channel();
    let (_pq_tx, pq_rx) = mpsc::channel();
    let skiplist = read_skip_list(&config.skip_list_file);
    thread::scope(|s| {
        let handle = s.spawn(|| poll(&packet_queue.clone(), &config, pq_rx));
        let handle2 = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));

        if pcap_path != "" {
            let cap = Capture::from_file(&pcap_path);
            match cap {
                Ok(mut c) => {
                    match c.filter(config.filter.as_str().as_ref(), false) {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("Cannot apply filter {}: {}", config.filter, e)
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
                    panic!("{}", format!("{:?}", e).red());
                }
            }
        } else if config.interface != "" {
            log::debug!("Listening on interface {}", config.interface);
            let listener = listen(&config.server, config.port.clone());
            let handle4 = s.spawn(|| match listener {
                Some(l) => server(l, &stats.clone(), &tcp_list.clone(), &config.clone()),
                None => {}
            });
            let Some(mut cap) = capin else {
                log::error!("Something wrong with the capture");
                panic!("Something wrong with the capture");
            };
            log::debug!("Filter: {}", config.filter);

            match cap.filter(config.filter.as_str(), false) {
                Ok(()) => {}
                Err(e) => {
                    log::error!("Cannot apply filter {}: {}", config.filter, e)
                }
            }
            //cap.filter(config.filter.as_str(), false).unwrap();

            log::debug!("Ready to start packet loop");
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
    //println!("{:#?}", stats.lock().unwrap().to_str());
}

fn main() {
    syslog::init(Facility::LOG_USER, log::LevelFilter::Info, Some(PROGNAME))
        .expect("Logging failed");

    let mut config = Config::new();
    let mut pcap_path = String::new();
    let mut create_db: bool = false;
    parse_config(&mut config, &mut pcap_path, &mut create_db);

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
    if config.interface != "" {
        // do it here otherwise PCAP hangs on open if we do it after daemonizing
        cap = Some(
            Capture::from_device(config.interface.as_str())
                .unwrap()
                .timeout(1000)
                .promisc(true) // todo make a paramater
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
        log::debug!("Daemonising");
        match daemonize.start() {
            Ok(_) => {
                log::debug!("Daemonising2");
                run(&config, cap, &pcap_path);
            }
            Err(_e) => {
                log::error!("Error daemonizing {}", _e);
                exit(-1);
            }
        }
    } else {
        log::debug!("NOT Daemonising");
        run(&config, cap, &pcap_path);
    }
}
