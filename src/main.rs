// TODO
// - Look at timestamp utc vs local time?
// parametrize Rank with IP address type
// gpos decoding

#![allow(non_camel_case_types)]
pub mod dns;
use base64::{engine::general_purpose, Engine as _};
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{arg, ArgAction, Command, Parser};
use colored::Colorize;
use core::fmt;
use dns::{
    cert_type_str, dns_reply_type, dnssec_algorithm, dnssec_digest, sshfp_algorithm, sshfp_fp_type,
    tlsa_algorithm, tlsa_cert_usage, tlsa_selector, zonemd_digest, DNS_Class, DNS_RR_type,
    DNS_record, SVC_Param_Keys,
};
use dns::{key_algorithm, key_protocol};
use futures::executor::block_on;
use pcap::{Active, Capture, Linktype};
use regex::Regex;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySql, Pool};
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::exit;
use std::str::{self, FromStr};
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::sleep;
use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};
use std::{thread, time};
use strum::{AsStaticRef, IntoEnumIterator};

#[derive(Debug, Clone)]
struct DNS_Cache {
    items: HashMap<(String, String, String), DNS_record>,
    timeout: u64,
}

impl DNS_Cache {
    fn new(time_out: u64) -> DNS_Cache {
        return DNS_Cache {
            items: HashMap::new(),
            timeout: time_out

        };
    }

    fn add(&mut self, record: &DNS_record) {
        self.items
            .entry((
                record.rr_type.clone(),
                record.name.clone(),
                record.rdata.clone(),
            ))
            .and_modify(|f| f.count += 1)
            .or_insert(record.clone());
    }

    fn push_all(&mut self) -> Vec<DNS_record> {
        let mut res = Vec::new();
        for (_k, v) in self.items.iter() {
            res.push(v.clone());
        }
        self.items.clear();
        return res;
    }
}

impl fmt::Display for DNS_Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (_k, v) in self.items.iter() {
            write!(f, "{}", v).expect("Cannot write output format ");
        }
        return write!(f, "");
    }
}

fn server(
    listener: TcpListener,
    stats: &Arc<Mutex<statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
) {
    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream, stats, tcp_list);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    stats: &Arc<Mutex<statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
) {
    let buf_reader = BufReader::new(&mut stream);
    let http_request: Vec<_> = buf_reader
        .lines()
        .map(|result| result.unwrap())
        .take_while(|line| !line.is_empty())
        .collect();

    let req: Vec<&str> = http_request[0].split(" ").collect();
    if req[0] != ("GET") {
        return;
    }
    let status_line = "HTTP/1.1 200 OK";
    if req[1] == ("/stats") {
        let stats_data = stats.lock().unwrap().clone();
        let stats_str = serde_json::to_string(&stats_data).unwrap();
        let len = stats_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{stats_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == ("/topdomains") {
        let top_domains = stats.lock().unwrap().topdomain.clone();
        let td_str = serde_json::to_string(&top_domains).unwrap();
        let len = td_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{td_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == ("/topnx") {
        let top_nx = stats.lock().unwrap().topnx.clone();
        let td_str = serde_json::to_string(&top_nx).unwrap();
        let len = td_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{td_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == ("/destinations") {
        let destinations = stats.lock().unwrap().destinations.clone();
        let d_str = serde_json::to_string(&destinations).unwrap();
        let len = d_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{d_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == ("/sources") {
        let sources = stats.lock().unwrap().sources.clone();
        let s_str = serde_json::to_string(&sources).unwrap();
        let len = s_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{s_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == ("/debug") {
        let tcp_len = tcp_list.lock().unwrap().len();
        let debug_str = format!("TCP LEN: {}\r\n", tcp_len);
        let len = debug_str.len();
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{debug_str}");
        stream.write_all(response.as_bytes()).unwrap();
    }
    return;
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct Rank<
    T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
> {
    rank: HashMap<T, usize>,
    size: usize,
}

impl<
        T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
    > Rank<T>
{
    fn new(size_in: usize) -> Rank<T> {
        let r = Rank {
            size: size_in,
            rank: HashMap::with_capacity(size_in),
        };
        return r;
    }

    fn remove_lowest(&mut self) -> usize {
        let mut mink = &T::default();
        let mut minv: usize = 0;
        let mut maxv: usize = 0;

        for (k, v) in self.rank.iter() {
            if minv == 0 || *v < minv {
                minv = *v;
                mink = k;
            }
            if *v > maxv {
                maxv = *v;
            }
        }
        if minv > 0 {
            //println!("Removinng {} {} {} ", mink, minv, maxv);
            let Some((_k, _v)) = self.rank.remove_entry(&mink.clone()) else {
                return 0;
            };
            //println!("Removed: {} {} ", k, v);
        }
        return (2 * minv + maxv) / 3;
    }

    fn add(&mut self, element: T) {
        if self.rank.contains_key(&element) {
            let _c = self.rank.entry(element).and_modify(|v| *v += 1);
        } else {
            let mut val = 1;
            if self.rank.len() >= self.size {
                val = min(self.remove_lowest(), 1);
            }
            self.rank.insert(element, val);
        }
    }
}

impl<
        T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
    > fmt::Display for Rank<T>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut l = Vec::new();
        for (k, v) in self.rank.iter() {
            l.push((k, v));
        }
        l.sort_by(|a, b| (b.1).partial_cmp(a.1).unwrap());
        for (k, v) in l.iter() {
            write!(f, "{}: {}\n", k, v).expect("Cannot write output format ");
        }
        return write!(f, "");
    }
}

impl<
        T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
    > Serialize for Rank<T>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut l = Vec::new();
        for (k, v) in self.rank.iter() {
            l.push((k, v));
        }
        l.sort_by(|a, b| (a.1).partial_cmp(b.1).unwrap());
        let mut seq = serializer.serialize_seq(Some(l.len()))?;
        for i in l {
            seq.serialize_element(&i)?;
        }
        return seq.end();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    rr_type: Vec<DNS_RR_type>,
    interface: String,
    filter: String,
    output: String,
    output_type: String,
    database: String,
    server: String,
    port: u16,
    daemon: bool,
    promisc: bool,
    config_file: String,
    dbhostname: String,
    dbusername: String,
    dbport: String,
    dbpassword: String,
    toplistsize: usize,
    skip_list_file: String,
    pid_file: String,
    uid: String,
    gid: String,
}

impl Config {
    fn new() -> Config {
        let mut c = Config {
            rr_type: Vec::<DNS_RR_type>::new(),
            interface: String::new(),
            filter: String::new(),
            output: String::new(),
            output_type: String::new(),
            database: String::new(),
            server: String::new(),
            port: 0,
            daemon: false,
            promisc: false,
            config_file: String::new(),
            dbhostname: String::new(),
            dbpassword: String::new(),
            dbport: String::new(),
            dbusername: String::new(),
            toplistsize: 20,
            skip_list_file: String::new(),
            pid_file: String::new(),
            gid: String::new(),
            uid: String::new(),
        };
        c.rr_type.extend(vec![
            DNS_RR_type::A,
            DNS_RR_type::AAAA,
            DNS_RR_type::NS,
            DNS_RR_type::PTR,
            DNS_RR_type::MX,
        ]);
        return c;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct statistics {
    errors: HashMap<String, u128>,
    qtypes: HashMap<String, u128>,
    atypes: HashMap<String, u128>,
    queries: u128,
    answers: u128,
    additional: u128,
    authority: u128,
    sources: Rank<String>,
    destinations: Rank<String>,
    udp: u128,
    tcp: u128,
    topdomain: Rank<String>,
    topnx: Rank<String>,
}

impl statistics {
    fn origin(toplistsize: usize) -> statistics {
        statistics {
            errors: HashMap::new(),
            qtypes: HashMap::new(),
            atypes: HashMap::new(),
            queries: 0,
            answers: 0,
            additional: 0,
            authority: 0,
            sources: Rank::new(toplistsize),
            destinations: Rank::new(toplistsize),
            udp: 0,
            tcp: 0,
            topdomain: Rank::new(toplistsize),
            topnx: Rank::new(toplistsize),
        }
    }

    fn to_str(&self) -> String {
        return format!(
            "Statistics:
        Query types: {:#?}
        Answer Types: {:#?}
        Errors: {:?}
        Sources: {:?}
        Destinations: {:?}
        Queries: {}
        Answers: {}
        Additional: {}
        Authority: {}
        UDP: {}
        TCP: {}",
            self.qtypes,
            self.atypes,
            self.errors,
            self.sources,
            self.destinations,
            self.queries,
            self.answers,
            self.additional,
            self.authority,
            self.udp,
            self.tcp
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DNS_Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
struct Packet_info {
    timestamp: DateTime<Utc>,
    sp: u16, // source port
    dp: u16, // destination port
    s_addr: IpAddr,
    d_addr: IpAddr,
    ip_len: u16,
    frame_len: u32,
    data_len: u32,
    protocol: DNS_Protocol,
    dns_records: Vec<DNS_record>,
}

impl Default for Packet_info {
    fn default() -> Self {
        Packet_info {
            timestamp: Utc::now(),
            sp: 0,
            dp: 0,
            s_addr: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            d_addr: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_len: 0,
            frame_len: 0,
            data_len: 0,
            protocol: DNS_Protocol::UDP,
            dns_records: Vec::new(),
        }
    }
}

impl Packet_info {
    fn set_source_port(&mut self, port: u16) {
        self.sp = port
    }
    fn set_protocol(&mut self, protocol: DNS_Protocol) {
        self.protocol = protocol
    }
    fn set_dest_port(&mut self, port: u16) {
        self.dp = port
    }
    fn set_source_ip(&mut self, s_ip: IpAddr) {
        self.s_addr = s_ip;
    }
    fn set_dest_ip(&mut self, d_ip: IpAddr) {
        self.d_addr = d_ip;
    }
    fn set_ip_len(&mut self, len: u16) {
        self.ip_len = len;
    }
    fn set_data_len(&mut self, len: u32) {
        self.data_len = len;
    }
    fn add_dns_record(&mut self, rec: DNS_record) {
        self.dns_records.push(rec);
    }

    fn to_str(&self) -> String {
        return format!(
            "{}:{} => {}:{}\n{:?}",
            self.s_addr, self.sp, self.d_addr, self.dp, self.dns_records
        );
    }
    fn to_csv(&self) -> String {
        let mut s = String::new();
        for i in &self.dns_records {
            s += &format!(
                "{},{},{},{},{},{},{},{},{}\n",
                self.s_addr,
                self.d_addr,
                self.timestamp,
                i.rr_type,
                i.class,
                i.ttl,
                i.name,
                i.rdata,
                1
            );
        }
        return s;
    }
    fn to_json(&self) -> String {
        let mut s = String::new();
        for i in &self.dns_records {
            s += &format!(
                "{{ 
                    \"source_ip\" : {},
                    \"destination_ip\" : {},
                   \"timestamp\": {},
                   \"rr_type\": {},
                   \"class\": {},
                   \"ttl\": {},
                   \"name\": {},
                   \"rdata\": {},
                   \"count\": {}
            }},",
                self.s_addr,
                self.d_addr,
                self.timestamp,
                i.rr_type,
                i.class,
                i.ttl,
                i.name,
                i.rdata,
                1
            );
        }
        return s;
    }
}

struct Mysql_connection {
    pool: Pool<MySql>,
}

impl Mysql_connection {
    async fn connect(host: &str, user: &str, pass: &str, port: &str) -> Mysql_connection {
        let database_url = format!("mysql://{}:{}@{}:{}/pdns", user, pass, host, port);
        match MySqlPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await
        {
            Ok(mysql_pool) => {
                // println!("Connection to the database is successful!");
                return Mysql_connection { pool: mysql_pool };
            }
            Err(err) => {
                eprintln!("Failed to connect to the database: {:?}", err);
                std::process::exit(1);
            }
        };
    }
    pub fn insert_or_update_record(&mut self, record: &DNS_record) {
        let i = record;
        let ts = i.timestamp.timestamp();
        let q_res = block_on(sqlx::query(r#"INSERT INTO pdns (QUERY,RR,MAPTYPE,ANSWER,TTL,COUNT,LAST_SEEN,FIRST_SEEN) VALUES (
                ?, ?, ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?)) ON DUPLICATE KEY UPDATE
                TTL = if (TTL < ?, ?, TTL), COUNT = COUNT + ?, LAST_SEEN = if (LAST_SEEN < FROM_UNIXTIME(?), FROM_UNIXTIME(?), LAST_SEEN),
                FIRST_SEEN = if (FIRST_SEEN > FROM_UNIXTIME(?), FROM_UNIXTIME(?), FIRST_SEEN)"#)
            .bind(&i.name)
            .bind(&i.class).bind(&i.rr_type)
            .bind(&i.rdata).bind(i.ttl).bind(i.count)
            .bind(ts).bind(ts)
            .bind(i.ttl).bind(i.ttl).bind(i.count)
            .bind(ts).bind(ts)
            .bind(ts).bind(ts)
            .execute(&self.pool));
        match q_res {
            Ok(_x) => {
                //println!("{:?}", x);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }
}

fn dns_read_u64(packet: &[u8], offset: usize) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 8) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u64(r);
    return Ok(val);
}
fn dns_read_u16(packet: &[u8], offset: usize) -> Result<u16, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 2) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u16(r);
    return Ok(val);
}

fn dns_read_u8(packet: &[u8], offset: usize) -> Result<u8, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset) else {
        return Err("Invalid index !".into());
    };
    return Ok(*r);
}
fn base32hex_encode(input: &[u8]) -> String {
    static BASE32HEX_NOPAD: data_encoding::Encoding = data_encoding::BASE32HEX_NOPAD;

    let mut output = String::new();
    let mut enc = BASE32HEX_NOPAD.new_encoder(&mut output);
    enc.append(input);
    enc.finalize();
    return output;
}
fn dns_read_u32(packet: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 4) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u32(r);
    return Ok(val);
}

fn timestame_to_str(timestamp: u32) -> Result<String, Box<dyn std::error::Error>> {
    let Some(naive_datetime) = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0) else {
        return Err("Cannot parse timestamp".into());
    };
    let datetime_again: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive_datetime, Utc);
    return Ok(datetime_again.to_string());
}

fn parse_dns_https(rdata: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let svc_prio = dns_read_u16(rdata, 0)?;
    let (target, mut offset) = dns_parse_name(rdata, 2)?;
    let mut res = String::new();
    res += &format!("{} {} ", svc_prio, target);
    while offset < rdata.len() {
        let svc_param_key = SVC_Param_Keys::find(dns_read_u16(rdata, offset)?)?;
        let svc_param_len = dns_read_u16(rdata, offset + 2)? as usize;
        match svc_param_key {
            SVC_Param_Keys::mandatory => {
                let mut pos: usize = 0;
                res += "mandatory=";
                while pos < svc_param_len {
                    let man_val = dns_read_u16(rdata, offset + pos + 4)?;
                    res += &format!("{},", SVC_Param_Keys::find(man_val)?.as_static());
                    pos += 2;
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::alpn => {
                let mut pos: usize = 0;
                res += "alpn=";
                while pos < svc_param_len {
                    let alpn_len = rdata[offset + pos + 4] as usize;
                    let alpn = String::from_utf8_lossy(
                        &rdata[offset + pos + 4 + 1..offset + pos + 4 + 1 + alpn_len],
                    );
                    pos += 1 + alpn_len;
                    res += &format!("{},", alpn);
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::ech => {
                res += "ech=";
                let data = general_purpose::STANDARD
                    .encode(&rdata[offset + 4..offset + 4 + svc_param_len]);
                res += &data;
                res += " ";
            }
            SVC_Param_Keys::ipv4hint => {
                res += "ipv4hint=";
                let mut pos: usize = 0;
                while pos + 4 <= svc_param_len {
                    let loc = offset + 4 + pos;
                    res += &format!(
                        "{}.{}.{}.{},",
                        rdata[loc],
                        rdata[loc + 1],
                        rdata[loc + 2],
                        rdata[loc + 3]
                    );
                    pos += 4;
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::ipv6hint => {
                res += "ipv6hint=";
                let mut pos: usize = 0;
                while pos + 16 <= svc_param_len {
                    let r: [u8; 16] = rdata[offset + 4 + pos..offset + 4 + pos + 16].try_into()?;
                    let addr = Ipv6Addr::from(r);
                    res += &format!("{},", addr);
                    pos += 16;
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::no_default_alpn => {
                res += "no-default-alpn";
            }
            SVC_Param_Keys::port => {
                let port = dns_read_u16(rdata, offset + 4)?;
                res += &format!("port={}", port);
            }
        }
        offset += 4 + svc_param_len as usize;
    }
    return Ok(res);
}

fn dns_parse_rdata(
    rdata: &[u8],
    rrtype: DNS_RR_type,
    packet: &[u8],
    offset_in: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut outdata = String::new();
    //println!("{}", rrtype);
    if rrtype == DNS_RR_type::A {
        if rdata.len() != 4 {
            return Err("Invalid record".into());
        }
        outdata.push_str(&format!(
            "{}.{}.{}.{}",
            rdata[0], rdata[1], rdata[2], rdata[3]
        ));
        return Ok(outdata);
    } else if rrtype == DNS_RR_type::AAAA {
        if rdata.len() != 16 {
            return Err("Invalid record".into());
        }
        let r: [u8; 16] = rdata.try_into()?;
        let addr = Ipv6Addr::from(r);
        return Ok(addr.to_string());
    } else if rrtype == DNS_RR_type::CNAME || rrtype == DNS_RR_type::DNAME {
        let (s, _offset) = dns_parse_name(packet, offset_in)?;
        return Ok(s);
    } else if rrtype == DNS_RR_type::CAA {
        let flag = rdata[0];
        let tag_len = rdata[1];
        let Some(r) = rdata.get(2..2 + tag_len as usize) else {
            return Err("Index error".into());
        };
        let tag = str::from_utf8(r)?;
        let Some(r) = rdata.get(2 + tag_len as usize..) else {
            return Err("Index error".into());
        };
        let value = str::from_utf8(r)?;
        return Ok(format!("{} {} ({})", tag, value, flag));
    } else if rrtype == DNS_RR_type::SOA {
        let mut offset: usize = offset_in;
        let ns: String;
        let mb: String;
        (ns, offset) = dns_parse_name(packet, offset)?;
        (mb, offset) = dns_parse_name(packet, offset)?;
        let sn = dns_read_u32(packet, offset)?;
        let refr = dns_read_u32(packet, offset + 4)?;
        let ret = dns_read_u32(packet, offset + 8)?;
        let exp = dns_read_u32(packet, offset + 16)?;
        let ttl = dns_read_u32(packet, offset + 16)?;
        return Ok(format!(
            "{} {} {} {} {} {} {}",
            ns, mb, sn, refr, ret, exp, ttl
        ));
    } else if rrtype == DNS_RR_type::NS {
        let (ns, _offset_out) = dns_parse_name(packet, offset_in)?;
        return Ok(ns);
    } else if rrtype == DNS_RR_type::TXT
        || rrtype == DNS_RR_type::NINF0
        || rrtype == DNS_RR_type::AVC
        || rrtype == DNS_RR_type::SPF
    {
        let mut pos = 0;
        let mut res = String::new();
        while pos < rdata.len() {
            let tlen: usize = rdata[pos].into();
            let Some(r) = rdata.get(1 + pos..pos + tlen + 1) else {
                return Err("Index error".into());
            };
            //            let s = std::str::from_utf8(r)?;
            res += &format!("{} ", std::str::from_utf8(r)?);
            pos += 1 + tlen;
        }
        return Ok(String::from(res));
    } else if rrtype == DNS_RR_type::PTR {
        let (ptr, _offset_out) = dns_parse_name(packet, offset_in)?;
        return Ok(ptr);
    } else if rrtype == DNS_RR_type::MX || rrtype == DNS_RR_type::RT {
        let _pref = BigEndian::read_u16(&rdata[0..2]);
        let (mx, _offset_out) = dns_parse_name(packet, offset_in + 2)?;
        return Ok(mx);
    } else if rrtype == DNS_RR_type::HINFO {
        let cpu_len1 = dns_read_u8(rdata, 0)?;
        let cpu_len: usize = cpu_len1 as usize;
        let mut offset: usize = 1;
        let Some(r) = rdata.get(offset..offset + cpu_len as usize) else {
            return Err("Index error".into());
        };
        let mut s = String::from(std::str::from_utf8(r)?);
        offset += cpu_len as usize;
        let os_len = rdata[offset] as usize;
        offset += 1;
        s.push(' ');
        let Some(r) = rdata.get(offset..offset + os_len) else {
            return Err("Index error".into());
        };
        s += &String::from(std::str::from_utf8(r)?);
        return Ok(s);
    } else if rrtype == DNS_RR_type::SRV {
        let prio = dns_read_u16(rdata, 0)?;
        let weight = dns_read_u16(rdata, 2)?;
        let port = dns_read_u16(rdata, 4)?;
        let (target, _offset_out) = dns_parse_name(rdata, 6)?;
        return Ok(format!("{} {} {} {}", prio, weight, port, target));
    } else if rrtype == DNS_RR_type::TLSA || rrtype == DNS_RR_type::SMIMEA {
        if rdata.len() < 4 {
            return Err("Rdata too small".into());
        }
        let cert_usage = tlsa_cert_usage(rdata[0])?;
        let selector = tlsa_selector(rdata[1])?;
        let alg_type = tlsa_algorithm(rdata[2])?;
        let cad = &rdata[3..];
        return Ok(format!(
            "{} {} {} {}",
            cert_usage,
            selector,
            alg_type,
            hex::encode(cad)
        ));
    } else if rrtype == DNS_RR_type::AFSDB {
        let subtype = dns_read_u16(rdata, 0)?;
        let (hostname, _offset_out) = dns_parse_name(rdata, 2)?;
        return Ok(format!("{} {}", subtype, hostname));
    } else if rrtype == DNS_RR_type::CDS || rrtype == DNS_RR_type::DS || rrtype == DNS_RR_type::TA {
        if rdata.len() < 5 {
            return Err("Index error".into());
        }
        let keyid = dns_read_u16(rdata, 0)?;
        let alg = dnssec_algorithm(rdata[2])?;
        let dig_t = dnssec_digest(rdata[3])?;
        let dig = &rdata[4..];
        return Ok(format!("{} {} {} {}", keyid, alg, dig_t, hex::encode(dig)));
    } else if rrtype == DNS_RR_type::DNSKEY || rrtype == DNS_RR_type::CDNSKEY {
        if rdata.len() < 5 {
            return Err("Index error".into());
        }
        let flag = dns_read_u16(rdata, 0)?;
        let protocol = dnssec_algorithm(rdata[2])?;
        let alg = dnssec_algorithm(rdata[3])?;
        let pubkey = &rdata[4..];
        return Ok(format!(
            "{} {} {} {}",
            flag,
            protocol,
            alg,
            hex::encode(pubkey)
        ));
    } else if rrtype == DNS_RR_type::LOC {
        let version = dns_read_u8(rdata, 0)?;
        let size = dns_read_u8(rdata, 1)?;
        let hor_prec = dns_read_u8(rdata, 2)?;
        let ver_prec = dns_read_u8(rdata, 3)?;

        // todo need to do coversion to degrees
        let lat = dns_read_u32(rdata, 4)?;
        let lon = dns_read_u32(rdata, 8)?;
        let alt = dns_read_u32(rdata, 10)?;
        return Ok(format!(
            "{} {} {} {} {} {} {}",
            version, size, hor_prec, ver_prec, lat, lon, alt
        ));
    } else if rrtype == DNS_RR_type::NAPTR {
        let order = dns_read_u16(rdata, 0)?;
        let pref = dns_read_u16(rdata, 2)?;
        let flag_len = dns_read_u8(rdata, 4)?;
        let mut offset: usize = 5;
        let flags = str::from_utf8(&rdata[offset..offset + flag_len as usize])?;
        offset += flag_len as usize;
        let srv_len = rdata[offset as usize];
        offset += 1;
        let srv = str::from_utf8(&rdata[offset..offset + srv_len as usize])?;
        offset += srv_len as usize;
        let re_len = dns_read_u8(rdata, offset)?;
        offset += 1;
        let mut re = "";
        if re_len > 0 {
            re = str::from_utf8(&rdata[offset..offset + re_len as usize])?;
        }
        offset += re_len as usize;
        let (repl, _) = dns_parse_name(rdata, offset)?;
        return Ok(format!(
            "{} {} {} {} {} {}",
            order, pref, flags, srv, re, repl
        ));
    } else if rrtype == DNS_RR_type::RRSIG {
        let sig_rrtype = parse_rrtype(dns_read_u16(rdata, 0)?)?;
        let sig_rrtype_str = sig_rrtype.to_str()?;
        let alg = dnssec_algorithm(dns_read_u8(rdata, 2)?)?;
        let labels = dns_read_u8(rdata, 3)?;
        let ttl = dns_read_u32(rdata, 4)?;
        let sig_exp = timestame_to_str(dns_read_u32(rdata, 8)?)?;
        let sig_inc = timestame_to_str(dns_read_u32(rdata, 12)?)?;
        let key_tag = dns_read_u16(rdata, 16)?;
        let (signer, offset_out) = dns_parse_name(rdata, 18)?;
        let signature = &rdata[offset_out..];
        return Ok(format!(
            "{} {} {} {} {} {} {} {} {}",
            sig_rrtype_str,
            alg,
            labels,
            ttl,
            sig_exp,
            sig_inc,
            key_tag,
            signer,
            hex::encode(&signature)
        ));
    } else if rrtype == DNS_RR_type::SSHFP {
        if rdata.len() < 3 {
            return Err("Invalid packet".into());
        }
        let alg = sshfp_algorithm(rdata[0])?;
        let fp_type = sshfp_fp_type(rdata[1])?;
        let fingerprint = &rdata[2..];
        return Ok(format!("{} {} {}", alg, fp_type, hex::encode(&fingerprint)));
    } else if rrtype == DNS_RR_type::OPENPGPKEY {
        let pubkey = general_purpose::STANDARD_NO_PAD.encode(&rdata);
        return Ok(pubkey);
    } else if rrtype == DNS_RR_type::RP {
        let (mailbox, offset) = dns_parse_name(rdata, 0)?;
        let (txt, _) = dns_parse_name(rdata, offset)?;
        return Ok(format!("{} {}", mailbox, txt));
    } else if rrtype == DNS_RR_type::MB {
        let (mb, _offset) = dns_parse_name(packet, offset_in)?;
        return Ok(mb);
    } else if rrtype == DNS_RR_type::A6 {
        let prefix_len = rdata[0];
        let len: usize = (128 - prefix_len as usize) / 8;
        let mut r: [u8; 16] = [0; 16];
        for i in 0..len {
            r[15 - i] = rdata[len - i]
        }
        let addr_suffix = Ipv6Addr::from(r);
        let mut prefix_name = String::new();
        if prefix_len != 0 {
            (prefix_name, _) = dns_parse_name(packet, offset_in + 1 + len)?;
        }
        return Ok(format!("{} {} {}", prefix_len, addr_suffix, prefix_name));
    } else if rrtype == DNS_RR_type::AMTRELAY {
        let precedence = rdata[0];
        let mut rtype = rdata[1];
        let dbit = rtype >> 7;
        rtype = rtype & 0x7f;
        let mut relay: String = String::new();
        if rtype == 3 {
            (relay, _) = dns_parse_name(packet, offset_in + 2)?;
        } else if rtype == 2 {
            let r: [u8; 16] = rdata[2..18].try_into()?;
            let addr = Ipv6Addr::from(r);
            relay = format!("{}", addr);
        } else if rtype == 1 {
            let r: [u8; 4] = rdata[2..6].try_into()?;
            let addr = Ipv4Addr::from(r);
            relay = format!("{}", addr);
        }
        return Ok(format!("{} {} {} {}", precedence, dbit, rtype, relay));
    } else if rrtype == DNS_RR_type::X25 {
        let len: usize = rdata[0] as usize;
        if len + 1 != rdata.len() {
            return Err("Ivalid X25 format".into());
        }
        let Some(addr) = rdata.get(1..1 + len) else {
            return Err("Parse Error".into());
        };
        let addr1 = str::from_utf8(addr)?;
        return Ok(String::from_str(addr1)?);
    } else if rrtype == DNS_RR_type::NSEC3PARAM {
        let hash = rdata[0];
        let flags = rdata[1];
        let iterations = dns_read_u16(rdata, 2)?;
        let salt_len = rdata[4] as usize;
        if salt_len + 5 > rdata.len() {
            return Err("Invalid NSEC3PARAM format".into());
        }
        let Some(salt) = rdata.get(5..5 + salt_len) else {
            return Err("Parse Error".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            hash,
            flags,
            iterations,
            hex::encode(salt)
        ));
    } else if rrtype == DNS_RR_type::GPOS {
        let mut idx = 0;
        let lon_len = rdata[idx] as usize;
        idx += 1;
        let Some(lon) = rdata.get(idx..idx + lon_len) else {
            return Err("Parse Error".into());
        };
        idx += lon_len;
        let lat_len = rdata[idx] as usize;
        idx += 1;
        let Some(lat) = rdata.get(idx..idx + lat_len) else {
            return Err("Parse Error".into());
        };
        idx += lat_len;
        let alt_len = rdata[idx] as usize;
        idx += 1;
        let Some(alt) = rdata.get(idx..idx + alt_len) else {
            return Err("Parse Error".into());
        };
        return Ok(format!(
            "{} {} {}",
            str::from_utf8(lon)?,
            str::from_utf8(lat)?,
            str::from_utf8(alt)?
        ));
    } else if rrtype == DNS_RR_type::EUI48 {
        if rdata.len() != 6 {
            return Err("Parse Error".into());
        }
        return Ok(format!(
            "{:x}-{:x}-{:x}-{:x}-{:x}-{:x}",
            rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5]
        ));
    } else if rrtype == DNS_RR_type::EUI64 {
        if rdata.len() != 8 {
            return Err("Parse Error".into());
        }
        return Ok(format!(
            "{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}",
            rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5], rdata[6], rdata[7]
        ));
    } else if rrtype == DNS_RR_type::CERT {
        let cert_type = dns_read_u16(rdata, 0)?;
        let key_tag = dns_read_u16(rdata, 2)?;
        let alg = dns_read_u8(rdata, 4)?;
        let Some(cert) = rdata.get(5..) else {
            return Err("Packet too small".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            cert_type_str(cert_type)?,
            (key_tag),
            dnssec_algorithm(alg)?,
            hex::encode(cert)
        ));
    } else if rrtype == DNS_RR_type::HTTPS || rrtype == DNS_RR_type::SVCB {
        return parse_dns_https(rdata);
    } else if rrtype == DNS_RR_type::WKS {
        let protocol = dns_read_u8(rdata, 4)?;
        let Some(bitmap) = rdata.get(5..) else {
            return Err("Parse error".into());
        };

        return Ok(format!(
            "{}.{}.{}.{} {} {}",
            rdata[0],
            rdata[1],
            rdata[2],
            rdata[3],
            parse_protocol(protocol)?,
            parse_bitmap_str(bitmap)?
        ));
    } else if rrtype == DNS_RR_type::TSIG {
        // todo
    } else if rrtype == DNS_RR_type::APL {
        let mut pos = 0;
        let mut res = String::new();
        while pos < rdata.len() {
            let af = dns_read_u16(rdata, pos)?;
            let pref_len = dns_read_u8(rdata, pos + 2)?;
            let addr_len_ = dns_read_u8(rdata, pos + 3)?;
            let flags = addr_len_ >> 7;
            let mut neg_str = "";
            if flags > 0 {
                neg_str = "!";
            }
            let addr_len = (addr_len_ & 0x7f) as usize;
            let Some(addr) = rdata.get(pos + 4..pos + 4 + addr_len) else {
                return Err("Parse error".into());
            };
            //println!("{:?} {}", addr, addr_len);
            let mut ip_addr = std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            if af == 1 {
                // ipv4
                let mut ip: [u8; 4] = [0; 4];
                for i in 0..addr_len {
                    ip[i] = addr[i];
                }
                ip_addr = std::net::IpAddr::V4(Ipv4Addr::from(ip));
            }
            if af == 2 {
                // Ipv6
                let mut ip: [u8; 16] = [0; 16];
                for i in 0..addr_len {
                    ip[i] = addr[i];
                }
                ip_addr = std::net::IpAddr::V6(Ipv6Addr::from(ip));
            }
            res += &format!("{}{}/{} ", neg_str, ip_addr, pref_len);
            pos += 4 + addr_len;
        }
        return Ok(res);
    } else if rrtype == DNS_RR_type::ATMA {
        let format = rdata[0];
        let address = &rdata[1..];
        return Ok(format!("{} {}", format, hex::encode(address)));
    } else if rrtype == DNS_RR_type::DLV {
        let Some(key_id) = rdata.get(0..2) else {
            return Err("Packet too small".into());
        };

        let alg = dns_read_u8(rdata, 2)?;
        let digest_type = dns_read_u8(rdata, 3)?;
        let Some(digest) = rdata.get(4..) else {
            return Err("Packet too small".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            hex::encode(key_id),
            dnssec_algorithm(alg)?,
            dnssec_digest(digest_type)?,
            hex::encode(digest)
        ));
    } else if rrtype == DNS_RR_type::TALINK {
        let (name1, offset_out) = dns_parse_name(packet, offset_in)?;
        let (name2, _) = dns_parse_name(packet, offset_out)?;
        return Ok(format!("{} {}", name1, name2));
    } else if rrtype == DNS_RR_type::DHCID {
        return Ok(format!("{}", hex::encode(rdata)));
    } else if rrtype == DNS_RR_type::ZONEMD {
        let serial = dns_read_u32(rdata, 0)?;
        let scheme = dns_read_u8(rdata, 4)?;
        let alg = dns_read_u8(rdata, 5)?;
        let Some(digest) = rdata.get(6..) else {
            return Err("Packet too small".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            serial,
            scheme,
            zonemd_digest(alg)?,
            hex::encode(digest)
        ));
    } else if rrtype == DNS_RR_type::URI {
        let prio = dns_read_u16(rdata, 0)?;
        let weight = dns_read_u16(rdata, 2)?;
        let Some(target_data) = rdata.get(4..) else {
            return Err("Packet too small".into());
        };
        let target = str::from_utf8(target_data)?;
        return Ok(format!("{} {} {}", prio, weight, target));
    } else if rrtype == DNS_RR_type::CSYNC {
        let soa = dns_read_u32(rdata, 0)?;
        let flags = dns_read_u16(rdata, 4)?;
        let bitmap = parse_nsec_bitmap_vec(&rdata[6..])?;
        let mut bitmap_str = String::new();
        for i in bitmap {
            bitmap_str += &format!("{} ", DNS_RR_type::find(i)?);
        }
        return Ok(format!("{} {} {}", soa, flags, bitmap_str));
    } else if rrtype == DNS_RR_type::DOA {
        let doa_ent = dns_read_u32(rdata, 0)?;
        let doa_type = dns_read_u32(rdata, 4)?;
        let doa_loc = dns_read_u8(rdata, 8)?;
        let doa_media_type_len = dns_read_u8(rdata, 9)? as usize;
        let Some(doa_media_type) = rdata.get(10..10 + doa_media_type_len) else {
            return Err("parse error".into());
        };
        let Some(doa_data) = rdata.get(10 + doa_media_type_len..) else {
            return Err("parse error".into());
        };

        let doa_data_str = general_purpose::STANDARD.encode(doa_data);
        return Ok(format!(
            "{} {} {} {:?} {} ",
            doa_ent,
            doa_type,
            doa_loc,
            String::from_utf8_lossy(doa_media_type),
            doa_data_str
        ));
    } else if rrtype == DNS_RR_type::HIP {
        let hit_len = dns_read_u8(rdata, 0)? as usize;
        let hit_alg = dns_read_u8(rdata, 1)?;
        let pk_len = dns_read_u16(rdata, 2)? as usize;
        let Some(hit) = rdata.get(4..4 + hit_len as usize) else {
            return Err("parse error".into());
        };
        let Some(hip_pk) = rdata.get(4 + hit_len..4 + hit_len + pk_len) else {
            return Err("parse error".into());
        };
        let (rendezvous, _) = dns_parse_name(rdata, 4 + hit_len + pk_len)?;
        return Ok(format!(
            "{} {:x?} {:x?} {}",
            hit_alg,
            hex::encode(hit),
            general_purpose::STANDARD_NO_PAD.encode(hip_pk),
            rendezvous
        ));
    } else if rrtype == DNS_RR_type::MD {
        let (res_md, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_md));
    } else if rrtype == DNS_RR_type::MF {
        let (res_mf, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_mf));
    } else if rrtype == DNS_RR_type::MG {
        let (res_mg, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_mg));
    } else if rrtype == DNS_RR_type::MR {
        let (res_mr, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_mr));
    } else if rrtype == DNS_RR_type::NXT {
        let (next, _) = dns_parse_name(packet, offset_in)?;
        let bm = parse_bitmap_vec(&rdata[next.len() + 1..])?;
        return Ok(format!("{} {}", next, map_bitmap_to_rr(&bm)?));
    } else if rrtype == DNS_RR_type::NSAP {
        return Ok(format!("0x{}", hex::encode(rdata)));
    } else if rrtype == DNS_RR_type::NSAP_PTR {
        let (nsap_ptr, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", nsap_ptr));
    } else if rrtype == DNS_RR_type::MINFO {
        let (res_mb, offset) = dns_parse_name(packet, offset_in)?;
        let (err_mb, _) = dns_parse_name(packet, offset)?;
        return Ok(format!("{} {}", res_mb, err_mb));
    //} else if rrtype == DNS_RR_type::MAILA { // not an rr _type
    // todo
    //} else if rrtype == DNS_RR_type::MAILB {
    // todo
    } else if rrtype == DNS_RR_type::IPSECKEY {
        let precedence = dns_read_u8(rdata, 0)?;
        let gw_type = dns_read_u8(rdata, 1)?;
        let alg = dns_read_u8(rdata, 2)?;
        let mut pk_offset = 3;
        let mut name = String::new();
        match gw_type {
            0 => {
                name.push('.');
            } // No Gateway
            1 => {
                pk_offset += 4;
                let r: [u8; 4] = rdata[3..8].try_into()?;
                let addr = IpAddr::V4(Ipv4Addr::from(r));
                name = addr.to_string();
            } // IPv4 address
            2 => {
                pk_offset += 16;
                let r: [u8; 16] = rdata[3..20].try_into()?;
                let addr = IpAddr::V6(Ipv6Addr::from(r));
                name = addr.to_string();
            } // IPv6 Address
            3 => {
                (name, pk_offset) = dns_parse_name(rdata, 3)?;
            } // a FQDN
            _ => {
                return Err("Parse Error".into());
            }
        }
        let alg_name;
        if alg == 1 {
            alg_name = "DSA"
        } else if alg == 2 {
            alg_name = "RSA"
        } else {
            return Err("Unknown algorithm".into());
        }
        let Some(pk) = rdata.get(pk_offset..) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {} {} {} {}",
            precedence,
            gw_type,
            alg_name,
            name,
            hex::encode(pk)
        ));
    } else if rrtype == DNS_RR_type::ISDN {
        let addr_len = dns_read_u8(rdata, 0)?;
        let Some(addr) = rdata.get(1..1 + addr_len as usize) else {
            return Err("Parse error".into());
        };
        let subaddr_len = dns_read_u8(rdata, 1 + addr_len as usize)?;
        let Some(sub_addr) = rdata.get(1..1 + addr_len as usize + 1 + subaddr_len as usize) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {}",
            String::from_utf8_lossy(&addr),
            String::from_utf8_lossy(&sub_addr)
        ));
    } else if rrtype == DNS_RR_type::NID {
        let prio = dns_read_u16(rdata, 0)?;
        let node_id1 = dns_read_u16(rdata, 2)?;
        let node_id2 = dns_read_u16(rdata, 4)?;
        let node_id3 = dns_read_u16(rdata, 6)?;
        let node_id4 = dns_read_u16(rdata, 7)?;
        return Ok(format!(
            "{} {:x}:{:x}:{:x}:{:x}",
            prio, node_id1, node_id2, node_id3, node_id4
        ));
    } else if rrtype == DNS_RR_type::L32 {
        let prio = dns_read_u16(rdata, 0)?;
        let r: [u8; 4] = rdata[2..].try_into()?;
        let addr = Ipv4Addr::from(r);
        return Ok(format!("{} {}", prio, addr));
    } else if rrtype == DNS_RR_type::L64 {
        let prio = dns_read_u16(rdata, 0)?;
        let mut r: [u8; 16] = [0; 16];
        for i in 0..rdata[2..].len() {
            r[i] = rdata[2 + i];
        }
        let addr = Ipv6Addr::from(r).to_string();
        return Ok(format!("{} {}", prio, addr.trim_end_matches(':')));
    } else if rrtype == DNS_RR_type::LP {
        let prio = dns_read_u16(rdata, 0)?;
        let (fqdn, _) = dns_parse_name(rdata, 2)?;
        return Ok(format!("{} {}", prio, fqdn));
    } else if rrtype == DNS_RR_type::KX {
        let pref = dns_read_u16(rdata, 0)?;
        let (kx, _) = dns_parse_name(packet, offset_in + 2)?;
        return Ok(format!("{} {}", pref, kx));
    } else if rrtype == DNS_RR_type::TKEY { // meta RR?
         // todo /
    } else if rrtype == DNS_RR_type::KEY {
        let flags = dns_read_u16(rdata, 0)?;
        let protocol = dns_read_u8(rdata, 2)?;
        let alg = dns_read_u8(rdata, 3)?;
        let Some(key) = rdata.get(4..) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            flags,
            key_protocol(protocol)?,
            key_algorithm(alg)?,
            general_purpose::STANDARD.encode(key)
        ));
    } else if rrtype == DNS_RR_type::PX {
        let pref = dns_read_u16(rdata, 0)?;
        let (map822, offset) = dns_parse_name(rdata, 2)?;
        let (mapx400, _) = dns_parse_name(rdata, offset)?;
        return Ok(format!("{} {} {}", pref, map822, mapx400));
    } else if rrtype == DNS_RR_type::SIG {
        // todo
    } else if rrtype == DNS_RR_type::SINK {
        let mut coding = dns_read_u8(rdata, 0)?;
        let mut offset = 1;
        if coding == 0 {
            // weird bind thing
            coding = dns_read_u8(rdata, 1)?;
            offset = 2;
        }
        let subcoding = dns_read_u8(rdata, offset)?;
        let Some(data) = rdata.get(offset + 1..) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {} {}",
            coding,
            subcoding,
            general_purpose::STANDARD.encode(data)
        ));
    } else if rrtype == DNS_RR_type::EID || rrtype == DNS_RR_type::NIMLOC {
        return Ok(hex::encode(rdata));
    } else if rrtype == DNS_RR_type::NSEC {
        let (next_dom, offset) = dns_parse_name(rdata, 0)?;
        let mut bitmap_str = String::new();
        let bitmap = parse_nsec_bitmap_vec(&rdata[offset..])?;
        for i in bitmap {
            bitmap_str += &format!("{} ", DNS_RR_type::find(i)?);
        }
        return Ok(format!("{} {}", next_dom, bitmap_str));
    } else if rrtype == DNS_RR_type::NSEC3 {
        let hash_alg = dns_read_u8(rdata, 0)?;
        let flags = dns_read_u8(rdata, 1)?;
        let iterations = dns_read_u16(rdata, 2)?;
        let salt_len = dns_read_u8(rdata, 4)? as usize;
        let Some(salt) = rdata.get(5..5 + salt_len) else {
            return Err("parse error".into());
        };
        let hash_len = dns_read_u8(rdata, 5 + salt_len)? as usize;
        let Some(next_owner) = rdata.get(6 + salt_len..6 + salt_len + hash_len) else {
            return Err("parse error".into());
        };
        let bitmap = parse_nsec_bitmap_vec(&rdata[6 + salt_len + hash_len..])?;
        let mut bitmap_str = String::new();
        for i in bitmap {
            bitmap_str += &format!("{} ", DNS_RR_type::find(i)?);
        }
        return Ok(format!(
            "{} {} {} {} {} {}",
            dnssec_digest(hash_alg)?,
            flags,
            iterations,
            hex::encode(salt),
            base32hex_encode(next_owner),
            bitmap_str
        ));
    } else {
        return Err(format!("RR type not supported {:?}", rrtype).into());
    }
    return Ok("".to_string());
}

fn parse_nsec_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let len = bitmap.len();
    let mut res: Vec<u16> = Vec::new();
    let mut offset = 0;
    while offset < len {
        let high_byte = (bitmap[offset] as u16) << 8;
        let size = bitmap[offset + 1] as usize;
        for i in 0..size {
            let mut pos: u8 = 0x80;
            for j in 0..8 {
                if bitmap[offset + 2 + i] & pos != 0 {
                    res.push((high_byte as usize | ((8 * i) + j)).try_into()?);
                }
                pos >>= 1;
            }
        }
        //        println!("iDDD {} {} {:x?} {:?}", offset, len, &bitmap[offset..], res);
        offset += size + 2;
    }
    return Ok(res);
}
fn parse_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let len = bitmap.len();
    let mut res: Vec<u16> = Vec::new();
    for i in 0..len {
        let mut pos: u8 = 0x80;
        for j in 0..8 {
            if bitmap[i] & pos != 0 {
                res.push(((8 * i) + j).try_into()?);
            }
            pos >>= 1;
        }
    }
    return Ok(res);
}

fn map_bitmap_to_rr(bitmap: &Vec<u16>) -> Result<String, Box<dyn std::error::Error>> {
    let mut res = String::new();
    for i in bitmap {
        res += &format!("{} ", DNS_RR_type::find(*i)?);
    }
    return Ok(res);
}

fn parse_bitmap_str(bitmap: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let bitmap = parse_bitmap_vec(bitmap)?;
    return map_bitmap_to_rr(&bitmap);
}

fn parse_protocol(proto: u8) -> Result<String, Box<dyn std::error::Error>> {
    match proto {
        17 => {
            return Ok("UDP".into());
        }
        6 => {
            return Ok("TCP".into());
        }
        _ => {
            return Err("Unknown protocol".into());
        }
    }
}

fn dns_parse_name(
    packet: &[u8],
    offset: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let (mut name, offset_out) = dns_parse_name_internal(packet, offset)?;
    if name.len() == 0 {
        name = String::from(".");
    }
    return Ok((name, offset_out));
}

fn dns_parse_name_internal(
    packet: &[u8],
    offset_in: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let mut idx = offset_in;
    let mut name = String::new();
    //    println!("{} {:x?}", offset_in, &packet[offset_in.. offset_in+20]);
    while packet[idx] != 0 {
        let Some(val) = packet.get(idx) else {
            return Err("Invalid index".into());
        };
        if *val > 63 {
            let pos = (dns_read_u16(packet, idx)? & 0x3fff) as usize;
            let (name1, _len) = dns_parse_name(&packet, pos)?;
            return Ok((name + &name1, idx + 2));
        } else {
            let label_len: usize = *packet.get(idx).unwrap() as usize;
            idx += 1;
            let Some(label) = packet.get(idx..(idx + (label_len))) else {
                return Err("Invalid index !!".into());
            };
            name.push_str(std::str::from_utf8(&label)?);
            name.push('.');
            idx += label_len;
        }
    }
    return Ok((name, idx + 1));
}

fn parse_rrtype(rrtype: u16) -> Result<DNS_RR_type, Box<dyn std::error::Error>> {
    return DNS_RR_type::find(rrtype);
}

fn parse_class(class: u16) -> Result<DNS_Class, Box<dyn std::error::Error>> {
    return DNS_Class::find(class);
}

fn match_skip_list(name: &String, skip_list: &Vec<Regex>) -> bool {
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
    stats: &mut statistics,
    _config: &Config,
    rcode: u16,
    skip_list: &Vec<Regex>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, offset) = dns_parse_name(packet, offset_in)?;
    if match_skip_list(&name, skip_list) {
        return Err("skipped".into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let rrtype = parse_rrtype(rrtype_val)?;
    let class_val = dns_read_u16(packet, offset + 2)?;
    let _rrtype = parse_rrtype(rrtype_val).unwrap();
    let _class = parse_class(class_val).unwrap();
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
    stats: &mut statistics,
    config: &Config,
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
    /*println!(
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
    let rec: DNS_record = DNS_record {
        rr_type: rrtype.to_str()?,
        ttl: ttl,
        class: class.to_str()?,
        name: name.trim_end_matches('.').to_string(),
        rdata: rdata.trim_end_matches('.').to_string(),
        count: 1,
        timestamp: packet_info.timestamp,
    };
    packet_info.add_dns_record(rec);
    offset += datalen as usize - 1;
    let len = offset - offset_in;
    return Ok(len);
}

fn parse_dns(
    packet_in: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    config: &Config,
    skip_list: &Vec<Regex>,
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
        offset += parse_answer(packet_info, packet, offset, stats, config)?;
    }
    //println!("Authority {} {}", authority, offset);
    for _i in 0..authority {
        offset += parse_answer(packet_info, packet, offset, stats, config)?;
    }
    //println!("Additional {} {}", additional, offset);
    for _i in 0..additional {
        offset += parse_answer(packet_info, packet, offset, stats, config)?;
    }
    return Ok(());
}

#[derive(Debug, Clone)]
struct tcp_data {
    sp: u16,
    dp: u16,
    src: IpAddr,
    dst: IpAddr,
    data: Vec<u8>,
    init_seqnr: u32,
}

impl tcp_data {
    fn add_data(&mut self, seqnr: u32, data: &[u8]) {
        let pos = (seqnr - self.init_seqnr) as usize;
        let datasize = pos + data.len();
        self.data.resize(datasize, 0);
        for i in 0..data.len() {
            self.data[pos + i] = data[i];
        }
    }
    const MAX_TCP_LEN: usize = 1024 * 65; //LEN in the packet is 16 bts, so max 64KiB
    fn check_data_size(&self) -> bool {
        return self.data.len() > tcp_data::MAX_TCP_LEN;
    }

    fn init(sp: u16, dp: u16, src: IpAddr, dst: IpAddr, seqnr: u32) -> tcp_data {
        let t = tcp_data {
            sp: sp,
            dp: dp,
            src: src,
            dst: dst,
            init_seqnr: seqnr,
            data: Vec::new(),
        };
        return t;
    }
}

#[derive(Debug, Clone)]
struct tcp_connection {
    in_data: tcp_data,
    ts: DateTime<Utc>,
}

impl tcp_connection {
    fn new(
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
        seqnr: u32,
        timestamp: DateTime<Utc>,
    ) -> tcp_connection {
        let t = tcp_connection {
            in_data: tcp_data::init(sp, dp, src, dst, seqnr),
            ts: timestamp,
        };
        return t;
    }
    fn get_data(self) -> tcp_data {
        return self.in_data;
    }
}

#[derive(Debug, Clone)]
struct TCP_Connections {
    connections: HashMap<(IpAddr, IpAddr, u16, u16), tcp_connection>,
    timelimit: i64,
}

impl TCP_Connections {
    fn new() -> TCP_Connections {
        let t = TCP_Connections {
            connections: HashMap::new(),
            timelimit: 20,
        };
        return t;
    }

    fn len(&self) -> usize {
        //println!("{}", self.connections.len());
        return self.connections.len();
    }

    fn add_data(&mut self, sp: u16, dp: u16, src: IpAddr, dst: IpAddr, seqnr: u32, data: &[u8]) {
        let timestamp = Utc::now();
        let c = self
            .connections
            .entry((src, dst, sp, dp))
            .or_insert(tcp_connection::new(sp, dp, src, dst, seqnr, timestamp));
        c.in_data.add_data(seqnr, data);
        if c.in_data.check_data_size() {
            // if it is too big we just throw it away
            self.remove(sp, dp, src, dst);
        }
    }

    fn get_data(
        self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<tcp_data, Box<dyn std::error::Error>> {
        let Some(c) = self.connections.get(&(src, dst, sp, dp)) else {
            return Err("connection not found".into());
        };
        let p: tcp_data = c.clone().get_data();
        return Ok(p);
    }

    fn remove(&mut self, sp: u16, dp: u16, src: IpAddr, dst: IpAddr) {
        //  println!("Removing key {} {} {} {} ", src, dst, sp, dp);
        self.connections.remove(&(src, dst, sp, dp));
    }

    fn check_timeout(&mut self) -> u64 {
        let now = Utc::now().timestamp();
        let mut m_ts = 1;
        let mut keys: Vec<(IpAddr, IpAddr, u16, u16)> = Vec::new();
        for (k, v) in &self.connections {
            if v.ts.timestamp() + self.timelimit < now {
                keys.push(*k);
            }
            if now - v.ts.timestamp() > m_ts {
                m_ts = self.timelimit + v.ts.timestamp() - now;
            }
        }
        for k in keys {
            self.connections.remove(&k);
        }
        if m_ts > 0 {
            return (m_ts) as u64;
        } else {
            return self.timelimit as u64;
        }
    }

    fn process_data(
        &mut self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
        seqnr: u32,
        data: &[u8],
        _timestamp: DateTime<Utc>,
        flags: u8,
    ) -> Option<tcp_data> {
        if (flags & 1 != 0) || (flags & 4 != 0) {
            // FIN flag or reset
            self.add_data(sp, dp, src, dst, seqnr, data);
            match self.clone().get_data(sp, dp, src, dst) {
                Ok(x) => {
                    self.remove(sp, dp, src, dst);
                    return Some(x);
                }
                Err(_e) => {
                    self.remove(sp, dp, src, dst);
                    return None;
                }
            }
        } else if (flags & 2 != 0) || (flags & 7 == 0) {
            // SYN flag or no flag
            let mut sn = seqnr;
            if flags & 2 == 2 {
                sn += 1;
            }
            self.add_data(sp, dp, src, dst, sn, data);
            return None;
        }
        return None;
    }
}

fn clean_tcp_list(tcp_list: &Arc<Mutex<TCP_Connections>>, rx: mpsc::Receiver<String>) {
    let timeout = time::Duration::from_secs(1);

    loop {
        //    println!("{}", "Looping.... ".green());
        //   println!("{}", "Locking.... ".blue());
        let dur = tcp_list.lock().unwrap().check_timeout();
        //  println!("{}", "UnLocking.... ".red());
        match rx.try_recv() {
            Ok(_e) => {
                //println!("{} {:?}", "Disconnect".yellow(), _e);
                return;
            }
            Err(TryRecvError::Disconnected) => {
                //println!("{}", "Lost connection".yellow());
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
        //        println!("{} {:?}", "sleeping".cyan(), dur);
        sleep(std::cmp::max(timeout, time::Duration::from_secs(dur)));
    }
}

fn parse_tcp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Vec<Regex>,
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
            return parse_dns(&d.data, packet_info, stats, config, skip_list);
        }
        None => {}
    };

    return Ok(());
}

fn parse_udp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    config: &Config,
    skip_list: &Vec<Regex>,
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
        return parse_dns(&packet[8..], packet_info, stats, config, skip_list);
    } else {
        return Err(format!("Not a dns packet {} {}", dp, sp).into());
    }
}

fn parse_ip_data(
    packet: &[u8],
    protocol: u8,
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Vec<Regex>,
) -> Result<(), Box<dyn std::error::Error>> {
    if protocol == 6 {
        packet_info.set_protocol(DNS_Protocol::TCP);
        // TCP
        return parse_tcp(&packet, packet_info, stats, tcp_list, config, skip_list);
    } else if protocol == 17 {
        packet_info.set_protocol(DNS_Protocol::UDP);
        //  UDP
        return parse_udp(&packet, packet_info, stats, config, skip_list);
    }
    return Ok(());
}

fn parse_ipv4(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Vec<Regex>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    parse_ip_data(
        &packet[ihl as usize..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
    )?;
    return Ok(());
}

fn parse_ipv6(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Vec<Regex>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    parse_ip_data(
        &packet[40..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
    )?;
    return Ok(());
}

fn parse_eth(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Vec<Regex>,
) -> Result<(), Box<dyn std::error::Error>> {
    packet_info.frame_len = packet.len() as _;
    if packet[12..14] == [8, 0] {
        return parse_ipv4(
            &packet[14..],
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
        );
    } else if packet[12..14] == [0x86, 0xdd] {
        return parse_ipv6(
            &packet[14..],
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
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
    stats: &Arc<Mutex<statistics>>,
    config: &Config,
    skip_list: &Vec<Regex>,
) where
    T: pcap::Activated,
{
    //println!("Starting loop");
    while let Ok(packet) = cap.next_packet() {
        //println!("Packet");
        //        println!("{:?}", cap.stats().unwrap());
        let mut packet_info: Packet_info = Default::default();
        packet_info.timestamp = DateTime::<Utc>::from_timestamp(
            packet.header.ts.tv_sec,
            packet.header.ts.tv_usec as u32 * 1000,
        )
        .unwrap();
        let result = parse_eth(
            &packet.data,
            &mut packet_info,
            &mut stats.lock().unwrap(),
            tcp_list,
            config,
            skip_list,
        );
        match result {
            Ok(_c) => {
                packet_queue.lock().unwrap().push_back(Some(packet_info));
            }
            Err(error) => {
                eprintln!("{}", format!("{:?}", error));
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
    if config.output != "" {
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
        ));
        database_conn = Some(x);
    }

    loop {
        let packet_info = packet_queue.lock().unwrap().pop_front();
        match packet_info {
            Some(p) => match p {
                Some(p1) => {
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
        if ct > (last_push as u64) + dns_cache.timeout {
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

fn parse_rrtypes(config_str: &str) -> Vec<DNS_RR_type> {
    let mut rrtypes: Vec<DNS_RR_type> = Vec::new();
    if config_str == "" {
        rrtypes.push(DNS_RR_type::A);
        rrtypes.push(DNS_RR_type::AAAA);
        rrtypes.push(DNS_RR_type::NS);
        rrtypes.push(DNS_RR_type::MX);
        return rrtypes;
    } else if config_str == "*" {
        rrtypes = DNS_RR_type::iter().collect::<Vec<_>>();
        return rrtypes;
    }

    let elems = config_str.split(',');
    for i in elems {
        let a = DNS_RR_type::from_str(i);
        match a {
            Ok(p) => {
                rrtypes.push(p);
            }
            Err(_e) => {
                eprintln!("Invalid RR type: {}", i);
            }
        }
    }
    return rrtypes;
}

fn listen(address: String, port: u16) -> Option<TcpListener> {
    if address == "" {
        return None;
    }
    let addr = format!("{}:{}", address, port);
    //println!("{}", addr);
    let x = TcpListener::bind(addr);
    match x {
        Ok(conn) => {
            //println!("{:?}", conn);
            return Some(conn);
        }
        Err(_e) => {
            panic!("Cannot listen on {}:{}", address, port);
        }
    }
}

fn read_skip_list(filename: &String) -> Vec<Regex> {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(_) => {
            eprintln!("no such file");
            return Vec::new();
        }
    };
    let mut file_contents = String::new();
    match file.read_to_string(&mut file_contents) {
        //   .ok() {
        Ok(_) => {
            let lines: Vec<Regex> = file_contents
                .split("\n")
                .map(|s: &str| s.trim().to_string())
                .filter(|s| s != "")
                .map(|s| Regex::new(s.as_str()).unwrap())
                .collect();
            return lines;
        }
        Err(_) => {
            eprintln!("File could not be read");
            return Vec::new();
        }
    };
}

fn run(config: &Config, capin: Option<Capture<Active>>, pcap_path: &String) {
    // println!("{:?}", config);
    let packet_queue = Arc::new(Mutex::new(VecDeque::new()));
    let tcp_list = Arc::new(Mutex::new(TCP_Connections::new()));
    let stats = Arc::new(Mutex::new(statistics::origin(config.toplistsize)));
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
                    c.filter(config.filter.as_str().as_ref(), false).unwrap();
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
            let listener = listen(config.server.clone(), config.port.clone());
            let handle4 = s.spawn(|| match listener {
                Some(l) => server(l, &stats.clone(), &tcp_list.clone()),
                None => {}
            });
            let Some(mut cap) = capin else {
                panic!("Something wrong with the capture");
            };
            //            println!("Filter: {}", config.filter);
            cap.filter(config.filter.as_str(), false).unwrap();
            let link_type = cap.get_datalink();

            if link_type != Linktype::ETHERNET {
                panic!("Not ethernet");
            }
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
    let matches = Command::new("pdns")
        .version("1.0")
        .author("Gavin Spearhead")
        .about("PassiveDNS")
        .arg(arg!(-c --config <VALUE>).required(false))
        .arg(arg!(-H --dbhostname <VALUE>).required(false))
        .arg(arg!(-T --dbport <VALUE>).required(false))
        .arg(arg!(-u --dbusername <VALUE>).required(false))
        .arg(arg!(-w --dbpassword <VALUE>).required(false))
        .arg(arg!(-p --path <VALUE>).required(false))
        .arg(arg!(-S --skip_list_file <VALUE>).required(false))
        .arg(arg!(-l --listen <VALUE>).required(false))
        .arg(arg!(-P --port <VALUE>).required(false))
        .arg(arg!(-r --rrtypes <VALUE>).required(false))
        .arg(arg!(-i --interface <VALUE>).required(false))
        .arg(arg!(-f --filter <VALUE>).required(false))
        .arg(arg!(-o --output <VALUE>).required(false))
        .arg(arg!(-d --database <VALUE>).required(false))
        .arg(arg!(-L --toplistsize <VALUE>).required(false))
        .arg(arg!(-U --uid <VALUE>).required(false))
        .arg(arg!(-g --gid <VALUE>).required(false))
        .arg(
            arg!(-C --promisc <VALUE>)
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-D - -daemon)
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-I --pid_file <VALUE>)
                .required(false)
                .default_missing_value("/var/run/pdns.pid"),
        )
        .arg(
            arg!(-t --output_type <VALUE>)
                .required(false)
                .default_missing_value("csv"),
        )
        .get_matches();
    let empty_str = String::new();
    let mut config = Config::new();
    //const DEFAULT_CONFIG_FILE: &str = "pdns.cfg";
    config.config_file = matches
        .get_one::<String>("config")
        .unwrap_or(&String::from_str(&empty_str).unwrap())
        .clone();

    if config.config_file != "" {
        let config_str = std::fs::read_to_string(&config.config_file).unwrap_or(String::new());
        if !config_str.is_empty() {
            match serde_json::from_str(&config_str) {
                Ok(x) => {
                    //                    println!("{:#?}", x);
                    config = x;
                }
                Err(_e) => {
                    let err_msg = format!("Failed to parse config file: {}", (config.config_file));
                    panic!("{}", err_msg);
                }
            }
        }
    }
    //  println!("config: {:#?}", config);
    config.server = matches
        .get_one::<String>("listen")
        .unwrap_or(&config.server)
        .clone();
    config.port = matches
        .get_one::<String>("port")
        .unwrap_or(&format!("{}", config.port))
        .clone()
        .parse::<u16>()
        .unwrap();
    let pcap_path = matches
        .get_one::<String>("path")
        .unwrap_or(&empty_str)
        .clone();
    config.interface = matches
        .get_one::<String>("interface")
        .unwrap_or(&config.interface)
        .clone();
    config.filter = matches
        .get_one::<String>("filter")
        .unwrap_or(&config.filter)
        .clone();
    config.skip_list_file = matches
        .get_one::<String>("skip_list_file")
        .unwrap_or(&config.skip_list_file)
        .clone();
    config.output = matches
        .get_one::<String>("output")
        .unwrap_or(&config.output)
        .clone();
    config.output_type = matches
        .get_one::<String>("output_type")
        .unwrap_or(&config.output_type)
        .clone();
    config.database = matches
        .get_one::<String>("database")
        .unwrap_or(&config.database)
        .clone();
    config.daemon = matches
        .get_one::<bool>("daemon")
        .unwrap_or(&config.daemon)
        .clone();
    config.promisc = matches
        .get_one::<bool>("promisc")
        .unwrap_or(&config.promisc)
        .clone();
    config.toplistsize = matches
        .get_one::<usize>("toplistsize")
        .unwrap_or(&config.toplistsize)
        .clone();
    config.pid_file = matches
        .get_one::<String>("pid_file")
        .unwrap_or(&config.pid_file)
        .clone();
    config.gid = matches
        .get_one::<String>("gid")
        .unwrap_or(&config.gid)
        .clone();
    config.uid = matches
        .get_one::<String>("uid")
        .unwrap_or(&config.uid)
        .clone();

    let rr_types = parse_rrtypes(&matches.get_one("rrtypes").unwrap_or(&empty_str).clone());
    if !rr_types.is_empty() {
        config.rr_type = rr_types;
    }
    let stdout = File::open("/dev/null").unwrap();
    let stderr = File::open("/dev/null").unwrap();
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
        match daemonize.start() {
            Ok(_) => {
                //                println!("Daemonizing");
                run(&config, cap, &pcap_path);
            }
            Err(_e) => {
                //              println!("Error daemonizing {}", e);
                exit(-1);
            }
        }
    } else {
        run(&config, cap, &pcap_path);
    }
}
