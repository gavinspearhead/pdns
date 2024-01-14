#![allow(non_camel_case_types)]




use clap::builder::Str;
use pcap::{Active, Offline};
use pcap::{Capture, Linktype};
use phf::map;
use std::fmt::format;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
//use std::os;
use std::str::{self, from_utf8, FromStr};
//use std::ops::Add;
//use core::result;
//use std::arch::x86_64::_addcarryx_u32;
use ::phf::{phf_map, Map};
use base64::{engine::general_purpose, Engine as _};
use byteorder::BigEndian; // 1.3.4
use byteorder::ByteOrder;
use chrono::prelude::*;
use chrono::{DateTime, Utc};
use clap::{arg, Command, Parser};
use colored::Colorize;
use hex::encode;
use std::collections::HashMap;
use std::process::exit;
use strum::IntoEnumIterator;
use strum_macros::EnumIter; // 0.17.1

#[derive(Debug, EnumIter, Copy, Clone)]
enum DNS_Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl PartialEq for DNS_Class {
    fn eq(&self, other: &Self) -> bool {
        return *self as u16 == *other as u16;
    }
}
impl DNS_Class {
    fn to_str(self) -> Result<String, Box<dyn std::error::Error>> {
        if self == DNS_Class::IN {
            return Ok("IN".parse().unwrap());
        } else if self == DNS_Class::CS {
            return Ok(("CS").parse().unwrap());
        } else if self == DNS_Class::CH {
            return Ok(("CH").parse().unwrap());
        } else if self == DNS_Class::HS {
            return Ok(("HS").parse().unwrap());
        } else {
            return Err(format!("Invalid Class {:?}", self).into());
        }
    }
    fn find(val: u16) -> Result<Self, Box<dyn std::error::Error>> {
        for cl in DNS_Class::iter() {
            if (cl as u16) == val {
                return Ok(cl);
            }
        }
        return Err(format!("Invalid Class type  {:?}", val).into());
    }
}

#[derive(Debug, EnumIter, Copy, Clone)]
enum DNS_RR_type {
    A = 1,
    A6 = 38,
    AAAA = 28,
    AFSDB = 18,
    AMTRELAY = 260,
    ANY = 255,
    APL = 42,
    ATMA = 34,
    AVC = 258,
    AXFR = 252,
    CAA = 257,
    CDNSKEY = 60,
    CDS = 59,
    CERT = 37,
    CNAME = 5,
    CSYNC = 62,
    DHCID = 49,
    DLV = 32769,
    DNAME = 39,
    DNSKEY = 48,
    DOA = 259,
    DS = 43,
    EID = 31,
    EUI48 = 108,
    EUI64 = 109,
    GID = 102,
    GPOS = 27,
    HINFO = 13,
    HIP = 55,
    HTTPS = 65,
    IPSECKEY = 45,
    ISDN = 20,
    IXFR = 251,
    KEY = 25,
    KX = 36,
    L32 = 105,
    L64 = 106,
    LOC = 29,
    LP = 107,
    MAILA = 254,
    MAILB = 253,
    MB = 7,
    MD = 3,
    MF = 4,
    MG = 8,
    MINFO = 14,
    MR = 9,
    MX = 15,
    NAPTR = 35,
    //NB = 32,
    // NBSTAT = 33,
    NID = 104,
    NIMLOC = 32,
    NINF0 = 56,
    NS = 2,
    NSAP = 22,
    NSAP_PTR = 23,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    NSEC = 47,
    NULL = 10,
    NXT = 30,
    OPENPGPKEY = 61,
    OPT = 41,
    PTR = 12,
    PX = 26,
    RKEY = 57,
    RP = 17,
    RRSIG = 46,
    RT = 21,
    SIG = 24,
    SINK = 40,
    SMIMEA = 53,
    SOA = 6,
    SPF = 99,
    SRV = 33,
    SSHFP = 44,
    SVCB = 64,
    TA = 32768,
    TALINK = 58,
    TKEY = 249,
    TLSA = 52,
    TSIG = 250,
    TXT = 16,
    UID = 101,
    UINFO = 100,
    UNSPEC = 103,
    URI = 256,
    WKS = 11,
    X25 = 19,
    ZONEMD = 63,
}
impl PartialEq for DNS_RR_type {
    fn eq(&self, other: &Self) -> bool {
        //return matches!(self, other);
        return *self as u16 == *other as u16;
    }
}

#[derive(Debug,  Clone)]
struct Config {
    rr_type:Vec<DNS_RR_type>,
    path: String,
    interface: String,
    filter: String,
}


impl Config{
    fn new() -> Config
    {
        let mut c = Config {
            rr_type: Vec::<DNS_RR_type>::new(),
            path : String::new(),
            interface: String::new(),
            filter: String::new()
        };
        c.rr_type .extend(vec![DNS_RR_type::A, DNS_RR_type::AAAA, DNS_RR_type::NS, DNS_RR_type::PTR, DNS_RR_type::MX]);
        return c;
    }
}


impl DNS_RR_type {
    fn to_str(self) -> Result<String, Box<dyn std::error::Error>> {
        if self == DNS_RR_type::ANY {
            return Ok("ANY".parse().unwrap());
        } else if self == DNS_RR_type::A {
            return Ok(("A").parse().unwrap());
        } else if self == DNS_RR_type::AAAA {
            return Ok(("AAAA").parse().unwrap());
        } else if self == DNS_RR_type::PTR {
            return Ok(("PTR").parse().unwrap());
        } else if self == DNS_RR_type::SOA {
            return Ok(("SOA").parse().unwrap());
        } else if self == DNS_RR_type::TXT {
            return Ok(("TXT").parse().unwrap());
        } else if self == DNS_RR_type::SRV {
            return Ok(("SRV").parse().unwrap());
        } else if self == DNS_RR_type::CNAME {
            return Ok(("CNAME").parse().unwrap());
        } else if self == DNS_RR_type::MX {
            return Ok(("MX").parse().unwrap());
        } else if self == DNS_RR_type::CAA {
            return Ok(("CAA").parse().unwrap());
        } else if self == DNS_RR_type::MF {
            return Ok(("MF").parse().unwrap());
        } else if self == DNS_RR_type::MD {
            return Ok(("MD").parse().unwrap());
        } else if self == DNS_RR_type::NS {
            return Ok(("NS").parse().unwrap());
        } else if self == DNS_RR_type::HTTPS {
            return Ok(("HTTPS").parse().unwrap());
        } else if self == DNS_RR_type::OPT {
            return Ok(("OPT").parse().unwrap());
        } else if self == DNS_RR_type::ANY {
            return Ok(("ANY").parse().unwrap());
        } else if self == DNS_RR_type::MB {
            return Ok(("MB").parse().unwrap());
        } else if self == DNS_RR_type::MG {
            return Ok(("MG").parse().unwrap());
        } else if self == DNS_RR_type::NULL {
            return Ok(("NULL").parse().unwrap());
        } else if self == DNS_RR_type::WKS {
            return Ok(("WKS").parse().unwrap());
        } else if self == DNS_RR_type::HINFO {
            return Ok(("HINFO").parse().unwrap());
        } else if self == DNS_RR_type::MINFO {
            return Ok(("MINFO").parse().unwrap());
        } else if self == DNS_RR_type::RP {
            return Ok(("RP").parse().unwrap());
        } else if self == DNS_RR_type::AFSDB {
            return Ok(("AFSDB").parse().unwrap());
        } else if self == DNS_RR_type::X25 {
            return Ok(("X25").parse().unwrap());
        } else if self == DNS_RR_type::ISDN {
            return Ok(("ISDN").parse().unwrap());
        } else if self == DNS_RR_type::RT {
            return Ok(("RT").parse().unwrap());
        } else if self == DNS_RR_type::NSAP {
            return Ok(("NSAP").parse().unwrap());
        } else if self == DNS_RR_type::NSAP_PTR {
            return Ok(("NSAP_PTR").parse().unwrap());
        } else if self == DNS_RR_type::SIG {
            return Ok(("SIG").parse().unwrap());
        } else if self == DNS_RR_type::KEY {
            return Ok(("KEY").parse().unwrap());
        } else if self == DNS_RR_type::PX {
            return Ok(("PX").parse().unwrap());
        } else if self == DNS_RR_type::GPOS {
            return Ok(("GPOS").parse().unwrap());
        } else if self == DNS_RR_type::LOC {
            return Ok(("LOC").parse().unwrap());
        } else if self == DNS_RR_type::NXT {
            return Ok(("NXT").parse().unwrap());
        } else if self == DNS_RR_type::EID {
            return Ok(("EID").parse().unwrap());
        } else if self == DNS_RR_type::NIMLOC {
            return Ok(("NIMLOC").parse().unwrap());
        } else if self == DNS_RR_type::ATMA {
            return Ok(("ATMA").parse().unwrap());
        } else if self == DNS_RR_type::NAPTR {
            return Ok(("NAPTR").parse().unwrap());
        } else if self == DNS_RR_type::KX {
            return Ok(("KX").parse().unwrap());
        } else if self == DNS_RR_type::CERT {
            return Ok(("CERT").parse().unwrap());
        } else if self == DNS_RR_type::A6 {
            return Ok(("A6").parse().unwrap());
        } else if self == DNS_RR_type::DNAME {
            return Ok(("DNAME").parse().unwrap());
        } else if self == DNS_RR_type::SINK {
            return Ok(("SINK").parse().unwrap());
        } else if self == DNS_RR_type::APL {
            return Ok(("APL").parse().unwrap());
        } else if self == DNS_RR_type::DS {
            return Ok(("DS").parse().unwrap());
        } else if self == DNS_RR_type::SSHFP {
            return Ok(("SSHFP").parse().unwrap());
        } else if self == DNS_RR_type::IPSECKEY {
            return Ok(("IPSECKEY").parse().unwrap());
        } else if self == DNS_RR_type::RRSIG {
            return Ok(("RRSIG").parse().unwrap());
        } else if self == DNS_RR_type::NSEC {
            return Ok(("NSEC").parse().unwrap());
        } else if self == DNS_RR_type::DNSKEY {
            return Ok(("DNSKEY").parse().unwrap());
        } else if self == DNS_RR_type::DHCID {
            return Ok(("DHCID").parse().unwrap());
        } else if self == DNS_RR_type::NSEC3 {
            return Ok(("NSEC3").parse().unwrap());
        } else if self == DNS_RR_type::NSEC3PARAM {
            return Ok(("NSEC3PARAM").parse().unwrap());
        } else if self == DNS_RR_type::TLSA {
            return Ok(("TLSA").parse().unwrap());
        } else if self == DNS_RR_type::SMIMEA {
            return Ok(("SMIMEA").parse().unwrap());
        } else if self == DNS_RR_type::HIP {
            return Ok(("HIP").parse().unwrap());
        } else if self == DNS_RR_type::NINF0 {
            return Ok(("NINFO").parse().unwrap());
        } else if self == DNS_RR_type::RKEY {
            return Ok(("RKEY").parse().unwrap());
        } else if self == DNS_RR_type::TALINK {
            return Ok(("TALINK").parse().unwrap());
        } else if self == DNS_RR_type::CDS {
            return Ok(("CDS").parse().unwrap());
        } else if self == DNS_RR_type::CDNSKEY {
            return Ok(("CDNSKEY").parse().unwrap());
        } else if self == DNS_RR_type::SPF {
            return Ok(("SPF").parse().unwrap());
        } else if self == DNS_RR_type::UINFO {
            return Ok(("UINFO").parse().unwrap());
        } else if self == DNS_RR_type::UID {
            return Ok(("UID").parse().unwrap());
        } else if self == DNS_RR_type::GID {
            return Ok(("GID").parse().unwrap());
        } else if self == DNS_RR_type::UNSPEC {
            return Ok(("UNSPEC").parse().unwrap());
        } else if self == DNS_RR_type::NID {
            return Ok(("NID").parse().unwrap());
        } else if self == DNS_RR_type::L32 {
            return Ok(("L32").parse().unwrap());
        } else if self == DNS_RR_type::L64 {
            return Ok(("L64").parse().unwrap());
        } else if self == DNS_RR_type::LP {
            return Ok(("LP").parse().unwrap());
        } else if self == DNS_RR_type::EUI48 {
            return Ok(("EUI48").parse().unwrap());
        } else if self == DNS_RR_type::EUI64 {
            return Ok(("EUI64").parse().unwrap());
        } else if self == DNS_RR_type::TKEY {
            return Ok(("TKEY").parse().unwrap());
        } else if self == DNS_RR_type::TSIG {
            return Ok(("TSIG").parse().unwrap());
        } else if self == DNS_RR_type::IXFR {
            return Ok(("IXFR").parse().unwrap());
        } else if self == DNS_RR_type::AXFR {
            return Ok(("AXFR").parse().unwrap());
        } else if self == DNS_RR_type::MAILB {
            return Ok(("MAILB").parse().unwrap());
        } else if self == DNS_RR_type::MAILA {
            return Ok(("MAILA").parse().unwrap());
        } else if self == DNS_RR_type::URI {
            return Ok(("URI").parse().unwrap());
        } else if self == DNS_RR_type::AVC {
            return Ok(("AVC").parse().unwrap());
        } else if self == DNS_RR_type::DOA {
            return Ok(("DOA").parse().unwrap());
        } else if self == DNS_RR_type::AMTRELAY {
            return Ok(("AMTRELAY").parse().unwrap());
        } else if self == DNS_RR_type::TA {
            return Ok(("TA").parse().unwrap());
        } else if self == DNS_RR_type::DLV {
            return Ok(("DLV").parse().unwrap());
        } else if self == DNS_RR_type::OPENPGPKEY {
            return Ok(("OPENPGPKEY").parse().unwrap());
        } else {
            return Err(format!("Unknown RR type  {:?}", self).into());
        }
    }

    fn find(val: u16) -> Result<Self, Box<dyn std::error::Error>> {
        for rr in DNS_RR_type::iter() {
            if (rr as u16) == val {
                return Ok(rr);
            }
        }
        return Err(format!("Invalid RR type  {:?}", val).into());
    }
}

#[derive(Debug)]
struct DNS_record {
    rr_type: String,
    ttl: u32,
    class: String,
    name: String,
    rdata: String,
}

impl DNS_record {
    fn to_str(&self) -> Result<String, Box<dyn std::error::Error>> {
        return Ok(format!(
            "{} {} {} {} {}",
            self.name, self.rr_type, self.class, self.ttl, self.rdata
        ));
    }
}

impl Default for DNS_record {
    fn default() -> Self {
        DNS_record {
            rr_type: String::new(),
            ttl: 0,
            class: String::new(),
            name: String::new(),
            rdata: String::new(),
        }
    }
}

struct statistics {
    errors: HashMap<String, u128>,
    types: HashMap<String, u128>,
    queries: u128,
    answers: u128,
    additional: u128,
    authority: u128,
}

impl statistics {
    fn origin() -> statistics {
        statistics {
            errors: HashMap::new(),
            types: HashMap::new(),
            queries: 0,
            answers: 0,
            additional: 0,
            authority: 0,
        }
    }

    fn to_str(&self) -> String {
        return format!(
            "Statistics:
        Types: {:?}
        Errors : {:?}
        Queries: {}
        Answers: {}
        Additional: {}
        Authority: {}",
            self.types, self.errors, self.queries, self.answers, self.additional, self.authority
        );
    }
}

#[derive(Debug)]
struct Packet_info {
    timestamp: DateTime<Utc>,
    sp: u16, // source port
    dp: u16, // destination port
    s_addr: IpAddr,
    d_addr: IpAddr,
    ip_len: u16,
    frame_len: u16,
    data_len: u32,
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
            dns_records: Vec::new(),
        }
    }
}

impl Packet_info {
    fn set_source_port(&mut self, port: u16) {
        self.sp = port
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

    fn to_str(&self) -> Result<String, Box<dyn std::error::Error>> {
        return Ok(format!(
            "{}:{} => {}:{}\n{:?}",
            self.s_addr, self.sp, self.d_addr, self.dp, self.dns_records
        ));
    }
}

fn dns_reply_type(u: u16) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("NOERROR");
        }
        1 => {
            return Ok("FORMERROR");
        }
        2 => {
            return Ok("SERVFAIL");
        }
        3 => {
            return Ok("NXDOMAIN");
        }
        5 => {
            return Ok("REFUSED");
        }
        6 => {
            return Ok("YXDOMAIN");
        }
        7 => {
            return Ok("YXRRSET");
        }
        8 => {
            return Ok("NXRRSET");
        }
        9 => {
            return Ok("NOTAUTH");
        }
        10 => {
            return Ok("NOTZONE");
        }
        11 => {
            return Ok("DSOTYPENI");
        }
        16 => {
            return Ok("BADVERS");
        }
        17 => {
            return Ok("BADKEY");
        }
        18 => {
            return Ok("BADTIME");
        }
        19 => {
            return Ok("BADMODE");
        }
        20 => {
            return Ok("BADNAME");
        }
        21 => {
            return Ok("BADALG");
        }
        22 => {
            return Ok("BADTRUNC");
        }
        23 => {
            return Ok("BADCOOKIE");
        }
        _ => {
            return Err("Unkown error".into());
        }
    }
}

fn tlsa_cert_usage(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("PKIX-TA");
        }
        1 => {
            return Ok("PKIX-EE");
        }
        2 => {
            return Ok("DANE-TA");
        }
        3 => {
            return Ok("DANE-EE");
        }
        _ => {
            return Err("Unkown usage".into());
        }
    };
}

fn tlsa_selector(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("All");
        }
        1 => {
            return Ok("Pubkey");
        }
        _ => {
            return Err("Unkown selector".into());
        }
    };
}

fn tlsa_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("None");
        }
        1 => {
            return Ok("SHA2-256");
        }
        2 => {
            return Ok("SHA2-512");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    };
}

fn sshfp_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("RSA");
        }
        2 => {
            return Ok("DSS");
        }
        3 => {
            return Ok("ECDSA");
        }
        4 => {
            return Ok("Ed25519");
        }
        5 => {
            return Ok("Ed448");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    }
}

fn sshfp_fp_type(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("SHA-1");
        }
        2 => {
            return Ok("SHA2-256");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    }
}

fn dnssec_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("RSA/MD5");
        }
        3 => {
            return Ok("DSA/SHA1");
        }
        5 => {
            return Ok("RSA/SHA1");
        }
        6 => {
            return Ok("DSA-NSEC3-SHA1");
        }
        7 => {
            return Ok("RSASHA1-NSEC3-SHA1");
        }
        8 => {
            return Ok("RSA/SHA2-256");
        }
        10 => {
            return Ok("RSA/SHA2-512");
        }
        12 => {
            return Ok("GOST");
        }
        13 => {
            return Ok("ECDSA/SHA2-256");
        }
        14 => {
            return Ok("ECDSA/SHA2-384");
        }
        15 => {
            return Ok("Ed25519");
        }
        16 => {
            return Ok("Ed448");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    };
}

fn dnssec_digest(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("SHA1");
        }
        2 => {
            return Ok("SHA2-256");
        }
        3 => {
            return Ok("GOST R 34.10-2001");
        }
        4 => {
            return Ok("SHA2-384");
        }
        _ => {
            return Err("Unkown digest".into());
        }
    };
}

fn dns_read_u16(packet: &[u8], offset: usize) -> Result<u16, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 2) else {
        return Err("Invalid index !".into());
    };
    let val: u16 = BigEndian::read_u16(r);
    return Ok(val);
}

fn dns_read_u32(packet: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 4) else {
        return Err("Invalid index !".into());
    };
    let val: u32 = BigEndian::read_u32(r);
    return Ok(val);
}

fn timestame_to_str(timestamp: u32) -> Result<String, Box<dyn std::error::Error>> {
    let Some(naive_datetime) = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0) else {
        return Err("Cannot parse timestamp".into());
    };
    let datetime_again: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive_datetime, Utc);
    return Ok(datetime_again.to_string());
}

fn dns_parse_rdata(
    rdata: &[u8],
    rrtype: DNS_RR_type,
    packet: &[u8],
    offset_in: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut outdata = String::new();

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
        let mut r: [u8; 16] = [0; 16];
        r.clone_from_slice(rdata);
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
        let mut ns: String = String::new();
        let mut mb: String = String::new();
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
    } else if rrtype == DNS_RR_type::TXT {
        let tlen: usize = rdata[0].into();
        let Some(r) = rdata.get(1..tlen + 1) else {
            return Err("Index error".into());
        };
        let s = std::str::from_utf8(r)?;
        return Ok(String::from(s));
    } else if rrtype == DNS_RR_type::PTR {
        let (ptr, _offset_out) = dns_parse_name(packet, offset_in)?;
        return Ok(ptr);
    } else if rrtype == DNS_RR_type::MX {
        let _pref = BigEndian::read_u16(&rdata[0..2]);
        let (mx, _offset_out) = dns_parse_name(packet, offset_in + 2)?;
        return Ok(mx);
    } else if rrtype == DNS_RR_type::HINFO {
        let cpu_len: usize = rdata[0] as usize;
        let mut offset: usize = 1;
        let Some(r) = rdata.get(offset..offset + cpu_len) else {
            return Err("Index error".into());
        };
        let mut s = String::from(std::str::from_utf8(r)?);
        offset += cpu_len;
        let os_len = rdata[offset] as usize;
        offset += 1;
        s.push(' ');
        let Some(r) = &rdata.get(offset..offset + os_len) else {
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
    } else if rrtype == DNS_RR_type::TLSA {
        if rdata.len() < 4 {
            return Err("Rdata to small".into());
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
    } else if rrtype == DNS_RR_type::CDS || rrtype == DNS_RR_type::DS {
        let keyid = dns_read_u16(rdata, 0)?;
        let alg = dnssec_algorithm(rdata[2])?;
        let dig_t = dnssec_digest(rdata[3])?;
        let dig = &rdata[4..];
        return Ok(format!("{} {} {} {}", keyid, alg, dig_t, hex::encode(dig)));
    } else if rrtype == DNS_RR_type::DNSKEY || rrtype == DNS_RR_type::CDNSKEY {
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
        let version = rdata[0];
        let size = rdata[1];
        let hor_prec = rdata[2];
        let ver_prec = rdata[3];
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
        let flag_len = rdata[4];
        let mut offset: usize = 5;
        let flags = str::from_utf8(&rdata[offset..offset + flag_len as usize])?;
        offset += flag_len as usize;
        println!("{} {:x?}", flag_len, flags);
        let srv_len = rdata[offset as usize];
        offset += 1;
        let srv = str::from_utf8(&rdata[offset..offset + srv_len as usize])?;
        offset += srv_len as usize;
        let re_len = rdata[offset];
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
        let alg = dnssec_algorithm(rdata[2])?;
        let labels = rdata[3];
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
            r[15 - i] = rdata[(len - i)]
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
            let mut r: [u8; 16] = [0; 16];
            r.clone_from_slice(&rdata[2..18]);
            let addr = Ipv6Addr::from(r);
            relay = format!("{}", addr);
        } else if rtype == 1 {
            let mut r: [u8; 4] = [0; 4];
            r.clone_from_slice(&rdata[2..6]);
            let addr = Ipv4Addr::from(r);
            relay = format!("{}", addr);
        }
        return Ok(format!("{} {} {} {}", precedence, dbit, rtype, relay));
    } else if rrtype == DNS_RR_type::APL {
        // todo
    } else if rrtype == DNS_RR_type::ATMA {
        let format = rdata[0];
        let address = &rdata[1..];
        return Ok(format!("{} {}", format, hex::encode(address)));

    } else {
        return Err(format!("RR type not supported {:?}", rrtype).into());
    }
    return Ok("".to_string());
}

fn dns_parse_name(
    packet: &[u8],
    offset: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let (mut name, mut offset_out) = dns_parse_name_internal(packet, offset)?;
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

fn parse_question(
    query: &[u8],
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut statistics,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;

    let rrtype_val = dns_read_u16(packet, offset)?;
    let class_val = dns_read_u16(packet, offset + 2)?;
    let rrtype = parse_rrtype(rrtype_val).unwrap();
    let class = parse_class(class_val).unwrap();
    /*println!(
        "Question: {} {} {} ",
        name,
        rrtype.to_str().unwrap(),
        class.to_str().unwrap()
    );*/
    let len = offset - offset_in;
    return Ok(len + 4);
}

fn parse_answer(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut statistics,
) -> Result<usize, Box<dyn std::error::Error>> {
    //let mut offset = offset_in;
    //println!("aaaeE {} ", offset_in);
    println!(
        "Parsing DNS : {} {:x?}",
        offset_in,
        &packet[offset_in..offset_in + 4]
    );
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;
    let rrtype_val = BigEndian::read_u16(&packet[offset..offset + 2]);
    let rrtype = parse_rrtype(rrtype_val)?;
    if rrtype == DNS_RR_type::OPT {
        return Ok(0);
    }
    let class_val = dns_read_u16(packet, offset + 2)?;
    let class = parse_class(class_val)?;
    let ttl = dns_read_u32(packet, offset + 4)?;
    let datalen: usize = dns_read_u16(packet, offset + 8)?.into();
    let data = &packet[offset + 10..offset + 10 + datalen];
    let rdata = dns_parse_rdata(data, rrtype, packet, offset + 10)?;
    let mut c = stats.types.entry(rrtype.to_str()?).or_insert(1);
    *c += 1;
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
    let mut rec: DNS_record = DNS_record {
        rr_type: rrtype.to_str()?,
        ttl: ttl,
        class: class.to_str()?,
        rdata: rdata,
        name: name,
    };
    packet_info.add_dns_record(rec);
    offset += datalen as usize - 1;
    let len = offset - offset_in;
    return Ok(len);
}

fn parse_dns(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
) -> Result<(), Box<dyn std::error::Error>> {
    let trans_id = dns_read_u16(packet, 0)?;
    let flags = dns_read_u16(packet, 2)?;
    let qr = (flags & 0x8000) >> 15;
    let opcode = (flags >> 11) & 0x000f;
    let tr = (flags >> 9) & 0x0001;
    let rd = (flags >> 8) & 0x0001;
    let ra = (flags >> 7) & 0x0001;
    let rcode = flags & 0x000f;

    let questions = dns_read_u16(packet, 4)?;
    let answers = dns_read_u16(packet, 6)?;
    let authority = dns_read_u16(packet, 8)?;
    let additional = dns_read_u16(packet, 10)?;
    stats.additional += additional as u128;
    stats.authority += authority as u128;
    stats.answers += answers as u128;
    stats.queries += questions as u128;

    if qr != 1 {
        // we ignore questions
        return Ok(());
    }

    let c = stats
        .errors
        .entry(dns_reply_type(rcode)?.to_string())
        .or_insert(1);
    *c += 1;
    if rcode != 0 {
        // errors
        return Ok(());
    }

    let mut offset: usize = 12;
    for i in 0..questions {
        let query = &packet[12..];
        offset += parse_question(query, packet_info, packet, offset, stats)?;
    }
    //println!("Answers {} {} ", answers, offset);
    for i in 0..answers {
        offset += parse_answer(packet_info, packet, offset, stats)?;
    }
    //println!("Authority {} {}", authority, offset);
    for _i in 0..authority {
        offset += parse_answer(packet_info, packet, offset, stats)?;
    }
    //println!("Additional {} {}", additional, offset) ;
    for _i in 0..additional {
        offset += parse_answer(packet_info, packet, offset, stats)?;
    }
    //println!("{}", packet_info.to_str()?);
    println!("done");
    return Ok(());
}

fn parse_tcp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 20 {
        return Err("Invalid P header".into());
    }
    let sp: u16 = dns_read_u16(packet, 0)?;
    let dp: u16 = dns_read_u16(packet, 2)?;
    let hl: u8 = (packet[12] >> 4) * 4;
    let len: u32 = (packet.len() - hl as usize) as u32;
    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(len);
    return Ok(());
}
fn parse_udp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
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
        return parse_dns(&packet[8..], packet_info, stats);
    } else {
        return Err(format!("Not a dns packet {} {}", dp, sp).into());
    }
}

fn parse_ip_data(
    packet: &[u8],
    protocol: u8,
    packet_info: &mut Packet_info,
    stats: &mut statistics,
) -> Result<(), Box<dyn std::error::Error>> {
    if protocol == 6 {
        // TCP
        return parse_tcp(&packet, packet_info, stats);
    } else if protocol == 17 {
        //  UDP
        return parse_udp(&packet, packet_info, stats);
    }
    return Ok(());
}

fn parse_ipv4(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
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
    parse_ip_data(&packet[ihl as usize..], next_header, packet_info, stats)?;
    return Ok(());
}
fn parse_ipv6(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
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
    //println!("ipv6, {:x?} {} {} {}", packet[0] >>4, src, dst, next_header);
    parse_ip_data(&packet[40..], next_header, packet_info, stats)?;
    return Ok(());
}

fn parse_eth(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut statistics,
) -> Result<(), Box<dyn std::error::Error>> {
    // println!("ETH {:x?} {:x?}", packet[12], packet[13]);
    if packet[12..14] == [8, 0] {
        return parse_ipv4(&packet[14..], packet_info, stats);
    } else if packet[12..14] == [0x86, 0xdd] {
        return parse_ipv6(&packet[14..], packet_info, stats);
    } else {
        return Err(format!("Unknown packet type {:x?}", &packet[12..14]).into());
    }
    //return Ok(());
}

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    path: std::path::PathBuf,
}

fn packet_loop_file(mut cap: Capture<Offline>) {
    let mut stats = statistics::origin();

    while let Ok(packet) = cap.next_packet() {
        let mut packet_info: Packet_info = Default::default();
        let result = parse_eth(&packet.data, &mut packet_info, &mut stats);
        match result {
            Ok(_c) => {
                println!("{}", format!("{:?}", packet_info).green())
            }
            Err(error) => {
                println!("{}", format!("{:?}", error).red());
            }
        }
    }
    println!("{}", stats.to_str());
}

fn packet_loop(mut cap: Capture<Active>) {
    let mut stats = statistics::origin();
    while let Ok(packet) = cap.next_packet() {
        //println!("received packet! {:x?}", &packet.data);
        let mut packet_info: Packet_info = Default::default();
        let result = parse_eth(&packet.data, &mut packet_info, &mut stats);
        match result {
            Ok(_c) => {
                println!("{}", format!("{:?}", packet_info).green());
            }
            Err(error) => {
                println!("{}", format!("{:?}", error).red());
            }
        }
    }
}

fn main() {
    // let args = Args::parse();
    let matches = Command::new("pdns")
        .version("1.0")
        .author("")
        .about("PassiveDNS")
        .arg(
            arg!(--path <VALUE>)
                .required(false)
                .default_missing_value("")
                .short('p'),

        ).arg(
            arg!(--rrtypes <VALUE>).required(false).short('r')
        ).arg(arg!(--interface <VALUE>).required(false).short('i')
        ).arg(arg!(--filter <VALUE>).required(false).short('f')

        )
        .get_matches();
    //let mut cap;
    let empty_str = String::new();
    let mut config = Config :: new();

    config.path = matches.get_one::<String>("path").unwrap_or(&empty_str).clone();
    config.interface = matches.get_one::<String>("interface").unwrap_or(&empty_str).clone();
    config.filter = matches.get_one::<String>("filter").unwrap_or(&empty_str).clone();

    println!("{:?}", config);

    if config.path != "" {
        let cap = Capture::from_file(config.path);
        match cap {
            Ok(mut c) => {
                c.filter(config.filter.as_str(), false).unwrap();
                packet_loop_file(c);
            }
            Err(e) => {
                println!("{}", format!("{:?}", e).red());
                exit(-1);
            }
        }
    } else if config.interface != "" {
            let mut cap = Capture::from_device(config.interface.as_str())
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .open()
            .unwrap();
        cap.filter(config.filter.as_str(), false).unwrap();
        let link_type = cap.get_datalink();
        println!("link: {:?}", link_type);
        if link_type != Linktype::ETHERNET {
            panic!("Not ethernet");
        }
        packet_loop(cap);
    }
}
