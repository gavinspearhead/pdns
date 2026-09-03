use crate::version::{VERSION,PROGNAME};
use crate::dns_answers::{write_header, write_question, DnsAnswer};
use base64::Engine;
use chrono::DateTime;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use native_tls::TlsConnector;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::process::exit;
use std::result::Result;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, fmt, reload, Layer};
pub mod config;
pub mod dns;
pub mod dns_answers;
pub mod dns_class;
pub mod dns_edns;
pub mod dns_helper;
pub mod dns_name;
pub mod dns_opcodes;
pub mod dns_packet;
pub mod dns_protocol;
pub mod dns_query;
pub mod dns_record;
pub mod dns_record_trait;
pub mod dns_reply_type;
pub mod dns_rr;
pub mod dns_rr_type;
pub mod ech;
pub mod edns;
pub mod errors;
pub mod packet_info;
pub mod rank;
pub mod rr;
pub mod statistics;
pub mod time_stats;
pub mod util;
pub mod version;

use crate::dns_class::DnsClass;
use crate::dns_helper::NamesList;
use crate::dns_name::is_valid_dns_name;
use crate::dns_opcodes::DnsOpcodes;
use crate::dns_packet::{parse_dns, DnsHeader, DnsQuestion};
use crate::dns_protocol::DnsProtocol;
use crate::dns_protocol::DnsProtocol::{
    HTTPS_GET, HTTPS_JSON, HTTPS_POST, HTTP_GET, HTTP_POST, QUIC, TCP, TLS, UDP,
};
use crate::dns_query::{DnsDir, DnsQuery};
use crate::dns_record::DnsField;
use crate::dns_record::DnsField::{Additional, Answer, Authority};
use crate::dns_reply_type::DnsReplyType;
use crate::dns_reply_type::DnsReplyType::NOERROR;
use crate::dns_rr_type::DnsRRType;
use crate::dns_rr_type::DnsRRType::{ANY, AXFR, IXFR, PTR};
use crate::edns::EDNSOptionCodes;
use crate::packet_info::PacketInfo;
use crate::statistics::Statistics;
use crate::util::{load_asn_database, read_public_suffix_file};
use crate::DnsDir::Forward;

type AppError = Box<dyn std::error::Error>;

//type DnsQueryResult = (Vec<u8>, IpAddr, IpAddr, u16, u16, u16, usize);
const DEFAULT_PUBLIC_SUFFIX_FILE: &str = "../../data/public_suffix_list.dat";
const DEFAULT_ASN_DATABASE_FILE: &str = "../../data/ip2asn-combined.tsv";
const DEFAULT_DNS_SERVER: &str = "1.1.1.1";
const DEFAULT_STATS_TOPLIST_SIZE: usize = 10;
const MAX_UDP_DNS_RESPONSE_SIZE: usize = 2048;
const RESOLV_LOCATION: &str = "/etc/resolv.conf";

const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const DOQ_PORT: u16 = 853;

#[derive(Parser, Debug, Clone, Deserialize, Default, Serialize)]
#[command(name = "Dot - DNS Lookup Tool")]
#[command(version = VERSION)]
#[command(about = "Dot - DNS Lookup Tool")]
#[command(long_about = "DNS Lookup Tool")]
#[serde(default)]
struct DigConfig {
    #[arg(short = 's', long, default_value_t = false)]
    short: bool,

    #[arg(short = 'a', long, default_value_t = false)]
    print_additional: bool,

    #[arg(short = 'u', long, default_value_t = false)]
    print_authority: bool,

    /// Suppress output
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// Enable DNSSEC validation
    #[arg(short = 'd', long, default_value_t = false)]
    dnssec_validate: bool,

    #[arg(
        short = 'T',
        long,
        default_value = "UDP",
        value_parser = parse_dns_protocol
    )]
    transmission_type: DnsProtocol,
    #[arg(short = 'p', long = "port", default_value_t = 0)]
    dns_port: u16,

    #[arg(short = 'A', long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    lookup_asn: bool,

    #[arg(short = 'D', long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    lookup_domain: bool,

    /// Query elements: name, class, RRtype, and @server may be mixed.
    ///
    /// Example:
    /// nu.nl IN A @8.8.8.8 @9.9.9.9 example.com IN AAAA foo.com
    #[arg(long, default_value = "dns-query")]
    https_url: String,
    #[arg(skip)]
    queries: Vec<DnsQuery>,
    #[arg(long, default_value = "false")]
    nopuny: bool,
    #[arg(long, default_value = "false")]
    debug: bool,
    #[arg(long, short = 'c', default_value = None)]
    config_file: Option<String>,
    #[arg(long, short = 'f', default_value = None)]
    input_file: Option<String>,
    #[arg(long, short = 'Q', default_value = None)]
    print_query: bool,
    #[arg(long, short = 'S', default_value = None)]
    default_server: Option<String>,
    #[arg(short = 'x', action = clap::ArgAction::SetTrue)]
    x: bool,
    #[arg(short = 'j', action = clap::ArgAction::SetTrue)]
    print_json: bool,
    #[arg(long, default_value = None)]
    public_suffix_file: Option<String>,
    #[arg(long, default_value = None)]
    asn_database_file: Option<String>,
    #[arg(short = 'N', long, action = clap::ArgAction::SetTrue)]
    nsec_recon: bool,
    #[arg(short = 'Z', long, action = clap::ArgAction::SetTrue)]
    zone_transfer: bool,
    #[arg(short = 'C', long, action = clap::ArgAction::SetTrue)]
    cookie: bool,
    #[arg( long, action = clap::ArgAction::SetTrue)]
    nsid: bool,
    #[arg(long, default_value = "0")]
    padding: usize,
    #[arg( long, default_value = None)]
    client_subnet: Option<String>,
    #[arg(value_name = "QUERY", num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
    #[serde(skip)]
    query_args: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DnsEdns {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub z: u16,
    pub data_len: u16,
    pub options: Vec<DnsEdnsOption>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DnsEdnsOption {
    pub code: EDNSOptionCodes,
    pub length: u16,
    pub data: Vec<u8>,
}

impl DnsEdnsOption {
    #[must_use]
    #[inline]
    pub(crate) fn new(code: EDNSOptionCodes, data_in: Option<&[u8]>) -> Self {
        if let Some(data) = data_in {
            Self {
                code,
                length: data.len() as u16,
                data: data.to_vec(),
            }
        } else {
            Self {
                code,
                length: 0,
                data: Vec::new(),
            }
        }
    }
}

impl DnsEdns {
    #[must_use]
    pub(crate) fn new(size: u16) -> Self {
        Self {
            udp_payload_size: size,
            extended_rcode: 0,
            version: 0,
            z: 0,
            data_len: 0,
            options: Vec::new(),
        }
    }

    #[inline]
    fn set_dnssec_ok(&mut self) {
        self.z |= 0x8000;
    }

    pub(crate) fn add_option(
        &mut self,
        code: EDNSOptionCodes,
        data_in: Option<&[u8]>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(data) = data_in {
            let option_len = data
                .len()
                .checked_add(4)
                .ok_or("EDNS option length overflow")?;

            let new_len = (self.data_len as usize)
                .checked_add(option_len)
                .ok_or("EDNS options exceed u16 length")?;

            if new_len > u16::MAX as usize {
                return Err("EDNS options exceed u16::MAX".into());
            }
            self.data_len = new_len as u16;
        } else {
            self.data_len = self.data_len.checked_add(4).ok_or("EDNS option length overflow")?;
        }
    self .options.push(DnsEdnsOption::new(code, data_in));
        Ok(())
    }
}

fn read_queries_from_file(input_file: &str) -> Result<Vec<DnsQuery>, Box<dyn std::error::Error>> {
    let file = File::open(input_file)?;
    let reader = BufReader::new(file);
    let mut queries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let mut domain_name = String::new();
        let mut dns_class = DnsClass::default();
        let mut dns_rr_type: HashSet<DnsRRType> = HashSet::new();
        let mut server = String::new();
        let mut dir = Forward;

        for token in tokens {
            if token.starts_with('@') {
                if let Ok(parsed_server) = parse_dns_server(token) {
                    server = parsed_server;
                } else {
                    error!("Invalid server name: {token}");
                }
            } else if let Ok(parsed_class) = parse_dns_class(token) {
                dns_class = parsed_class;
            } else if token.contains(',') && !token.starts_with(',') && !token.ends_with(',') {
                let rr_types: Vec<&str> = token.split(',').collect();
                let mut all_valid = true;
                let mut parsed_types = Vec::new();

                for rr_type_str in rr_types {
                    if let Ok(parsed_rr_type) = parse_dns_rr_type(rr_type_str) {
                        parsed_types.push(parsed_rr_type);
                    } else if rr_type_str.eq_ignore_ascii_case("all") {
                        parsed_types.extend(DnsRRType::collect_dns_rr_types());
                        all_valid = true;
                        break;
                    } else {
                        debug!("Invalid RR type: {rr_type_str}");
                        all_valid = false;
                        break;
                    }
                }

                if all_valid && !parsed_types.is_empty() {
                    dns_rr_type.extend(parsed_types);
                } else if let Ok(parsed_rr_type) = parse_dns_rr_type(token) {
                    dns_rr_type.insert(parsed_rr_type);
                }
            } else if let Ok(parsed_rr_type) = parse_dns_rr_type(token) {
                dns_rr_type.insert(parsed_rr_type);
            } else if token.eq_ignore_ascii_case("all") {
                debug!("All RR types specified");
                dns_rr_type.extend(DnsRRType::collect_dns_rr_types());
            } else if domain_name.is_empty() {
                // First non-special token is the domain name
                if let Ok(ip) = token.parse::<IpAddr>() {
                    // Handle IP address for reverse lookup
                    if let Ok(reversed_name) = parse_ip_address(ip) {
                        domain_name = reversed_name;
                        dir = DnsDir::Reverse;
                    } else {
                        domain_name = token.to_string();
                    }
                } else {
                    let (name, parsed_dir) = parse_dns_name(token);
                    domain_name = name;
                    dir = parsed_dir;
                }
            } else {
                debug!("Skipping unknown token: {token}");
            }
        }
        if dns_rr_type.is_empty() {
            dns_rr_type.insert(DnsRRType::A);
        }
        if domain_name.is_empty() {
            debug!("Skipping empty query {line}");
        } else {
            for rr_type in dns_rr_type {
                let query = DnsQuery::new(&domain_name, dir, rr_type, dns_class, &server);
                queries.push(query);
            }
        }
    }
    Ok(queries)
}

fn read_config_from_file(
    config_file: Option<&String>,
) -> Result<Option<DigConfig>, Box<dyn std::error::Error>> {
    if let Some(ref config_file) = config_file {
        debug!("Reading config from file: {config_file}");
        let config_content = fs::read_to_string(config_file)?;
        let mut file_config: DigConfig = serde_json::from_str(&config_content)?;
        file_config.config_file = Some(config_file.to_string());
        return Ok(Some(file_config));
        // Merge file config into current config, preferring command-line args
    }
    Ok(None)
}

fn parse_dns_protocol(s: &str) -> Result<DnsProtocol, String> {
    DnsProtocol::from_str(&s.to_uppercase()).map_err(|_| format!("Invalid DNS protocol: {s}"))
}

fn parse_dns_rr_type(s: &str) -> Result<DnsRRType, String> {
    debug!("s: {s}");
    let s_upper = s.to_uppercase();
    DnsRRType::from_str(&s_upper)
        .or_else(|_| {
            let s_with_underscore = s_upper.replace('-', "_");
            DnsRRType::from_str(&s_with_underscore)
        })
        .or_else(|_| {
            // Check if the string matches typeXXX where XXX is a decimal number
            if let Some(type_str) = s_upper.strip_prefix("TYPE") {
                if let Ok(type_num) = type_str.parse::<u16>() {
                    DnsRRType::find(type_num)
                        .or_else(|_| Err(format!("Unknown DNS RR type number: {type_num}")))
                } else {
                    Err(format!("Invalid type number in: {s}"))
                }
            } else {
                Err(format!("Invalid DNS RR type: {s}"))
            }
        })
}

fn parse_dns_class(s: &str) -> Result<DnsClass, String> {
    DnsClass::from_str(&s.to_uppercase()).map_err(|_| format!("Invalid DNS class: {s}"))
}

fn parse_dns_name(s: &str) -> (String, DnsDir) {
    let punycode_result = idna::domain_to_ascii(s);
    debug!("Punycode result: {:?}", punycode_result);
    match punycode_result {
        Ok(ascii_domain) => (ascii_domain, Forward),
        Err(_) => (s.to_string(), Forward),
    }
}

fn parse_ip_address(ip_addr: IpAddr) -> Result<String, String> {
    match ip_addr {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Ok(format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut nibbles = Vec::new();

            for segment in &segments {
                nibbles.push((segment >> 12) & 0xF);
                nibbles.push((segment >> 8) & 0xF);
                nibbles.push((segment >> 4) & 0xF);
                nibbles.push(segment & 0xF);
            }

            nibbles.reverse();
            let reversed: Vec<String> = nibbles.iter().map(|n| format!("{n:x}")).collect();
            Ok(format!("{}.ip6.arpa", reversed.join(".")))
        }
    }
}

fn parse_dns_server(s: &str) -> Result<String, String> {
    s.strip_prefix('@')
        .filter(|server| !server.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| "DNS server must start with '@', for example @8.8.8.8".to_string())
}

fn read_default_nameserver(dig_config: &DigConfig) -> Result<String, String> {
    debug!("Reading default nameserver from config");
    if let Some(default_server) = &dig_config.default_server {
        debug!("Using default nameserver: {default_server}");
        return Ok(default_server.to_string());
    }
    let file = File::open(RESOLV_LOCATION)
        .map_err(|e| format!("Failed to open {RESOLV_LOCATION}: {e}"))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
        let trimmed = line.trim();

        if let Some(nameserver) = trimmed.strip_prefix("nameserver") {
            let nameserver = nameserver.trim();
            if !nameserver.is_empty() {
                return Ok(nameserver.to_string());
            }
        }
    }
    Err("No nameserver found in {RESOLV_LOCATION}".to_string())
}

fn parse_json_response(
    json_bytes: &[u8],
    query: &DnsQuery,
    server_ip: IpAddr,
    local_ip: IpAddr,
    server_port: u16,
    local_port: u16,
    protocol: DnsProtocol,
) -> Result<PacketInfo, Box<dyn std::error::Error>> {
    let mut packet_info = PacketInfo::new();

    packet_info.d_addr = server_ip;
    packet_info.s_addr = local_ip;
    packet_info.sp = local_port;
    packet_info.dp = server_port;
    packet_info.protocol = protocol;

    let json_str = std::str::from_utf8(json_bytes)?;
    let json_response: Value = serde_json::from_str(json_str)?;

    // Parse header fields

    if let Some(status) = json_response["Status"].as_u64() {
        packet_info.header.rcode = DnsReplyType::find(status as u16).unwrap_or(NOERROR);
    }

    packet_info.header.tc = u8::from(json_response["TC"].as_bool().unwrap_or(false));
    packet_info.header.rd = u8::from(json_response["RD"].as_bool().unwrap_or(false));
    packet_info.header.ra = u8::from(json_response["RA"].as_bool().unwrap_or(false));
    packet_info.header.ad = u8::from(json_response["AD"].as_bool().unwrap_or(false));
    packet_info.header.cd = u8::from(json_response["CD"].as_bool().unwrap_or(false));
    packet_info.header.qr = 1;

    // Parse Question section
    if let Some(questions) = json_response["Question"].as_array() {
        if let Some(question) = questions.first() {
            if let Some(name) = question["name"].as_str() {
                packet_info.question.name = name.to_string();
            }
            if let Some(qtype) = question["type"].as_u64() {
                packet_info.question.dns_rr_type =
                    DnsRRType::find(u16::try_from(qtype)?).unwrap_or(DnsRRType::A);
            }
            packet_info.question.dns_class_type = query.dns_class;
        }
        packet_info.header.qdcount = u16::try_from(questions.len())?;
    }

    // Parse Answer section
    if let Some(answers) = json_response["Answer"].as_array() {
        packet_info.header.ancount = u16::try_from(answers.len())?;

        for answer in answers {
            let mut record = dns_record::DnsRecord::new(
                DnsRRType::default(),
                DnsClass::default(),
                DnsReplyType::default(),
                0,
                DateTime::default(),
                "",
                0,
                "",
                DnsField::default(),
            );
            record.source_field = Answer;

            if let Some(name) = answer["name"].as_str() {
                record.name = name.to_string();
            }

            if let Some(rr_type) = answer["type"].as_u64() {
                record.rr_type = DnsRRType::find(rr_type as u16).unwrap_or(DnsRRType::A);
            }

            if let Some(ttl) = answer["TTL"].as_u64() {
                record.ttl = ttl as u32;
            }

            if let Some(data) = answer["data"].as_str() {
                record.rdata = data.to_string();
            }

            record.class = query.dns_class;
            packet_info.dns_records.push(record);
        }
    }

    Ok(packet_info)
}

fn send_dns_query(
    protocol: DnsProtocol,
    query: &DnsQuery,
    dig_config: &DigConfig,
) -> Result<(PacketInfo, usize), Box<dyn std::error::Error>> {
    let mut packet_info = PacketInfo::new();
    let server_addr = resolve_dns_server_addr(
        query,
        dig_config,
        matches!(dig_config.transmission_type, TCP | UDP),
    );
    let size = if protocol == HTTPS_JSON {
        let (json_bytes, server_ip, local_ip, server_port, local_port, size) =
            send_dns_query_https_json(&server_addr, query, &dig_config.https_url)?;
        packet_info = parse_json_response(
            &json_bytes,
            query,
            server_ip,
            local_ip,
            server_port,
            local_port,
            protocol,
        )?;
        size
    } else {
        let (query_packet, identifier) =
            build_dns_query_packet(&query.query, query.dns_rr_type, query.dns_class, dig_config)?;
        debug!("Id: {identifier}");

        debug!("Sending DNS query to {server_addr}...");
        let (response, peer_ip, local_ip, peer_port, local_port, size) = match protocol {
            TCP => send_dns_query_tcp(&server_addr, &query_packet)?,
            UDP => send_dns_query_udp(&server_addr, &query_packet)?,
            TLS => send_dns_query_tls(&server_addr, &query_packet)?,
            QUIC => send_dns_query_quic(&server_addr, &query_packet)?,
            HTTPS_POST | HTTPS_GET | HTTP_POST | HTTP_GET => {
                let use_https = matches!(protocol, HTTPS_POST | HTTPS_GET);
                let use_post = matches!(protocol, HTTPS_POST | HTTP_POST);

                send_dns_query_https(
                    &server_addr,
                    &query_packet,
                    use_https,
                    use_post,
                    &dig_config.https_url,
                )?
            }
            _ => return Err(format!("Unsupported transmission type {protocol}").into()),
        };
        packet_info.data_len = size as u32;
        packet_info.d_addr = peer_ip;
        packet_info.s_addr = local_ip;
        packet_info.sp = local_port;
        packet_info.dp = peer_port;
        packet_info.protocol = protocol;
        parse_response(&response, &mut packet_info)?;
        if identifier != packet_info.header.id {
            error!(
                "Identifier mismatch: expected {identifier}, got {}",
                packet_info.header.id
            );
        }
        size
    };

    Ok((packet_info, size))
}

fn send_dns_query_quic(
    server_addr: &str,
    query: &[u8],
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    debug!("Using QUIC to send DNS query to: {server_addr}...");
    let runtime = tokio::runtime::Runtime::new()?;

    let result = runtime.block_on(send_dns_query_quic_internal(server_addr, DOT_PORT, query));

    match result {
        Ok(response) => {
            debug!("QUIC response: {response:?}");
            Ok(response)
        }

        Err(e) => {
            error!("Failed to send DNS query over QUIC: {e}");
            Err(e)
        }
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn parse_server_address_and_port(
    server_addr: &str,
    default_port: u16,
) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let addr = server_addr.trim();

    if addr.is_empty() {
        return Err("empty server address".into());
    }

    // ------------------------------------------------------------
    // [IPv6]:port
    // ------------------------------------------------------------
    if addr.starts_with('[') {
        let close = addr
            .find(']')
            .ok_or("invalid bracketed IPv6 address: missing ']'")?;

        let host = &addr[1..close];

        // Make sure the contents really are IPv6
        match host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => {}
            Err(_) => return Err(format!("invalid IPv6 address: {host}").into()),
        }

        let remainder = &addr[close + 1..];

        if remainder.is_empty() {
            return Ok((host.to_string(), default_port));
        }

        if !remainder.starts_with(':') {
            return Err(format!("invalid address after ']': {remainder}").into());
        }

        let port_str = &remainder[1..];

        if port_str.is_empty() {
            return Err("missing port after ':'".into());
        }

        let port = port_str.parse::<u16>()?;

        return Ok((host.to_string(), port));
    }

    // ------------------------------------------------------------
    // A bare IP address
    //
    // This also handles unbracketed IPv6:
    //     2001:db8::1
    // ------------------------------------------------------------
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Ok((ip.to_string(), default_port));
    }

    // ------------------------------------------------------------
    // Something containing ':' which is therefore potentially
    // hostname:port or IPv4:port.
    //
    // Since bare IPv6 was already handled above, at this point
    // a final ':' can safely be interpreted as a port separator.
    // ------------------------------------------------------------
    if let Some(colon_pos) = addr.rfind(':') {
        let host = &addr[..colon_pos];
        let port_str = &addr[colon_pos + 1..];

        if host.is_empty() {
            return Err("missing host before ':'".into());
        }

        if port_str.is_empty() {
            return Err("missing port after ':'".into());
        }

        let port = port_str.parse::<u16>()?;

        // Validate IPv4 if it looks like an IPv4 address.
        // Otherwise, treat it as a hostname.
        if host.parse::<std::net::Ipv4Addr>().is_err() && host.contains(':') {
            return Err(format!("invalid server address: {addr}").into());
        }

        return Ok((host.to_string(), port));
    }

    // ------------------------------------------------------------
    // Bare hostname
    // ------------------------------------------------------------
    Ok((addr.to_string(), default_port))
}

async fn send_dns_query_quic_internal(
    server_addr: &str,
    port: u16,
    query: &[u8],
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    use quinn::{ClientConfig, Endpoint};

    // Parse server address to get host and Port
    let (host, port) = parse_server_address_and_port(server_addr, port)?;
    debug!("Sending DNS query to: {host} and {port}...");
    // Configure Rustls client settings for DNS over QUIC.
    //
    // Note: This disables certificate verification to accept self-signed certificates.
    // For production use, populate a root store with trusted roots instead.
    // let mut crypto = rustls::ClientConfig::builder()
    //      .dangerous()
    //    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
    //     .with_no_client_auth();

    let mut root_store = rustls::RootCertStore::empty();

    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Set ALPN protocol for DNS over QUIC.
    crypto.alpn_protocols = vec![b"doq".to_vec()];

    // Quinn needs its QUIC-aware Rustls wrapper, not rustls::ClientConfig directly.
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    let client_config = ClientConfig::new(Arc::new(quic_crypto));

    // Create QUIC endpoint.
    let mut endpoint = Endpoint::client("[::]:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let local_addr = endpoint.local_addr()?;
    let local_ip = local_addr.ip();
    let local_port = local_addr.port();

    // Connect to the server.
    let ipaddr = match dns_lookup::lookup_host(&host) {
        Ok(ips) => ips
            .into_iter()
            .next()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| {
                error!("DNS lookup failed for {host}");
                exit(1);
            }),
        Err(e) => {
            error!("DNS lookup failed for {host}: {e}",);
            exit(1);
        }
    };
    let server_addr_full = format!("{ipaddr}:{port}");
    let x: Result<SocketAddr, _> = server_addr_full.parse();
    if let Err(a) = x {
        debug!("Error Connecting to {a}...");
    }
    let connecting = endpoint.connect(server_addr_full.parse()?, &host)?;
    let connection = tokio::time::timeout(Duration::from_secs(5), connecting).await??;

    let server_ip = connection.remote_address().ip();
    let server_port = connection.remote_address().port();

    // Open a bidirectional stream.
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send a DNS query with a length prefix.
    // DNS over QUIC commonly uses one DNS message per QUIC stream.
    // If your upstream expects RFC 9250 framing only, remove the 2-byte prefix.
    let length_prefix = (query.len() as u16).to_be_bytes();
    send.write_all(&length_prefix).await?;
    send.write_all(query).await?;
    send.finish()?;

    debug!(
        "Sent {} bytes to {server_addr} over QUIC (local address: {local_ip})",
        query.len(),
    );

    // Read response length.
    let mut length_buf = [0u8; 2];
    recv.read_exact(&mut length_buf).await?;

    let response_length = u16::from_be_bytes(length_buf) as usize;
    let mut response = vec![0u8; response_length];
    recv.read_exact(&mut response).await?;

    debug!("Received {response_length} bytes from {server_addr} over QUIC",);

    // Close the connection gracefully.
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok((
        response,
        server_ip,
        local_ip,
        server_port,
        local_port,
        response_length,
    ))
}

fn send_dns_query_tls(
    server_addr: &str,
    query: &[u8],
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    // Parse server address to get host and Port
    let (host, port) = parse_server_address_and_port(server_addr, DOT_PORT)?;

    // Establish TCP connection
    debug!("Connecting to {host}:{port}...");
    let tcp_stream = TcpStream::connect(format!("{host}:{port}"))?;
    tcp_stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    tcp_stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let server_ip = tcp_stream.peer_addr()?.ip();
    let local_ip = tcp_stream.local_addr()?.ip();
    let local_port = tcp_stream.local_addr()?.port();
    let server_port = tcp_stream.peer_addr()?.port();

    // Establish TLS connection
    let connector = TlsConnector::new()?;
    let mut tls_stream = connector.connect(&host, tcp_stream)?;

    // Send DNS query with length prefix (DNS over TLS uses TCP framing)
    let length_prefix = (query.len() as u16).to_be_bytes();
    tls_stream.write_all(&length_prefix)?;
    tls_stream.write_all(query)?;
    tls_stream.flush()?;

    debug!(
        "Sent {} bytes to {server_addr} over TLS (local address: {local_ip})",
        query.len()
    );

    // Read response length
    let mut length_buf = [0u8; 2];
    tls_stream.read_exact(&mut length_buf)?;

    let response_length = u16::from_be_bytes(length_buf) as usize;
    let mut response = vec![0u8; response_length];
    tls_stream.read_exact(&mut response)?;

    debug!("Received {response_length} bytes from {server_addr} over TLS");

    Ok((
        response,
        server_ip,
        local_ip,
        server_port,
        local_port,
        response_length,
    ))
}

fn send_dns_query_https(
    server_addr: &str,
    query: &[u8],
    secure: bool,
    post: bool,
    https_url: &str,
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    // Create HTTP client with timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    debug!("Sending DNS query to: {server_addr}...");
    let response = if post {
        // POST method: send DNS query as binary body
        let doh_url = if server_addr.starts_with("https://") || server_addr.starts_with("http://") {
            server_addr.to_string()
        } else {
            let server_addr = server_addr.trim_end_matches('/');
            debug!("Server address: {server_addr}");
            if secure {
                format!("https://{server_addr}/{https_url}")
            } else {
                format!("http://{server_addr}/{https_url}")
            }
        };
        debug!("DOH url: {doh_url:?}");
        client
            .post(&doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query.to_vec())
            .send()?
    } else {
        // GET method: encode query as base64url in URL parameter
        let encoded_query = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query);

        let doh_url = if server_addr.starts_with("https://") || server_addr.starts_with("http://") {
            format!("{server_addr}?dns={encoded_query}")
        } else {
            let server_addr = server_addr.trim_end_matches('/');
            if secure {
                format!("https://{server_addr}/{https_url}?dns={encoded_query}")
            } else {
                format!("http://{server_addr}/{https_url}?dns={encoded_query}")
            }
        };

        client
            .get(&doh_url)
            .header("Accept", "application/dns-message")
            .send()?
    };

    // Extract server IP from response
    let server_ip = response
        .remote_addr()
        .ok_or("Failed to get server address")?
        .ip();
    let server_port = response.url().port().unwrap_or(HTTPS_PORT);

    // Get local address (use placeholder as we don't have direct socket access)
    let local_ip: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let local_port: u16 = 0;

    if response.status().is_success() {
        // Read response body as bytes directly
        let response_bytes = response.bytes()?.to_vec();
        let response_length = response_bytes.len();
        debug!(
            "Received {response_length} bytes from {server_addr} over DoH ({})",
            if post { "POST" } else { "GET" }
        );

        Ok((
            response_bytes,
            server_ip,
            local_ip,
            server_port,
            local_port,
            response_length,
        ))
    } else {
        Err(format!("HTTP request failed with status: {}", response.status()).into())
    }
}

fn send_dns_query_tcp(
    server_addr: &str,
    query: &[u8],
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let server_ip = stream.peer_addr()?.ip();
    let local_ip = stream.local_addr()?.ip();
    let local_port = stream.local_addr()?.port();
    let server_port = stream.peer_addr()?.port();
    let query_len = u16::try_from(query.len()).map_err(|_| "DNS query exceeds 65535 bytes")?;
    stream.write_all(&query_len.to_be_bytes())?;
    stream.write_all(query)?;
    stream.flush()?;

    debug!("Sent {query_len} bytes to {server_addr} over TCP (local address: {local_ip}");

    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf)?;

    let response_length = u16::from_be_bytes(length_buf) as usize;
    let mut response = vec![0u8; response_length];
    stream.read_exact(&mut response)?;

    //    debug!("{response:x?}");
    debug!("Received {response_length} bytes from {server_addr} over TCP",);

    Ok((
        response,
        server_ip,
        local_ip,
        server_port,
        local_port,
        response_length,
    ))
}

fn send_dns_query_udp(
    server_addr: &str,
    query: &[u8],
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let local_addr = socket.local_addr()?.ip();
    let local_port = socket.local_addr()?.port();
    let server_port = socket.peer_addr()?.port();
    let response_addr = socket.peer_addr()?;
    socket.send(query)?;
    debug!(
        "Sent {} bytes from {local_addr} to {server_addr} over UDP",
        query.len(),
    );

    let mut response = vec![0u8; MAX_UDP_DNS_RESPONSE_SIZE];
    let response_size = socket.recv(&mut response).map_err(|error| {
        error!("Error reading response: {error:?}");
        error
    })?;
    response.truncate(response_size);

    debug!("Received {response_size} bytes from {response_addr:?} over UDP (local address: {local_addr})");
    Ok((
        response,
        response_addr.ip(),
        local_addr,
        server_port,
        local_port,
        response_size,
    ))
}

fn send_dns_query_https_json(
    server_addr: &str,
    query: &DnsQuery,
    https_url: &str,
) -> Result<(Vec<u8>, IpAddr, IpAddr, u16, u16, usize), Box<dyn std::error::Error>> {
    // Create HTTP client with timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Build JSON API URL
    let doh_url = if server_addr.starts_with("https://") || server_addr.starts_with("http://") {
        format!("{server_addr}/{https_url}")
    } else {
        format!("https://{server_addr}/{https_url}")
    };
    debug!("{:?}", doh_url);
    // Send GET request with query parameters
    let response = client
        .get(&doh_url)
        .query(&[
            ("name", query.query.as_str()),
            ("type", &query.dns_rr_type.to_string()),
            ("do", &query.dnssec.to_string()),
            ("cd", &query.validate.to_string()),
        ])
        .header("Accept", "application/dns-json")
        .send()?;

    // Extract server IP from response
    let server_ip = response
        .remote_addr()
        .ok_or("Failed to get server address")?
        .ip();

    let local_ip: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    let local_port: u16 = 0;
    let server_port = response.url().port().unwrap_or(HTTPS_PORT);

    if response.status().is_success() {
        // Get JSON response as bytes
        let json_bytes = response.bytes()?.to_vec();
        let json_size = json_bytes.len();

        Ok((
            json_bytes,
            server_ip,
            local_ip,
            server_port,
            local_port,
            json_size,
        ))
    } else {
        Err(format!("HTTP request failed with status: {}", response.status()).into())
    }
}

fn add_cookie(dns_edns: &mut DnsEdns) -> Result<(), Box<dyn std::error::Error>> {
    let cookie: [u8; 8] = rand::random();
    dns_edns.add_option(EDNSOptionCodes::Cookie, Some(&cookie))
}

fn add_nsid(dns_edns: &mut DnsEdns) -> Result<(), Box<dyn std::error::Error>> {
    dns_edns.add_option(EDNSOptionCodes::NSID, None)
}

fn add_padding(dns_edns: &mut DnsEdns, size:usize) -> Result<(), Box<dyn std::error::Error>> {
    let padding: Vec<u8> = vec![0u8; size];
    dns_edns.add_option(EDNSOptionCodes::Padding, Some(&padding))
}

fn add_client_subnet(dns_edns: &mut DnsEdns, subnet: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse subnet string (format: "IP/prefix")
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid subnet format. Expected IP/prefix (e.g., 192.0.2.1/24 or 2001:db8::1/56)".into());
    }

    let ip_str = parts[0];
    let prefix_len: u8 = parts[1].parse()
        .map_err(|_| "Invalid prefix length")?;

    // Parse IP address
    let ip_addr: IpAddr = ip_str.parse()
        .map_err(|_| format!("Invalid IP address: {}", ip_str))?;

    // RFC 7871 ECS option data format:
    // +0 (MSB)                            +1 (LSB)
    // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    // |                          OPTION-CODE                          |
    // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    // |                         OPTION-LENGTH                         |
    // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    // |                            FAMILY                             |
    // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    // |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
    // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    // |                           ADDRESS...                          /
    // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

    let mut ecs_data = Vec::new();

    match ip_addr {
        IpAddr::V4(ipv4) => {
            // Validate prefix length for IPv4 (0-32)
            if prefix_len > 32 {
                return Err(format!("Invalid IPv4 prefix length: {} (must be 0-32)", prefix_len).into());
            }

            // Family: 1 for IPv4
            ecs_data.extend_from_slice(&1u16.to_be_bytes());

            // Source prefix-length
            ecs_data.push(prefix_len);

            // Scope prefix-length (always 0 in queries)
            ecs_data.push(0);

            // Address bytes (only significant bytes based on prefix length)
            let addr_bytes = ipv4.octets();
            let significant_bytes = ((prefix_len + 7) / 8) as usize;
            ecs_data.extend_from_slice(&addr_bytes[..significant_bytes]);
        }
        IpAddr::V6(ipv6) => {
            // Validate prefix length for IPv6 (0-128)
            if prefix_len > 128 {
                return Err(format!("Invalid IPv6 prefix length: {} (must be 0-128)", prefix_len).into());
            }

            // Family: 2 for IPv6
            ecs_data.extend_from_slice(&2u16.to_be_bytes());

            // Source prefix-length
            ecs_data.push(prefix_len);

            // Scope prefix-length (always 0 in queries)
            ecs_data.push(0);

            // Address bytes (only significant bytes based on prefix length)
            let addr_bytes = ipv6.octets();
            let significant_bytes = ((prefix_len + 7) / 8) as usize;
            ecs_data.extend_from_slice(&addr_bytes[..significant_bytes]);
        }
    }

    dns_edns.add_option(EDNSOptionCodes::EdnsClientSubnet, Some(&ecs_data))
}
fn main() -> Result<(), AppError> {
    // Install default crypto provider for rustls/quinn
    let _ = CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());

    let mut dig_config = load_effective_config();
    populate_queries(&mut dig_config)?;

    let (asn_database, public_suffix_list) = load_optional_enrichment_data(&dig_config);
    debug!("Config: {dig_config:?}");

    for query in &dig_config.queries {
        debug!("!Query: \"{}\"", query.query);
        if is_valid_dns_name(&query.query) {
            process_query(
                &dig_config,
                query,
                asn_database.as_ref(),
                public_suffix_list.as_ref(),
            )?;
        } else {
            error!("!Invalid DNS name: {}", query.query);
        }
    }

    Ok(())
}

fn load_effective_config() -> DigConfig {
    let mut dig_config = DigConfig::parse();
    let filter_reload_handle = init_tracing(dig_config.debug);

    debug!("query: {:?}", &dig_config.query_args);

    if let Some(file_config) = read_config_from_file(dig_config.config_file.as_ref())
        .unwrap_or_else(|e| {
            error!(
                "Failed to read config file: {} {e}",
                &dig_config.config_file.clone().unwrap_or_default()
            );
            exit(1);
        })
    {
        let query_args = dig_config.query_args.clone();

        dig_config = file_config;
        dig_config.query_args = query_args;

        debug!("query after config load: {:?}", &dig_config.query_args);

        if dig_config.debug {
            let _ = filter_reload_handle.reload(filter::LevelFilter::DEBUG);
        }
    }

    dig_config
}

fn populate_queries(dig_config: &mut DigConfig) -> Result<(), AppError> {
    dig_config.queries = if let Some(input_file) = &dig_config.input_file {
        read_queries_from_file(input_file)?
    } else {
        debug!("No input file specified, using command line arguments");
        parse_queries_from_args(&dig_config.query_args)
    };

    Ok(())
}

fn process_query(
    dig_config: &DigConfig,
    query: &DnsQuery,
    asn_database: Option<&asn_db2::Database>,
    public_suffix_list: Option<&publicsuffix::List>,
) -> Result<(), AppError> {
    if dig_config.nsec_recon {
        return nsec_recon(dig_config.transmission_type, query, dig_config);
    }

    if dig_config.zone_transfer {
        return zone_transfer(dig_config.transmission_type, query, dig_config);
    }

    let (mut packet_info, size, duration, timestamp) = execute_standard_query(dig_config, query)?;

    validate_response_question(query, &packet_info);

    debug!("Response identifier: {}", packet_info.header.id);

    if let Some(asn_db) = asn_database {
        packet_info.update_asn(asn_db);
    }

    if let Some(public_suffix_list) = public_suffix_list {
        packet_info.update_public_suffix(public_suffix_list);
    }

    print_query_result(dig_config, &packet_info, size, duration, timestamp);

    Ok(())
}

fn execute_standard_query(
    dig_config: &DigConfig,
    query: &DnsQuery,
) -> Result<(PacketInfo, usize, Duration, DateTime<chrono::Local>), AppError> {
    let transmission_type = select_transmission_type(dig_config, query);
    let start = std::time::Instant::now();
    let timestamp = chrono::Local::now();

    let (mut packet_info, mut size) = match send_dns_query(transmission_type, query, dig_config) {
        Ok(response) => response,
        Err(e) => {
            debug!("Failed to send query: {e}");
            return Err("DNS query failed".into())
        },
    };

    debug!("error: {:?}", packet_info.header.tc);

    let truncated_udp_response = packet_info.header.tc == 1
        && transmission_type == UDP
        && packet_info.header.rcode == NOERROR;

    if truncated_udp_response {
        (packet_info, size) = send_dns_query(TCP, query, dig_config)?;
    }

    debug!("Query: {query:?}");

    let duration = start.elapsed();
    debug!("Query time: {} usec", duration.as_micros());

    Ok((packet_info, size, duration, timestamp))
}

fn select_transmission_type(dig_config: &DigConfig, query: &DnsQuery) -> DnsProtocol {
    let requires_tcp = matches!(query.dns_rr_type, AXFR | IXFR | ANY);

    if requires_tcp && dig_config.transmission_type == UDP {
        TCP
    } else {
        dig_config.transmission_type
    }
}

fn validate_response_question(query: &DnsQuery, packet_info: &PacketInfo) {
    let requested_name = query.query.trim_end_matches('.');
    let response_name = packet_info.question.name.trim_end_matches('.');

    if response_name != requested_name
        || packet_info.question.dns_rr_type != query.dns_rr_type
        || packet_info.question.dns_class_type != query.dns_class
    {
        error!(
            "Requested domain mismatch: expected {} {} {} , got {} {} {}",
            query.query,
            query.dns_rr_type,
            query.dns_class,
            packet_info.question.name,
            packet_info.question.dns_rr_type,
            packet_info.question.dns_class_type,
        );
    }
}

fn print_query_result(
    dig_config: &DigConfig,
    packet_info: &PacketInfo,
    size: usize,
    duration: Duration,
    timestamp: DateTime<chrono::Local>,
) {
    if dig_config.print_json {
        print_packet_info_json(packet_info);
    } else {
        debug_print_packet_info(packet_info);
        print_packet_short_info(packet_info, dig_config);

        if !dig_config.short {
            println!(
                ";; Size: {size}, Query time: {} usec, time: {} server: {}:{} ({})",
                duration.as_micros(),
                timestamp.format("%Y-%m-%d %H:%M:%S %:z"),
                packet_info.d_addr,
                packet_info.dp,
                packet_info.protocol
            );
        }
    }
}

fn zone_transfer(
    dns_protocol: DnsProtocol,
    dns_query: &DnsQuery,
    dig_config: &DigConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Zone transfer {dns_query:?}");
    let mut ns_query = dns_query.clone();
    ns_query.dns_rr_type = DnsRRType::NS;
    if let Ok((ns_packet_info, _)) = send_dns_query(dns_protocol, &ns_query, dig_config) {
        let axfr_protocol = if dns_protocol == UDP {
            TCP
        } else {
            dns_protocol
        };

        for record in ns_packet_info.dns_records {
            if record.rr_type == DnsRRType::NS {
                let name_server = record.rdata;
                debug!("Using name server: {name_server}");
                let mut axfr_query = dns_query.clone();
                axfr_query.dns_rr_type = AXFR;
                axfr_query.server = name_server;
                axfr_query.dir = Forward;

                if let Ok((axfr_packet_info, _)) =
                    send_dns_query(axfr_protocol, &axfr_query, dig_config)
                {
                    if axfr_packet_info.dns_records[0].error == NOERROR {
                        print_packet_short_info(&axfr_packet_info, &dig_config);
                    } else {
                        println!(
                            "Zone transfer failed: {}",
                            axfr_packet_info.dns_records[0].error
                        );
                    }
                } else {
                    debug!("Failed to send axfr query");
                }
            }
        }
    }
    Ok(())
}

fn nsec_recon(
    dns_protocol: DnsProtocol,
    query_in: &DnsQuery,
    dig_config: &DigConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut query = query_in.clone();
    debug!("nsec recon: {query:?}");
    query.dns_rr_type = DnsRRType::NSEC;
    loop {
        if let Ok((packet_info, _size)) = send_dns_query(dns_protocol, &query, dig_config) {
            let r = &packet_info.dns_records[0];
            let answer = r.rdata.split_whitespace().nth(0).unwrap_or("").to_string();
            if answer == "" {
                break;
            }
            query.query = answer.clone();
            println!("dns entry found: {}", r.rdata.trim());
            // break;
        } else {
            break;
        }
    }
    Ok(())
}

fn print_packet_info_json(packet_info: &PacketInfo) {
    let data = json!(packet_info);
    let pretty_json = serde_json::to_string_pretty(&data).unwrap_or_else(|e| {
        error!("Invalid json: {e}: {data}");
        String::new()
    });
    println!("{pretty_json}");
}

fn push_current_query(
    queries: &mut Vec<DnsQuery>,
    current_name: Option<&(String, DnsDir)>,
    current_rr_type: DnsRRType,
    current_class: DnsClass,
    current_server: &str,
) {
    if let Some((name, dir)) = current_name {
        queries.push(DnsQuery::new(
            name,
            *dir,
            if *dir == DnsDir::Reverse {
                PTR
            } else {
                current_rr_type
            },
            current_class,
            current_server,
        ));
    }
}

#[inline]
fn get_parsed_ip_address(arg: &str) -> (String, DnsDir) {
    let ip_address = arg.parse::<IpAddr>();

    match ip_address {
        Ok(ip) => match parse_ip_address(ip) {
            Ok(reversed_name) => (reversed_name, DnsDir::Reverse),
            Err(err) => {
                DigConfig::command()
                    .error(ErrorKind::ValueValidation, err)
                    .exit();
            }
        },
        Err(_) => {
            DigConfig::command()
                .error(ErrorKind::ValueValidation, "Invalid IP address")
                .exit();
        }
    }
}

fn parse_queries_from_args(args: &[String]) -> Vec<DnsQuery> {
    let mut queries = Vec::new();
    let mut current_name: Option<(String, DnsDir)> = None;
    let mut current_rr_type = HashSet::new();
    let mut current_class = DnsClass::default();
    let mut current_server = String::new();
    let mut reverse_lookup = false;

    for arg in args {
        debug!("Parsing argument: {arg}");
        if arg.starts_with('@') {
            match parse_dns_server(arg) {
                Ok(server) => current_server = server,
                Err(err) => DigConfig::command()
                    .error(ErrorKind::ValueValidation, err)
                    .exit(),
            }
            continue;
        }

        if arg.starts_with("-x") {
            reverse_lookup = true;
            continue;
        }

        if arg.starts_with("-") {
            error!("Unknown argument: {arg}");
            exit(1);
        }
        if let Ok(rr_type) = parse_dns_rr_type(arg) {
            debug!("DNS RR type: {rr_type:?}");
            current_rr_type.insert(rr_type);
            continue;
        } else if arg.contains(',') && !arg.starts_with(',') && !arg.ends_with(',') {
            let parts = arg.split(',');
            for part in parts {
                if let Ok(rr_type) = parse_dns_rr_type(part) {
                    current_rr_type.insert(rr_type);
                } else if part.eq_ignore_ascii_case("all") {
                    current_rr_type.extend(DnsRRType::collect_dns_rr_types());
                    break;
                } else {
                    DigConfig::command()
                        .error(
                            ErrorKind::ValueValidation,
                            format!("Invalid DNS RR type: {part}"),
                        )
                        .exit();
                }
            }
            continue;
        } else if arg.eq_ignore_ascii_case("all") {
            current_rr_type.extend(DnsRRType::collect_dns_rr_types());
            continue;
        } else {
            debug!("DNS RR type not found: {arg}");
        }
        if let Ok(class) = parse_dns_class(arg) {
            current_class = class;
            continue;
        } else {
            debug!("DNS class not found: {arg}");
        }

        let parsed_name = if reverse_lookup {
            get_parsed_ip_address(arg)
        } else {
            match arg.parse::<IpAddr>() {
                Ok(_) => get_parsed_ip_address(arg),
                Err(_) => parse_dns_name(arg) ,
            }
        };
        if current_rr_type.is_empty() {
            current_rr_type.insert(DnsRRType::A);
        }

        for dns_rr_type in &current_rr_type {
            debug!("Parsed name: {parsed_name:?} {dns_rr_type:?} {current_class:?}");
            push_current_query(
                &mut queries,
                current_name.as_ref(),
                *dns_rr_type,
                current_class,
                &current_server,
            );
        }

        current_name = Some(parsed_name);
        reverse_lookup = false;
    }
    if current_rr_type.is_empty() {
        current_rr_type.insert(DnsRRType::A);
    }
    for dns_rr_type in &current_rr_type {
        debug!("Parsed name: {current_name:?} {dns_rr_type:?} {current_class:?}");
        push_current_query(
            &mut queries,
            current_name.as_ref(),
            *dns_rr_type,
            current_class,
            &current_server,
        );
    }
    queries
}

fn init_tracing(debug: bool) -> reload::Handle<filter::LevelFilter, tracing_subscriber::Registry> {
    let layers = vec![fmt::Layer::default().boxed()];
    let filter = if debug {
        filter::LevelFilter::DEBUG
    } else {
        filter::LevelFilter::INFO
    };

    let (filter, filter_reload_handle) = reload::Layer::new(filter);
    let (tracing_layers, _layers_reload_handle) = reload::Layer::new(layers);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_layers)
        .init();

    filter_reload_handle
}

fn load_optional_enrichment_data(
    dig_config: &DigConfig,
) -> (Option<asn_db2::Database>, Option<publicsuffix::List>) {
    let asn_database: Option<asn_db2::Database> = if dig_config.lookup_asn {
        if let Some(asn_database_file) = &dig_config.asn_database_file {
            Some(load_asn_database(asn_database_file))
        } else {
            Some(load_asn_database(DEFAULT_ASN_DATABASE_FILE))
        }
    } else {
        None
    };

    let public_suffix_list: Option<publicsuffix::List> = if dig_config.lookup_domain {
        if let Some(ps_file) = &dig_config.public_suffix_file {
            Some(read_public_suffix_file(ps_file))
        } else {
            Some(read_public_suffix_file(DEFAULT_PUBLIC_SUFFIX_FILE))
        }
    } else {
        None
    };
    (asn_database, public_suffix_list)
}

fn build_dns_query_packet(
    name: &str,
    rr_type: DnsRRType,
    dns_class: DnsClass,
    dig_config: &DigConfig,
) -> Result<(Vec<u8>, u16), AppError> {
    let mut outbuf = vec![0u8; DnsAnswer::HEADER_LEN];
    let mut dns_header = DnsHeader::new();
    let id: u16 = rand::random();
    dns_header.init(
        id,
        0x0,
        DnsOpcodes::Query,
        0,
        0,
        1,
        0,
        0,
        1,
        0,
        NOERROR,
        1,
        0,
        0,
        1,
    );

    let mut dns_edns = DnsEdns::new(1232);
    if dig_config.dnssec_validate {
        dns_edns.set_dnssec_ok();
    }

    let dns_query = DnsQuestion {
        dns_rr_type: rr_type,
        dns_class_type: dns_class,
        name: name.to_string(),
    };

    let mut dns_answer = DnsAnswer::new();
    let mut names = NamesList::new();

    dns_answer.add_header(&dns_header)?;
    dns_answer.add_question(&dns_query)?;

    let _question_size =
        write_question(&mut outbuf, DnsAnswer::HEADER_LEN, &dns_query, &mut names)?;
    let _header_size = write_header(&mut outbuf, 0, &mut dns_header);

    if dig_config.cookie {
        add_cookie(&mut dns_edns)?;
    }
    if dig_config.nsid {
        add_nsid(&mut dns_edns)?;
    }

    if dig_config.padding > 0 {
        add_padding(&mut dns_edns, dig_config.padding)?;
    }
    
    if let Some(ref subnet) = dig_config.client_subnet {
        add_client_subnet(&mut dns_edns, &subnet)?;
    }
    
    append_opt_header(&mut outbuf, &dns_edns)?;

    Ok((outbuf, dns_header.id))
}

fn get_default_port(dig_config: &DigConfig) -> u16 {
    match dig_config.transmission_type {
        TCP | UDP => DNS_PORT,
        HTTP_POST | HTTP_GET => HTTP_PORT,
        HTTPS_POST | HTTPS_GET | HTTPS_JSON => HTTPS_PORT,
        QUIC => DOQ_PORT,
        TLS => DOT_PORT,
        _ => {
            error!(
                "Unsupported transmission type: {:?}",
                dig_config.transmission_type
            );
            exit(1);
        }
    }
}

fn strip_protocol_prefix(server: &str) -> &str {
    if let Some(idx) = server.find("://") {
        &server[idx + 3..]
    } else {
        server
    }
}

fn resolve_dns_server_addr(query: &DnsQuery, dig_config: &DigConfig, need_ip: bool) -> String {
    let server_ip = if query.server.is_empty() {
        read_default_nameserver(dig_config).unwrap_or_else(|_| DEFAULT_DNS_SERVER.to_string())
    } else {
        let server_without_prefix = strip_protocol_prefix(&query.server);
        match server_without_prefix.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => {
                if need_ip {
                    match dns_lookup::lookup_host(server_without_prefix) {
                        Ok(ips) => ips
                            .into_iter()
                            .next()
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| {
                                error!("DNS lookup failed for {server_without_prefix}");
                                exit(1);
                            }),
                        Err(e) => {
                            error!("DNS lookup failed for {server_without_prefix}: {e}",);
                            exit(1);
                        }
                    }
                } else {
                    server_without_prefix.to_string()
                }
            }
        }
    };
    debug!("Resolved server IP: {server_ip}");
    debug!("port = {}", dig_config.dns_port);
    let port = if dig_config.dns_port == 0 {
        get_default_port(dig_config)
    } else {
        dig_config.dns_port
    };
    debug!("port = {port}");

    if server_ip.contains(':') {
        format!("[{server_ip}]:{port}")
    } else {
        format!("{server_ip}:{port}")
    }
}

fn parse_response(response: &[u8], packet_info: &mut PacketInfo) -> Result<(), AppError> {
    let mut stats = Statistics::new(DEFAULT_STATS_TOPLIST_SIZE);
    let mut parser_config = config::Config::new();

    parser_config.rr_type = DnsRRType::collect_dns_rr_types();

    parse_dns(response, packet_info, &mut stats, &parser_config).map_err(|error| {
        error!("Error parsing DNS packet: {error:?}");
        error
    })
}

fn get_puny_name(name: &str, no_puny: bool) -> String {
    if no_puny {
        name.to_string()
    } else {
        idna::domain_to_unicode(name).0
    }
}

fn print_packet_short_info(packet_info: &PacketInfo, dig_config: &DigConfig) {
    if !dig_config.short {
        println!("; {PROGNAME} {VERSION}");
        println!(
            ";; Header Opcode: {} Status: {} Id:{} ",
            packet_info.header.opcode, packet_info.header.rcode, packet_info.header.id
        );

        println!(
            ";; Flags: {} Query: {} ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
            packet_info.header.flags_as_str(),
            packet_info.header.qdcount,
            packet_info.header.ancount,
            packet_info.header.nscount,
            packet_info.header.arcount
        );
    }
    if dig_config.print_query || !dig_config.short {
        println!(
            ";; Question:\n;{} {} {}\n",
            get_puny_name(&packet_info.question.name, dig_config.nopuny),
            packet_info.question.dns_rr_type,
            packet_info.question.dns_class_type
        );
    }

    if !dig_config.short {
        if let Some(edns_version) = packet_info.edns_version &&
            let Some(edns_size) = packet_info.edns_size &&
            let Some(edns_flags) = packet_info.edns_flags {
            let do_str = if edns_flags & 0x8000 != 0 { "DO" } else { "" };
            println!(";; OPT pseudo-header: \n; EDNS version: {edns_version} flags: {do_str} udp: {edns_size}");

            for record in &packet_info.edns_records {
                debug!("EDNS record: {record:?}");
                println!(";{} ", record.option_data);
            }
            println!();

        }
    }
    if !dig_config.short {
        println!(";; Answer:");
    }

    for record in &packet_info.dns_records {
        if record.source_field == Answer {
            println!(
                "{}\t {}\t {}\t {}\t {}",
                get_puny_name(&record.name, dig_config.nopuny),
                record.ttl,
                record.class,
                record.rr_type,
                record.rdata
            );
        }
    }
    if dig_config.print_additional && packet_info.header.arcount > 0 {
        println!(";; Additional:");
        for record in &packet_info.dns_records {
            if record.source_field == Additional {
                println!(
                    "{} {} {} {} {}",
                    record.name, record.ttl, record.class, record.rr_type, record.rdata
                );
            }
        }
    }
    if dig_config.print_authority && packet_info.header.nscount > 0 {
        println!(";; Authority:");
        for record in &packet_info.dns_records {
            if record.source_field == Authority {
                println!(
                    "{} {} {} {} {}",
                    record.name, record.ttl, record.class, record.rr_type, record.rdata
                );
            }
        }
    }
}

fn debug_print_packet_info(packet_info: &PacketInfo) {
    debug!("{packet_info:#?}");

    for record in &packet_info.dns_records {
        debug!("{record:#?}");
    }
}

fn append_opt_header(
    buf: &mut Vec<u8>,
    edns: &DnsEdns,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut size = 0;
    buf.push(0u8);
    size += 1;
    buf.extend_from_slice(&DnsRRType::OPT.to_u16().to_be_bytes());
    size += 2;
    buf.extend_from_slice(&edns.udp_payload_size.to_be_bytes());
    size += 2;
    buf.push(edns.extended_rcode);
    size += 1;
    buf.push(edns.version);
    size += 1;
    buf.extend_from_slice(&edns.z.to_be_bytes());
    size += 2;
    buf.extend_from_slice(&edns.data_len.to_be_bytes());
    size += 2;
    for option in &edns.options {
        buf.extend_from_slice(&option.code.to_u16().to_be_bytes());
        size += 2;
        buf.extend_from_slice(&option.length.to_be_bytes());
        size += 2;
        buf.extend_from_slice(&option.data);
        size += option.data.len();
    }
    Ok(size)
}
