use crate::config::Config;
use crate::dns::{dnssec_algorithm, dnssec_digest};
use crate::errors::Parse_error;
use crate::errors::ParseErrorType;
use crate::dns_class::DNS_Class;
use crate::dns_helper::{
    self, dns_parse_slice, dns_read_u128, dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8,
    parse_class, parse_rrtype,
};
use crate::dns_name::dns_parse_name;
use crate::dns_opcodes::DNS_Opcodes;
use crate::dns_record::DNS_record;
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr::dns_parse_rdata;
use crate::dns_rr_type::DNS_RR_type;
use crate::edns::{DNSExtendedError, EDNSOptionCodes};
use crate::packet_info::Packet_info;
use crate::skiplist::Skip_List;
use crate::statistics::Statistics;
use publicsuffix::Psl as _;
use tracing::{debug, error};

#[derive(Debug, Clone, Default)]
pub(crate) struct dns_question {
    pub dns_rr_type: DNS_RR_type,
    pub dns_class_type: DNS_Class,
    pub name: String,
}

impl dns_question {
    pub fn new() -> dns_question {
        dns_question {
            dns_rr_type: DNS_RR_type::A,
            dns_class_type: DNS_Class::IN,
            name: String::new(),
        }
    }
    pub fn parse(
        &mut self,
        packet: &[u8],
        offset_in: usize,
        skip_list: &Skip_List,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let (name, offset) = dns_parse_name(packet, offset_in)?;
        self.name = name;
        if skip_list.match_skip_list(&self.name) {
            return Err(Parse_error::new(ParseErrorType::Skipped_Message, &self.name).into());
        }
        let rrtype_val = dns_read_u16(packet, offset)?;
        let class_val = dns_read_u16(packet, offset + 2)?;
        self.dns_rr_type = parse_rrtype(rrtype_val)?;
        self.dns_class_type = parse_class(class_val)?;
        Ok(offset)
    }
}

fn parse_question(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    rcode: DnsReplyType,
    skip_list: &Skip_List,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut dns_question = dns_question::new();
    let offset = dns_question.parse(packet, offset_in, skip_list)?;
    let rrtype = dns_question.dns_rr_type;
    let class = dns_question.dns_class_type;
    *stats.qtypes.entry(rrtype).or_insert(0) += 1;
    *stats.qclass.entry(class).or_insert(0) += 1;
    stats.total_time_stats.add(packet_info.timestamp, 1);

    if rcode == DnsReplyType::NXDOMAIN {
        stats.topnx.add(&dns_question.name);
        stats.blocked_time_stats.add(packet_info.timestamp, 1);
    } else if rcode == DnsReplyType::NOERROR {
        stats.topdomain.add(&dns_question.name);
        stats.success_time_stats.add(packet_info.timestamp, 1);
    } else {
        debug!("Other rcode: {rcode:?}");
    }

    if rcode != DnsReplyType::NOERROR {
        let rec: DNS_record = DNS_record {
            rr_type: rrtype,
            ttl: 0,
            class,
            name: dns_question.name,
            rdata: String::new(),
            count: 1,
            timestamp: packet_info.timestamp,
            domain: String::new(),
            asn: 0,
            asn_owner: String::new(),
            prefix: String::new(),
            error: rcode,
            extended_error: DNSExtendedError::None,
        };
        packet_info.add_dns_record(rec);
    }
    let len = 4 + offset - offset_in;
    Ok(len)
}

fn parse_edns_extended_dns_error(
    packet_info: &mut Packet_info,
    rdata: &[u8],
    offset: usize,
    option_length: usize,
    stats: &mut Statistics,
) -> Result<(), Box<dyn std::error::Error>> {
    let info_code = DNSExtendedError::find(dns_read_u16(rdata, offset + 4)?)?;
    debug!("info code {info_code}");
    let info_text = std::str::from_utf8(dns_parse_slice(
        rdata,
        offset + 6..offset + 4 + option_length,
    )?)?;
    debug!("infotext {info_text}");
    if !packet_info.dns_records.is_empty() {
        packet_info.dns_records[0].extended_error = info_code;
    }
    *stats.extended_error.entry(info_code).or_insert(0) += 1;
    Ok(())
}

fn parse_edns_dau(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = offset + 4;
    for _ in 0..option_length {
        let alg = dns_read_u8(rdata, offset)?;
        debug!("DNS Signing Algorithm: {}", dnssec_algorithm(alg)?);
        offset += 1;
    }
    Ok(())
}

fn parse_edns_dhu(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = offset + 4;
    for _ in 0..option_length {
        let alg = dns_read_u8(rdata, offset)?;
        debug!("DNS Hash Algorithm: {}", dnssec_digest(alg)?);
        offset += 1;
    }
    Ok(())
}

fn parse_edns_n3u(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = offset + 4;
    for _ in 0..option_length {
        let alg = dns_read_u8(rdata, offset)?;
        debug!("NSEC3 Hash Algorithm: {}", dnssec_digest(alg)?);
        offset += 1;
    }
    Ok(())
}

fn parse_edns_llq(rdata: &[u8], offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    let llq_ver = dns_read_u16(rdata, offset + 4)?;
    let llq_opcode = dns_read_u16(rdata, offset + 6)?;
    let llq_error = dns_read_u16(rdata, offset + 8)?;
    let llq_id = dns_read_u64(rdata, offset + 10)?;
    let llq_lease = dns_read_u32(rdata, offset + 18)?;
    debug!( "LLQ Version: {llq_ver}, opcode: {llq_opcode}, error: {llq_error}, ID: {llq_id}, lease: {llq_lease}" );
    Ok(())
}

fn parse_edns_zone_version(rdata: &[u8], offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    let label_count = dns_read_u8(rdata, offset + 4)?;
    let version_type = dns_read_u8(rdata, offset + 5)?;
    let Some(version) = rdata.get(offset + 6..) else {
        return Err("No version data".into());
    };
    debug!("Zone version: {label_count} {version_type} {version:x?}");
    Ok(())
}

fn parse_edns_chain(rdata: &[u8], offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    let chain = dns_parse_name(rdata, offset + 4)?;
    debug!("Chain {}", chain.0);
    Ok(())
}

fn parse_edns_nsid(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let nsid = std::str::from_utf8(dns_parse_slice(
        rdata,
        offset + 4..offset + 4 + option_length,
    )?)?;
    debug!("infotext {nsid:?}");
    Ok(())
}

fn parse_edns_tcp_keepalive(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if option_length == 2 {
        let timeout = dns_read_u16(rdata, offset + 4)?;
        debug!("TCP Keepalive {timeout}");
    }
    Ok(())
}

fn parse_edns_client_subnet(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let family = dns_read_u16(rdata, offset + 4)?;
    let source_prefix_len = dns_read_u8(rdata, offset + 6)?;
    let scope_prefix_len = dns_read_u8(rdata, offset + 7)?;
    let addr = dns_parse_slice(rdata, offset + 8..offset + option_length + 4)?;

    if family == 1 {
        // ipv4
        let mut addr_: [u8; 4] = [0; 4];
        addr_[..addr.len()].copy_from_slice(addr);
        let v4addr = dns_helper::parse_ipv4(&addr_)?;
        debug!("{v4addr}/{source_prefix_len}/{scope_prefix_len} (IPv4)");
    } else if family == 2 {
        // ipv6
        let mut addr_: [u8; 16] = [0; 16];
        addr_[..addr.len()].copy_from_slice(addr);
        let v6addr = dns_helper::parse_ipv6(&addr_)?;
        debug!("{v6addr}/{source_prefix_len}/{scope_prefix_len} (IPv6)");
    } else {
        error!("Unknown address family {family}");
    }
    Ok(())
}

fn parse_edns_cookie(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if option_length == 24 {
        let client_cookie = dns_read_u64(rdata, offset + 4)?;
        let server_cookie = dns_read_u128(rdata, offset + 4 + 8)?;
        debug!("Server cookie {server_cookie:0x}, client_cookie {client_cookie:0x}");
    } else if option_length == 8 {
        let client_cookie = dns_read_u64(rdata, offset + 4)?;
        debug!("client_cookie {client_cookie:x}");
    }
    Ok(())
}

fn parse_edns_client_tag(rdata: &[u8], offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    let client_tag = dns_read_u16(rdata, offset + 4)?;
    debug!("Client Tag: {client_tag}");
    Ok(())
}

fn parse_edns_server_tag(rdata: &[u8], offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    let server_tag = dns_read_u16(rdata, offset + 4)?;
    debug!("Server Tag: {server_tag}");
    Ok(())
}

fn parse_edns_key_tag(
    packet: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = offset + 4;
    for _ in 0..option_length / 2 {
        let key_tag = dns_read_u16(packet, offset)?;
        debug!("Key tag: {key_tag}");
        offset += 2;
    }
    Ok(())
}

fn parse_edns_update_lease(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let lease = dns_read_u32(rdata, offset + 4)?;
    debug!("Lease: {lease}");
    if option_length == 8 {
        let key_lease = dns_read_u32(rdata, offset + 4)?;
        debug!("Key Lease: {key_lease}");
    }
    Ok(())
}

fn parse_edns_report_channel(
    rdata: &[u8],
    offset: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (name, _offset) = dns_parse_name(rdata, offset + 4)?;
    debug!("Report channel: {name}");
    Ok(())
}

fn parse_edns_padding(
    rdata: &[u8],
    offset: usize,
    option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!(
        "Padding {option_length} bytes: {:x?} ",
        hex::encode_upper(dns_parse_slice(rdata, offset + 4..)?)
    );
    Ok(())
}

fn parse_edns(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
) -> Result<usize, Box<dyn std::error::Error>> {
    //let payload_size = dns_read_u16(packet, offset_in)?;
    let e_rcode = u16::from(dns_read_u8(packet, offset_in + 2)?);
    if e_rcode != 0 {
        match packet_info.dns_records.first() {
            Some(x) => {
                let mut rec = x.clone();
                rec.error = DnsReplyType::find(rec.error as u16 | (e_rcode << 4))?;
                debug!("EDNS error code {}", rec.error);
                packet_info.dns_records[0] = rec;
            }
            _ => {}
        }
    }
    let data_length = usize::from(dns_read_u16(packet, offset_in + 6)?);
    if data_length == 0 {
        return Ok(8);
    }
    let rdata = dns_parse_slice(packet, offset_in + 8..offset_in + 8 + data_length)?;
    let mut offset = 0;
    while offset < data_length {
        let option_code = EDNSOptionCodes::find(dns_read_u16(rdata, offset)?)?;
        let option_length = usize::from(dns_read_u16(rdata, offset + 2)?);
        match option_code {
            EDNSOptionCodes::ExtendedDNSError => {
                parse_edns_extended_dns_error(packet_info, rdata, offset, option_length, stats)?;
            }
            EDNSOptionCodes::CHAIN => parse_edns_chain(rdata, offset)?,
            EDNSOptionCodes::NSID => parse_edns_nsid(rdata, offset, option_length)?,
            EDNSOptionCodes::EdnsTcpKeepalive => {
                parse_edns_tcp_keepalive(rdata, offset, option_length)?;
            }
            EDNSOptionCodes::EDNSEXPIRE => parse_edns_expire(rdata, offset, option_length)?,
            EDNSOptionCodes::EdnsClientSubnet => {
                parse_edns_client_subnet(rdata, offset, option_length)?;
            }
            EDNSOptionCodes::Padding => parse_edns_padding(rdata, offset, option_length)?,
            EDNSOptionCodes::COOKIE => parse_edns_cookie(rdata, offset, option_length)?,
            EDNSOptionCodes::DAU => parse_edns_dau(rdata, offset, option_length)?,
            EDNSOptionCodes::DHU => parse_edns_dhu(rdata, offset, option_length)?,
            EDNSOptionCodes::N3U => parse_edns_n3u(rdata, offset, option_length)?,
            EDNSOptionCodes::LLQ => parse_edns_llq(rdata, offset)?,
            EDNSOptionCodes::ZoneVersion => parse_edns_zone_version(rdata, offset)?,
            EDNSOptionCodes::EDNSClientTag => parse_edns_client_tag(rdata, offset)?,
            EDNSOptionCodes::EDNSServerTag => parse_edns_server_tag(rdata, offset)?,
            EDNSOptionCodes::EdnsKeyTag => parse_edns_key_tag(packet, offset, option_length)?,
            EDNSOptionCodes::UpdateLease => parse_edns_update_lease(rdata, offset, option_length)?,
            EDNSOptionCodes::ReportChannel => parse_edns_report_channel(rdata, offset)?,
            _ => {}
        }
        offset += option_length + 4; // need to add the option code and length fields too
    }
    Ok(8 + data_length)
}

fn parse_edns_expire(
    _packet: &[u8],
    _offset: usize,
    _option_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Expire set");
    Ok(())
}

fn parse_answer(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;
    if skip_list.match_skip_list(&name) {
        return Err(Parse_error::new(ParseErrorType::Skipped_Message, &name).into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let rrtype = parse_rrtype(rrtype_val)?;
    if rrtype == DNS_RR_type::OPT {
        offset += 2;
        let len = parse_edns(packet_info, packet, offset, stats)?;
        let len = offset + len - offset_in;
        return Ok(len);
    }
    let class_val = dns_read_u16(packet, offset + 2)?;
    let class = parse_class(class_val)?;
    *stats.atypes.entry(rrtype).or_insert(0) += 1;
    *stats.aclass.entry(class).or_insert(0) += 1;

    let ttl = dns_read_u32(packet, offset + 4)?;
    let data_len: usize = dns_read_u16(packet, offset + 8)?.into();

    if !config.rr_type.contains(&rrtype) {
        let len = (offset - offset_in) + 10 + data_len;
        return Ok(len);
    }

    offset += 10;
    let data = dns_parse_slice(packet, offset..offset + data_len)?;
    let rdata = dns_parse_rdata(data, rrtype, packet, offset)?;
    offset += 1;
    let rec: DNS_record = DNS_record {
        rr_type: rrtype,
        ttl,
        class,
        name,
        rdata,
        count: 1,
        timestamp: packet_info.timestamp,
        domain: String::new(), //domain_str,
        asn: 0,
        asn_owner: String::new(),
        prefix: String::new(),
        error: DnsReplyType::NOERROR,
        extended_error: DNSExtendedError::None,
    };
    packet_info.add_dns_record(rec);
    offset += data_len - 1;
    let len = offset - offset_in;
    Ok(len)
}

pub(crate) fn find_domain(publicsuffixlist: &publicsuffix::List, name: &str) -> String {
    let domain = publicsuffixlist.domain(name.as_bytes());
    if let Some(d) = domain {
        let x = d.as_bytes().to_vec();
        String::from_utf8(x).unwrap_or_default()
    } else {
        //debug!("Domain not found: {name}");
        String::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct dns_header {
    // Transaction ID
    pub id: u16,
    pub flags: u16,
    // Flags
    pub qr: u8,              // Query/Response flag
    pub opcode: DNS_Opcodes, // Operation code
    pub aa: u8,              // Authoritative Answer flag
    pub tc: u8,              // Truncation flag
    pub rd: u8,              // Recursion Desired flag
    pub ra: u8,              // Recursion Available flag
    pub z: u8,               // Reserved
    pub ad: u8,              // Authentic Data flag
    pub cd: u8,              // Checking Disabled flag
    pub rcode: DnsReplyType, // Response code
    // Counts
    pub qdcount: u16, // Number of questions
    pub ancount: u16, // Number of answers
    pub nscount: u16, // Number of authority records
    pub arcount: u16, // Number of additional records
}

impl dns_header {
    pub fn new() -> dns_header {
        dns_header {
            flags: 0,
            id: 0,
            qr: 0,
            opcode: DNS_Opcodes::Query,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            ad: 0,
            cd: 0,
            rcode: DnsReplyType::NOERROR,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn parse(&mut self, packet: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        self.id = dns_read_u16(packet, 0)?;
        let flags = dns_read_u16(packet, 2)?;
        self.flags = flags;
        self.qr = ((flags & 0x8000) >> 15) as u8;
        let opcode_val = (flags >> 11) & 0x000f;
        self.opcode = DNS_Opcodes::find(opcode_val)?;
        self.aa = ((flags >> 10) & 0x0001) as u8;
        self.tc = ((flags >> 9) & 0x0001) as u8;
        self.rd = ((flags >> 8) & 0x0001) as u8;
        self.ra = ((flags >> 7) & 0x0001) as u8;
        self.z = ((flags >> 6) & 0x0001) as u8;
        self.ad = ((flags >> 5) & 0x0001) as u8;
        self.cd = ((flags >> 4) & 0x0001) as u8;
        let rcode = flags & 0x000f;
        self.rcode = DnsReplyType::find(rcode)?;
        self.qdcount = dns_read_u16(packet, 4)?;
        self.ancount = dns_read_u16(packet, 6)?;
        self.nscount = dns_read_u16(packet, 8)?;
        self.arcount = dns_read_u16(packet, 10)?;
        Ok(12)
    }
}

pub(crate) fn parse_dns(
    packet_in: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut dns_header = dns_header::new();
    let packet = packet_in;
    let mut offset = dns_header.parse(packet)?;

    *stats.opcodes.entry(dns_header.opcode).or_insert(0) += 1;
    if dns_header.opcode != DNS_Opcodes::Query {
        // Query
        debug!("Skipping DNS packets that are not queries");
        return Ok(());
    }

    if dns_header.tc != 0 {
        debug!("Skipping truncated DNS packets");
        stats.truncated += 1;
        return Ok(());
    }

    if dns_header.qdcount == 0 {
        debug!("Empty questions section... ");
  //      return Err(Parse_error::new(ParseErrorType::Skipped_Message, "").into());
    }

    stats.additional += u128::from(dns_header.ancount);
    stats.authority += u128::from(dns_header.nscount);
    stats.answers += u128::from(dns_header.arcount);
    stats.queries += u128::from(dns_header.qdcount);

    if dns_header.qr != 1 {
        // we ignore questions; except for stats
        stats.sources.add(&packet_info.s_addr);
        stats.destinations.add(&packet_info.d_addr);
        return Ok(());
    }

    *stats.errors.entry(dns_header.rcode).or_insert(0) += 1;

    for _ in 0..dns_header.qdcount {
        offset += parse_question(
            packet_info,
            packet,
            offset,
            stats,
            dns_header.rcode,
            skip_list,
        )?;
    }
    for _ in 0..dns_header.ancount {
        offset += parse_answer(packet_info, packet, offset, stats, config, skip_list)?;
    }
    if config.authority {
        for _ in 0..dns_header.nscount {
            offset += parse_answer(packet_info, packet, offset, stats, config, skip_list)?;
        }
    }
    if config.additional {
        for _i in 0..dns_header.arcount {
            offset += parse_answer(packet_info, packet, offset, stats, config, skip_list)?;
        }
    }
    Ok(())
}
