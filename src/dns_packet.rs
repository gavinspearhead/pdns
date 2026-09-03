use crate::config::Config;
use crate::dns_class::DnsClass;
use crate::dns_edns::parse_edns;
use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u32};
use crate::dns_name::dns_parse_name;
use crate::dns_opcodes::DnsOpcodes;
use crate::dns_record::DnsField::{Additional, Answer, Authority, Question};
use crate::dns_record::{DnsField, DnsRecord};
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr::dns_parse_rdata;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use crate::errors::ParseErrorType;
use crate::packet_info::PacketInfo;
use crate::statistics::Statistics;
use publicsuffix::Psl as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize, Hash)]
pub struct DnsQuestion {
    pub dns_rr_type: DnsRRType,
    pub dns_class_type: DnsClass,
    pub name: String,
}

#[must_use]
pub fn match_skip_list(list: &[Regex], name: &str) -> bool {
    if list.is_empty() {
        return false;
    }
    let clean_name = name.strip_suffix('.').unwrap_or(name);
    list.iter().any(|r| r.is_match(clean_name))
}

impl DnsQuestion {
    #[must_use]
    pub fn new() -> DnsQuestion {
        DnsQuestion::default()
    }
    pub fn parse(
        &mut self,
        packet: &[u8],
        offset_in: usize,
        config: &Config,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let (name, offset) = dns_parse_name(packet, offset_in)?;
        if match_skip_list(&config.skip_domains, &name) {
            return Err(ParseError::new(ParseErrorType::SkippedMessage, &name).into());
        }
        let rrtype_val = dns_read_u16(packet, offset)?;
        let class_val = dns_read_u16(packet, offset + 2)?;
        name.clone_into(&mut self.name);
        self.dns_rr_type = DnsRRType::find(rrtype_val)?;
        self.dns_class_type = DnsClass::find(class_val)?;
        Ok(offset + 4)
    }
}

fn parse_question(
    packet_info: &mut PacketInfo,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    rcode: DnsReplyType,
    config: &Config,
) -> Result<usize, Box<dyn std::error::Error>> {
    packet_info.question = DnsQuestion::new();
    let offset = packet_info.question.parse(packet, offset_in, config)?;
    let rr_type = packet_info.question.dns_rr_type;
    let class = packet_info.question.dns_class_type;
    *stats.qtypes.entry(rr_type).or_insert(0) += 1;
    *stats.qclass.entry(class).or_insert(0) += 1;
    stats.total_time_stats.add(packet_info.timestamp, 1);

    if rcode == DnsReplyType::NXDOMAIN {
        stats.topnx.add(&packet_info.question.name.to_lowercase());
        stats.blocked_time_stats.add(packet_info.timestamp, 1);
    } else if rcode == DnsReplyType::NOERROR {
        stats.topdomain.add(&packet_info.question.name.to_lowercase());
        stats.success_time_stats.add(packet_info.timestamp, 1);
    } else {
        debug!("Other rcode: {rcode:?}");
    }

    if rcode != DnsReplyType::NOERROR {
        let rec = DnsRecord::new(
            rr_type,
            class,
            rcode,
            1,
            packet_info.timestamp,
            &packet_info.question.name,
            0,
            "",
            Question,
        );
        packet_info.add_dns_record(rec);
    }
    let len = offset - offset_in;
    Ok(len)
}

fn parse_answer(
    packet_info: &mut PacketInfo,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    config: &Config,
    source_field: DnsField,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;
    if match_skip_list(&config.skip_domains, &name) {
        return Err(ParseError::new(ParseErrorType::SkippedMessage, &name).into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let rrtype = DnsRRType::find(rrtype_val)?;
    if rrtype == DnsRRType::OPT {
        offset += 2;
        let len = parse_edns(packet_info, packet, offset, stats)?;
        let len = offset + len - offset_in;
        return Ok(len);
    }
    let class_val = dns_read_u16(packet, offset + 2)?;
    let class = DnsClass::find(class_val)?;
    *stats.atypes.entry(rrtype).or_insert(0) += 1;
    *stats.aclass.entry(class).or_insert(0) += 1;

    let ttl = dns_read_u32(packet, offset + 4)?;
    let data_len: usize = dns_read_u16(packet, offset + 8)? as usize;

    if !config.rr_type.contains(&rrtype) {
        let len = (offset - offset_in) + 10 + data_len;
        return Ok(len);
    }

    offset += 10;
    let data = dns_parse_slice(packet, offset..offset + data_len)?;
    let rdata = dns_parse_rdata(data, rrtype, packet, offset, stats)?;
    let rec = DnsRecord::new(
        rrtype,
        class,
        DnsReplyType::NOERROR,
        1,
        packet_info.timestamp,
        &name,
        ttl,
        &rdata,
        source_field,
    );

    packet_info.add_dns_record(rec);
    offset += data_len;
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

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize, Hash,
)]
pub struct DnsHeader {
    // Transaction ID
    pub id: u16,
    pub flags: u16,
    // Flags
    pub qr: u8,              // Query/Response flag
    pub opcode: DnsOpcodes,  // Operation code
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

impl DnsHeader {
    #[inline]
    #[must_use]
    pub fn new() -> DnsHeader {
        DnsHeader::default()
    }
    pub fn init(
        &mut self,
        id: u16,
        qr: u8,
        opcode: DnsOpcodes,
        aa: u8,
        tc: u8,
        rd: u8,
        ra: u8,
        z: u8,
        ad: u8,
        cd: u8,
        rcode: DnsReplyType,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) {
        self.id = id;
        self.qr = qr;
        self.opcode = opcode;
        self.aa = aa;
        self.tc = tc;
        self.rd = rd;
        self.ra = ra;
        self.z = z;
        self.ad = ad;
        self.cd = cd;
        self.rcode = rcode;
        self.qdcount = qdcount;
        self.ancount = ancount;
        self.nscount = nscount;
        self.arcount = arcount;

        // Reconstruct flags from individual fields
        self.flags = ((u16::from(qr) & 0x1) << 15)
            | ((opcode.to_u16() & 0xF) << 11)
            | ((u16::from(aa) & 0x1) << 10)
            | ((u16::from(tc) & 0x1) << 9)
            | ((u16::from(rd) & 0x1) << 8)
            | ((u16::from(ra) & 0x1) << 7)
            | ((u16::from(z) & 0x1) << 6)
            | ((u16::from(ad) & 0x1) << 5)
            | ((u16::from(cd) & 0x1) << 4)
            | (rcode.to_u16() & 0xF);
    }

    #[must_use]
    pub fn flags_as_str(&self) -> String {
        let mut flags = String::new();
        if self.qr != 0 {
            flags.push_str("qr ");
        }
        if self.aa != 0 {
            flags.push_str("aa ");
        }
        if self.tc != 0 {
            flags.push_str("tc ");
        }
        if self.rd != 0 {
            flags.push_str("rd ");
        }
        if self.ra != 0 {
            flags.push_str("ra ");
        }
        if self.ad != 0 {
            flags.push_str("ad ");
        }
        if self.cd != 0 {
            flags.push_str("cd ");
        }
        flags
    }

    pub fn parse(&mut self, packet: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        self.id = dns_read_u16(packet, 0)?;
        let flags = dns_read_u16(packet, 2)?;
        self.flags = flags;
        self.qr = ((flags & 0x8000) >> 15) as u8;
        let opcode_val = (flags >> 11) & 0x000f;
        self.opcode = DnsOpcodes::find(opcode_val)?;
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
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    packet_info.header = DnsHeader::new();
    //let dns_header = &mut packet_info.header;
    let packet = packet_in;
    let mut offset = packet_info.header.parse(packet)?;

    *stats.opcodes.entry(packet_info.header.opcode).or_insert(0) += 1;
    if packet_info.header.opcode != DnsOpcodes::Query {
        // Query
        debug!("Skipping DNS packets that are not queries");
        return Ok(());
    }

    if packet_info.header.tc != 0 {
        debug!("Skipping truncated DNS packets");
        stats.truncated += 1;
        return Ok(());
    }

    if packet_info.header.qdcount == 0 {
        debug!("Empty questions section... ");
        //      return Err(Parse_error::new(ParseErrorType::SkippedMessage, "").into());
    }

    stats.additional += u128::from(packet_info.header.arcount);
    stats.authority += u128::from(packet_info.header.nscount);
    stats.answers += u128::from(packet_info.header.ancount);
    stats.queries += u128::from(packet_info.header.qdcount);

    if packet_info.header.qr != 1 {
        // we ignore questions; except for stats
        stats.sources.add(&packet_info.s_addr);
        stats.destinations.add(&packet_info.d_addr);
        return Ok(());
    }

    *stats.errors.entry(packet_info.header.rcode).or_insert(0) += 1;

    for _ in 0..packet_info.header.qdcount {
        offset += parse_question(
            packet_info,
            packet,
            offset,
            stats,
            packet_info.header.rcode,
            config,
        )?;
    }
    for _ in 0..packet_info.header.ancount {
        offset += parse_answer(packet_info, packet, offset, stats, config, Answer)?;
    }
    if config.authority {
        for _ in 0..packet_info.header.nscount {
            offset += parse_answer(packet_info, packet, offset, stats, config, Authority)?;
        }
    }
    if config.additional {
        for _ in 0..packet_info.header.arcount {
            offset += parse_answer(packet_info, packet, offset, stats, config, Additional)?;
        }
    }
    Ok(())
}
