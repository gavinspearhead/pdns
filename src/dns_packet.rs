use crate::config::Config;
use crate::dns_class::DnsClass;
use crate::dns_edns::parse_edns;
use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u32};
use crate::dns_name::dns_parse_name;
use crate::dns_opcodes::DNSOpcodes;
use crate::dns_record::DNSRecord;
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr::dns_parse_rdata;
use crate::dns_rr_type::DNS_RR_type;
use crate::edns::DNSExtendedError;
use crate::errors::ParseError;
use crate::errors::ParseErrorType;
use crate::packet_info::PacketInfo;
use crate::skiplist::SkipList;
use crate::statistics::Statistics;
use publicsuffix::Psl as _;
use tracing::{debug};

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct DnsQuestion {
    pub dns_rr_type: DNS_RR_type,
    pub dns_class_type: DnsClass,
    pub name: String,
}

impl DnsQuestion {
    pub fn new() -> DnsQuestion {
        DnsQuestion::default()
    }
    pub fn parse(
        &mut self,
        packet: &[u8],
        offset_in: usize,
        skip_list: &SkipList,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let (name, offset) = dns_parse_name(packet, offset_in)?;
        if skip_list.match_skip_list(&name) {
            return Err(ParseError::new(ParseErrorType::Skipped_Message, &name).into());
        }
        let rrtype_val = dns_read_u16(packet, offset)?;
        let class_val = dns_read_u16(packet, offset + 2)?;
        name.clone_into(&mut self.name);
        self.dns_rr_type = DNS_RR_type::find(rrtype_val)?;
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
    skip_list: &SkipList,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut dns_question = DnsQuestion::new();
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
        let rec = DNSRecord {
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
    let len = offset - offset_in;
    Ok(len)
}

fn parse_answer(
    packet_info: &mut PacketInfo,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &SkipList,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;
    if skip_list.match_skip_list(&name) {
        return Err(ParseError::new(ParseErrorType::Skipped_Message, &name).into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let rrtype = DNS_RR_type::find(rrtype_val)?;
    if rrtype == DNS_RR_type::OPT {
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
    let rdata = dns_parse_rdata(data, rrtype, packet, offset)?;
    let rec = DNSRecord {
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

#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct DnsHeader {
    // Transaction ID
    pub id: u16,
    pub flags: u16,
    // Flags
    pub qr: u8,              // Query/Response flag
    pub opcode: DNSOpcodes,  // Operation code
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
    pub fn new() -> DnsHeader {
        DnsHeader::default()
    }

    pub fn parse(&mut self, packet: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        self.id = dns_read_u16(packet, 0)?;
        let flags = dns_read_u16(packet, 2)?;
        self.flags = flags;
        self.qr = ((flags & 0x8000) >> 15) as u8;
        let opcode_val = (flags >> 11) & 0x000f;
        self.opcode = DNSOpcodes::find(opcode_val)?;
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
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut dns_header = DnsHeader::new();
    let packet = packet_in;
    let mut offset = dns_header.parse(packet)?;

    *stats.opcodes.entry(dns_header.opcode).or_insert(0) += 1;
    if dns_header.opcode != DNSOpcodes::Query {
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

    stats.additional += u128::from(dns_header.arcount);
    stats.authority += u128::from(dns_header.nscount);
    stats.answers += u128::from(dns_header.ancount);
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
        for _ in 0..dns_header.arcount {
            offset += parse_answer(packet_info, packet, offset, stats, config, skip_list)?;
        }
    }
    Ok(())
}
