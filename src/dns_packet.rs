use crate::config::Config;
use crate::dns::{dnssec_algorithm, dnssec_digest, DNS_Opcodes};
use crate::dns_helper::{
    self, dns_read_u128, dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8, parse_class,
    parse_rrtype,
};
use crate::dns_rr::{dns_parse_name, dns_parse_rdata};
use crate::edns::{DNSExtendedError, EDNS0ptionCodes};
use crate::errors::ParseErrorType;
use crate::packet_info::Packet_info;
use crate::statistics::Statistics;
use byteorder::{BigEndian, ByteOrder};
use dns::{dns_reply_type, DNS_RR_type, DNS_record, DnsReplyType};
use errors::Parse_error;
use publicsuffix::Psl;
use regex::Regex;
use skiplist::match_skip_list;
use std::fmt;
use strum::IntoEnumIterator;
use strum_macros::{AsStaticStr, EnumIter, EnumString};
use tracing::debug;

use crate::{dns, errors, skiplist};

#[derive(Debug, EnumIter, Copy, Clone, PartialEq, Eq, EnumString, AsStaticStr)]
pub(crate) enum DNS_Protocol {
    TCP = 6,
    UDP = 17,
}

impl DNS_Protocol {
    pub(crate) fn to_str(self) -> String {
        String::from(strum::AsStaticRef::as_static(&self))
    }

    pub(crate) fn find(val: u16) -> Result<Self, Parse_error> {
        for oc in DNS_Protocol::iter() {
            if (oc as u16) == val {
                return Ok(oc);
            }
        }
        Err(Parse_error::new(
            ParseErrorType::Unknown_Protocol,
            &format!("{val}"),
        ))
    }
}

impl fmt::Display for DNS_Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

fn parse_question(
    _query: &[u8],
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    _config: &Config,
    rcode: DnsReplyType,
    skip_list: &[Regex],
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, offset) = dns_parse_name(packet, offset_in)?;
    if match_skip_list(&name, skip_list) {
        return Err(format!("skipped: {name}").into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let class_val = dns_read_u16(packet, offset + 2)?;
    let rrtype = parse_rrtype(rrtype_val)?;
    let class = parse_class(class_val)?;
    stats
        .qtypes
        .entry(rrtype.to_str())
        .and_modify(|c| *c += 1)
        .or_insert(1);

    stats
        .qclass
        .entry(class.to_str())
        .and_modify(|c| *c += 1)
        .or_insert(1);

    stats.total_time_stats.add(packet_info.timestamp, 1);

    let len = offset - offset_in;
    if rcode == DnsReplyType::NXDOMAIN {
        stats.topnx.add(name.clone());
        stats.blocked_time_stats.add(packet_info.timestamp, 1);
    } else if rcode == DnsReplyType::NOERROR {
        stats.topdomain.add(name.clone());
        stats.success_time_stats.add(packet_info.timestamp, 1);
    }
    if rcode != DnsReplyType::NOERROR {
        let rec: DNS_record = DNS_record {
            rr_type: rrtype.to_str(),
            ttl: 0,
            class: class.to_str(),
            name,
            rdata: String::new(),
            count: 1,
            timestamp: packet_info.timestamp,
            domain: String::new(),
            asn: String::new(),
            asn_owner: String::new(),
            prefix: String::new(),
            error: rcode,
            extended_error: DNSExtendedError::None,
        };
        packet_info.add_dns_record(rec);
    }

    Ok(len + 4)
}

fn parse_edns(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    _config: &Config,
) -> Result<usize, Box<dyn std::error::Error>> {
    let payload_size = dns_read_u16(packet, offset_in)?;
    debug!("payload size {payload_size}");
    let e_rcode = dns_read_u8(packet, offset_in + 2)?;
    debug!("e code {e_rcode}");
    let edns_version = dns_read_u8(packet, offset_in + 3)?;
    debug!("edns_version {edns_version}");
    let _z = dns_read_u16(packet, offset_in + 4)?;
    let data_length = dns_read_u16(packet, offset_in + 6)? as usize;
    if data_length == 0 {
        return Ok(8);
    }
    debug!("data length {data_length}");
    let rdata = &packet[offset_in + 8..offset_in + 8 + data_length];
    let mut offset: usize = 0;
    while offset < data_length as usize {
        let option_code = EDNS0ptionCodes::find(dns_read_u16(rdata, offset)?)?;
        tracing::debug!("option code {option_code}");
        let option_length = dns_read_u16(rdata, offset + 2)? as usize;
        tracing::debug!("option length {option_length}");
        match option_code {
            EDNS0ptionCodes::ExtendedDNSError => {
                // Extended DNS error
                let info_code = DNSExtendedError::find(dns_read_u16(rdata, offset + 4)?)?;
                debug!("info code {info_code}");
                let info_text =
                    std::str::from_utf8(&rdata[offset + 6..offset + 4 + option_length])?;
                debug!("infotext {info_text}");
                if packet_info.dns_records.len() > 0 {
                    packet_info.dns_records[0].extended_error = info_code;
                }

                stats
                    .extended_error
                    .entry(info_code.to_str())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
            }
            EDNS0ptionCodes::CHAIN => {
                let chain = dns_parse_name(rdata, offset + 4)?;
                debug!("Chain {}", chain.0);
            }
            EDNS0ptionCodes::NSID => {
                let nsid = std::str::from_utf8(&rdata[offset + 4..offset + 4 + option_length])?;
                debug!("infotext {nsid:?}");
            }
            EDNS0ptionCodes::EdnsTcpKeepalive => {
                if option_length == 2 {
                    let timeout = dns_read_u16(rdata, offset + 4)?;
                    debug!("TCP Keepalive {timeout}");
                }
            }
            EDNS0ptionCodes::EDNSEXPIRE => {
                debug!("Expire set");
            }
            EDNS0ptionCodes::EdnsClientSubnet => {
                let family = dns_read_u16(rdata, offset + 4)?;
                let source_prefix_len = dns_read_u8(rdata, offset + 6)?;
                let scope_prefix_len = dns_read_u8(rdata, offset + 7)?;
                let addr = &rdata[offset + 8..offset + option_length + 4];

                if family == 1 {
                    // ipv4
                    let mut addr_: [u8; 4] = [0; 4];
                    addr_[..addr.len()].copy_from_slice(&addr);
                    let v4addr = dns_helper::parse_ipv4(&addr_)?;
                    debug!("{v4addr}/{source_prefix_len}/{scope_prefix_len} (IPv4)");
                } else if family == 2 {
                    // ipv6
                    let mut addr_: [u8; 16] = [0; 16];
                    addr_[..addr.len()].copy_from_slice(&addr);
                    let v6addr = dns_helper::parse_ipv6(&addr_)?;
                    debug!("{v6addr}/{source_prefix_len}/{scope_prefix_len} (IPv6)");
                }
            }
            EDNS0ptionCodes::Padding => {
                debug!(
                    "Padding {option_length} bytes: {:x?} ",
                    &rdata[offset + 4..]
                );
            }
            EDNS0ptionCodes::COOKIE => {
                if option_length == 24 {
                    let client_cookie = dns_read_u64(rdata, offset + 4)?;
                    let server_cookie = dns_read_u128(rdata, offset + 4 + 8)?;
                    debug!("Server cookie {server_cookie:0x}, client_cookie {client_cookie:0x}");
                } else if option_length == 8 {
                    let client_cookie = dns_read_u64(rdata, offset + 4)?;
                    debug!("client_cookie {client_cookie:x}");
                }
            }
            EDNS0ptionCodes::DAU => {
                offset += 4;
                for i in 0..option_length {
                    let alg = dns_read_u8(rdata, offset + i)?;
                    debug!("DNS Signing Algorithm: {}", dnssec_algorithm(alg)?);
                }
            }
            EDNS0ptionCodes::DHU => {
                offset += 4;
                for i in 0..option_length {
                    let alg = dns_read_u8(rdata, offset + i)?;
                    debug!("DS Hash Algorithm: {}", dnssec_digest(alg)?);
                }
            }
            EDNS0ptionCodes::N3U => {
                offset += 4;
                for i in 0..option_length {
                    let alg = dns_read_u8(rdata, offset + i)?;
                    debug!("NSEC3 Hash Algorithm: {}", dnssec_digest(alg)?);
                }
            }
            EDNS0ptionCodes::LLQ => {
                let llq_ver = dns_read_u16(rdata, offset + 4)?;
                let llq_opcode = dns_read_u16(rdata, offset + 6)?;
                let llq_error = dns_read_u16(rdata, offset + 8)?;
                let llq_id = dns_read_u64(rdata, offset + 10)?;
                let llq_lease = dns_read_u32(rdata, offset + 18)?;
                debug!(
                    "LLQ Version: {}, opcode: {}, error: {}, ID: {}, lease: {}",
                    llq_ver, llq_opcode, llq_error, llq_id, llq_lease
                );
            }
            EDNS0ptionCodes::ZoneVersion => {
                let label_conut = dns_read_u8(rdata, offset + 4)?;
                let version_type = dns_read_u8(rdata, offset + 5)?;
                let Some(version) = rdata.get(offset + 6..) else {
                    return Err("No version data".into());
                };
                debug!(
                    "Zone version: {} {} {:x?}",
                    label_conut, version_type, &version
                );
            }
            EDNS0ptionCodes::EDNSClientTag => {
                let client_tag = dns_read_u16(rdata, offset + 4)?;
                debug!("Client Tag: {}", client_tag);
            }
            EDNS0ptionCodes::EDNSServerTag => {
                let server_tag = dns_read_u16(rdata, offset + 4)?;
                debug!("Server Tag: {}", server_tag);
            }
            EDNS0ptionCodes::EdnsKeyTag => {
                offset += 4;
                for i in 0..option_length / 2 {
                    let key_tag = dns_read_u16(packet, offset + 2 * i)?;
                    debug!("Key tag: {}", key_tag);
                }
            }
            EDNS0ptionCodes::UpdateLease => {
                let lease = dns_read_u32(rdata, offset + 4)?;
                debug!("Lease: {lease}");
                if option_length == 8 {
                    let key_lease = dns_read_u32(rdata, offset + 4)?;
                    debug!("Key Lease: {key_lease}");
                }
            }
            EDNS0ptionCodes::ReportChannel => {
                let (name, _offset) = dns_parse_name(rdata, offset + 4)?;
                debug!("Report channel: {name}");
            }
            _ => {}
        }
        offset += option_length + 4; // need to add the option code and length fields too
    }

    Ok(8 + data_length)
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
    debug!("rrtype {rrtype}");
    if rrtype == DNS_RR_type::OPT {
        let len = parse_edns(packet_info, packet, offset + 2, stats, config)?;
        offset += len as usize - 1;
        let len = offset + 2 - offset_in;
        return Ok(len);
    }
    let class_val = dns_read_u16(packet, offset + 2)?;
    let class = parse_class(class_val)?;
    stats
        .atypes
        .entry(rrtype.to_str())
        .and_modify(|c| *c += 1)
        .or_insert(1);
    stats
        .aclass
        .entry(class.to_str())
        .and_modify(|c| *c += 1)
        .or_insert(1);

    let ttl = dns_read_u32(packet, offset + 4)?;
    let datalen: usize = dns_read_u16(packet, offset + 8)?.into();

    if !config.rr_type.contains(&rrtype) {
        let len = (offset - offset_in) + 10 + datalen;
        return Ok(len);
    }

    offset += 10;
    let data = &packet[offset..offset + datalen];
    let rdata = dns_parse_rdata(data, rrtype, packet, offset)?;
    offset += 1;

    let domain = publicsuffixlist.domain(name.as_bytes());

    let domain_str = if let Some(d) = domain {
        let x = d.trim().as_bytes().to_vec();
        String::from_utf8(x).unwrap_or_default()
    } else {
        debug!("Not found {name}");
        String::new()
    };

    let rec: DNS_record = DNS_record {
        rr_type: rrtype.to_str(),
        ttl,
        class: class.to_str(),
        name,
        rdata,
        count: 1,
        timestamp: packet_info.timestamp,
        domain: domain_str,
        asn: String::new(),
        asn_owner: String::new(),
        prefix: String::new(),
        error: DnsReplyType::NOERROR,
        extended_error: DNSExtendedError::None,
    };
    packet_info.add_dns_record(rec);
    offset += datalen - 1;
    let len = offset - offset_in;
    Ok(len)
}

pub(crate) fn parse_dns(
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
    let opcode_val = (flags >> 11) & 0x000f;
    let tr = (flags >> 9) & 0x0001;
    let _rd = (flags >> 8) & 0x0001;
    let _ra = (flags >> 7) & 0x0001;
    let rcode = flags & 0x000f;
    let opcode = DNS_Opcodes::find(opcode_val)?;
    if opcode != DNS_Opcodes::Query {
        // Query
        tracing::debug!("Skipping DNS packets that are not queries");
        return Ok(());
    }

    if tr != 0 {
        tracing::debug!("Skipping truncated DNS packets");
        return Ok(());
    }

    let questions = dns_read_u16(packet, offset)?;
    if questions == 0 {
        tracing::debug!("Empty questions section... skipping");
        return Ok(());
    }

    offset += 2;
    let answers = dns_read_u16(packet, offset)?;
    offset += 2;
    let authority = dns_read_u16(packet, offset)?;
    offset += 2;
    let additional = dns_read_u16(packet, offset)?;
    offset += 2;
    stats.additional += u128::from(additional);
    stats.authority += u128::from(authority);
    stats.answers += u128::from(answers);
    stats.queries += u128::from(questions);

    if qr != 1 {
        // we ignore questions; except for stats
        stats
            .opcodes
            .entry(opcode.to_str())
            .and_modify(|c| *c += 1)
            .or_insert(1);
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
            DnsReplyType::find(rcode)?,
            skip_list,
        )?;
    }
   // tracing::debug!("Answers {}", answers);
    for _i in 0..answers {
       // debug!("answer {_i} of {answers} offset {offset}");
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    if config.authority {
       // tracing::debug!("Authority {}", authority);
        for _i in 0..authority {
         //   debug!("authority {_i} of {authority} offset {offset}");
            offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
        }
    }
    if config.additional {
      //  tracing::debug!("Additional {}", additional);
        for _i in 0..additional {
          //  debug!("additional {_i} of {additional} offset {offset}");
            offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
        }
    }
    debug!("{}", packet_info);
    Ok(())
}
