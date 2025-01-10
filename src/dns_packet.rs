use crate::config::Config;
use crate::dns::{dnssec_algorithm, dnssec_digest, DNS_Opcodes};
use crate::dns_helper::{
    self, dns_parse_slice, dns_read_u128, dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8,
    parse_class, parse_rrtype,
};
use crate::dns_rr::{dns_parse_name, dns_parse_rdata};
use crate::edns::{DNSExtendedError, EDNSOptionCodes};
use crate::errors::ParseErrorType;
use crate::packet_info::Packet_info;
use crate::skiplist::Skip_List;
use crate::statistics::Statistics;
use dns::{DNS_RR_type, DnsReplyType};
use errors::Parse_error;
use publicsuffix::Psl as _;
use std::fmt;
use std::fmt::Debug;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};
use tracing::{debug, error};

use crate::dns_record::DNS_record;
use crate::{dns, errors};

#[derive(Debug, EnumIter, Copy, Clone, PartialEq, Eq, EnumString, IntoStaticStr, FromRepr)]
pub(crate) enum DNS_Protocol {
    TCP = 6,
    UDP = 17,
    SCTP = 132,
}

impl DNS_Protocol {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, Parse_error> {
        match DNS_Protocol::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(Parse_error::new(
                ParseErrorType::Unknown_Protocol,
                &val.to_string(),
            )),
        }
    }
}

impl fmt::Display for DNS_Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

fn parse_question(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    _config: &Config,
    rcode: DnsReplyType,
    skip_list: &Skip_List,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, offset) = dns_parse_name(packet, offset_in)?;
    if skip_list.match_skip_list(&name) {
        return Err(format!("skipped: {name}").into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let class_val = dns_read_u16(packet, offset + 2)?;
    let rrtype = parse_rrtype(rrtype_val)?;
    let class = parse_class(class_val)?;
    *stats.qtypes.entry(rrtype).or_insert(0) += 1;
    *stats.qclass.entry(class).or_insert(0) += 1;
    stats.total_time_stats.add(packet_info.timestamp, 1);

    let len = offset - offset_in;
    if rcode == DnsReplyType::NXDOMAIN {
        stats.topnx.add(&name);
        stats.blocked_time_stats.add(packet_info.timestamp, 1);
    } else if rcode == DnsReplyType::NOERROR {
        stats.topdomain.add(&name);
        stats.success_time_stats.add(packet_info.timestamp, 1);
    } else {
        debug!("Other rcode: {rcode:?} ");
    }

    if rcode != DnsReplyType::NOERROR {
        let rec: DNS_record = DNS_record {
            rr_type: rrtype,
            ttl: 0,
            class,
            name,
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
    Ok(len + 4)
}

fn parse_edns(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
    _config: &Config,
) -> Result<usize, Box<dyn std::error::Error>> {
    //let payload_size = dns_read_u16(packet, offset_in)?;
    // debug!("payload size {payload_size}");
    //let e_rcode = dns_read_u8(packet, offset_in + 2)?;
    // debug!("e code {e_rcode}");
    //let edns_version = dns_read_u8(packet, offset_in + 3)?;
    // debug!("edns_version {edns_version}");
    // let _z = dns_read_u16(packet, offset_in + 4)?;
    let data_length = usize::from(dns_read_u16(packet, offset_in + 6)?);
    if data_length == 0 {
        return Ok(8);
    }
    // debug!("data length {data_length}");
    let rdata = dns_parse_slice(packet, offset_in + 8..offset_in + 8 + data_length)?;
    let mut offset: usize = 0;
    while offset < data_length {
        let option_code = EDNSOptionCodes::find(dns_read_u16(rdata, offset)?)?;
        // debug!("option code {option_code}");
        let option_length = dns_read_u16(rdata, offset + 2)? as usize;
        //debug!("option length {option_length}");
        match option_code {
            EDNSOptionCodes::ExtendedDNSError => {
                // Extended DNS error
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
            }
            EDNSOptionCodes::CHAIN => {
                let chain = dns_parse_name(rdata, offset + 4)?;
                debug!("Chain {}", chain.0);
            }
            EDNSOptionCodes::NSID => {
                let nsid = std::str::from_utf8(dns_parse_slice(
                    rdata,
                    offset + 4..offset + 4 + option_length,
                )?)?;
                debug!("infotext {nsid:?}");
            }
            EDNSOptionCodes::EdnsTcpKeepalive => {
                if option_length == 2 {
                    let timeout = dns_read_u16(rdata, offset + 4)?;
                    debug!("TCP Keepalive {timeout}");
                }
            }
            EDNSOptionCodes::EDNSEXPIRE => {
                debug!("Expire set");
            }
            EDNSOptionCodes::EdnsClientSubnet => {
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
            }
            EDNSOptionCodes::Padding => {
                debug!(
                    "Padding {option_length} bytes: {:x?} ",
                    dns_parse_slice(rdata, offset + 4..)?
                );
            }
            EDNSOptionCodes::COOKIE => {
                if option_length == 24 {
                    let client_cookie = dns_read_u64(rdata, offset + 4)?;
                    let server_cookie = dns_read_u128(rdata, offset + 4 + 8)?;
                    debug!("Server cookie {server_cookie:0x}, client_cookie {client_cookie:0x}");
                } else if option_length == 8 {
                    let client_cookie = dns_read_u64(rdata, offset + 4)?;
                    debug!("client_cookie {client_cookie:x}");
                }
            }
            EDNSOptionCodes::DAU => {
                offset += 4;
                for i in 0..option_length {
                    let alg = dns_read_u8(rdata, offset + i)?;
                    debug!("DNS Signing Algorithm: {}", dnssec_algorithm(alg)?);
                }
            }
            EDNSOptionCodes::DHU => {
                offset += 4;
                for i in 0..option_length {
                    let alg = dns_read_u8(rdata, offset + i)?;
                    debug!("DS Hash Algorithm: {}", dnssec_digest(alg)?);
                }
            }
            EDNSOptionCodes::N3U => {
                offset += 4;
                for i in 0..option_length {
                    let alg = dns_read_u8(rdata, offset + i)?;
                    debug!("NSEC3 Hash Algorithm: {}", dnssec_digest(alg)?);
                }
            }
            EDNSOptionCodes::LLQ => {
                let llq_ver = dns_read_u16(rdata, offset + 4)?;
                let llq_opcode = dns_read_u16(rdata, offset + 6)?;
                let llq_error = dns_read_u16(rdata, offset + 8)?;
                let llq_id = dns_read_u64(rdata, offset + 10)?;
                let llq_lease = dns_read_u32(rdata, offset + 18)?;
                debug!( "LLQ Version: {llq_ver}, opcode: {llq_opcode}, error: {llq_error}, ID: {llq_id}, lease: {llq_lease}" );
            }
            EDNSOptionCodes::ZoneVersion => {
                let label_count = dns_read_u8(rdata, offset + 4)?;
                let version_type = dns_read_u8(rdata, offset + 5)?;
                let Some(version) = rdata.get(offset + 6..) else {
                    return Err("No version data".into());
                };
                debug!("Zone version: {label_count} {version_type} {version:x?}");
            }
            EDNSOptionCodes::EDNSClientTag => {
                let client_tag = dns_read_u16(rdata, offset + 4)?;
                debug!("Client Tag: {client_tag}");
            }
            EDNSOptionCodes::EDNSServerTag => {
                let server_tag = dns_read_u16(rdata, offset + 4)?;
                debug!("Server Tag: {server_tag}");
            }
            EDNSOptionCodes::EdnsKeyTag => {
                offset += 4;
                for i in 0..option_length / 2 {
                    let key_tag = dns_read_u16(packet, offset + 2 * i)?;
                    debug!("Key tag: {key_tag}");
                }
            }
            EDNSOptionCodes::UpdateLease => {
                let lease = dns_read_u32(rdata, offset + 4)?;
                debug!("Lease: {lease}");
                if option_length == 8 {
                    let key_lease = dns_read_u32(rdata, offset + 4)?;
                    debug!("Key Lease: {key_lease}");
                }
            }
            EDNSOptionCodes::ReportChannel => {
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
    skip_list: &Skip_List,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (name, mut offset) = dns_parse_name(packet, offset_in)?;
    if skip_list.match_skip_list(&name) {
        return Err(format!("skipped: {name}").into());
    }
    let rrtype_val = dns_read_u16(packet, offset)?;
    let rrtype = parse_rrtype(rrtype_val)?;
    //debug!("rrtype: {rrtype}");
    if rrtype == DNS_RR_type::OPT {
        offset += 2;
        let len = parse_edns(packet_info, packet, offset, stats, config)?;
        let len = offset + len - offset_in;
        return Ok(len);
    }
    let class_val = dns_read_u16(packet, offset + 2)?;
    let class = parse_class(class_val)?;
    *stats.atypes.entry(rrtype).or_insert(0) += 1;
    *stats.aclass.entry(class).or_insert(0) += 1;

    let ttl = dns_read_u32(packet, offset + 4)?;
    let datalen: usize = dns_read_u16(packet, offset + 8)?.into();

    if !config.rr_type.contains(&rrtype) {
        let len = (offset - offset_in) + 10 + datalen;
        return Ok(len);
    }

    offset += 10;
    let data = dns_parse_slice(packet, offset..offset + datalen)?;
    let rdata = dns_parse_rdata(data, rrtype, packet, offset)?;
    offset += 1;
    let domain_str = find_domain(publicsuffixlist, name.as_str());
    let rec: DNS_record = DNS_record {
        rr_type: rrtype,
        ttl,
        class,
        name,
        rdata,
        count: 1,
        timestamp: packet_info.timestamp,
        domain: domain_str,
        asn: 0,
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

fn find_domain(publicsuffixlist: &publicsuffix::List, name: &str) -> String {
    let domain = publicsuffixlist.domain(name.as_bytes());
    let domain_str: String = if let Some(d) = domain {
        let x = d.trim().as_bytes().to_vec();
        String::from_utf8(x).unwrap_or_default()
    } else {
        debug!("Domain not found: {name}");
        String::new()
    };
    domain_str
}

pub(crate) fn parse_dns(
    packet_in: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &Skip_List,
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;
    //let mut _len = 0;
    let packet = packet_in;
    //let _trans_id = dns_read_u16(packet, offset)?;
    offset += 2;
    let flags = dns_read_u16(packet, offset)?;
    offset += 2;
    let qr = (flags & 0x8000) >> 15;
    let opcode_val = (flags >> 11) & 0x000f;
    let tr = (flags >> 9) & 0x0001;
    //let _rd = (flags >> 8) & 0x0001;
    //let _ra = (flags >> 7) & 0x0001;
    let rcode = flags & 0x000f;
    let rcode = DnsReplyType::find(rcode)?;
    let opcode = DNS_Opcodes::find(opcode_val)?;
    if opcode != DNS_Opcodes::Query {
        // Query
        debug!("Skipping DNS packets that are not queries");
        return Ok(());
    }

    if tr != 0 {
        debug!("Skipping truncated DNS packets");
        return Ok(());
    }

    let questions = dns_read_u16(packet, offset)?;
    if questions == 0 {
        debug!("Empty questions section... skipping");
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
        *stats.opcodes.entry(opcode).or_insert(0) += 1;
        stats.sources.add(&packet_info.s_addr);
        stats.destinations.add(&packet_info.d_addr);
        return Ok(());
    }

    *stats.errors.entry(rcode).or_insert(0) += 1;

    for _ in 0..questions {
        let _query = dns_parse_slice(packet, offset..)?;
        offset += parse_question(
            packet_info,
            packet,
            offset,
            stats,
            config,
            rcode,
            skip_list,
        )?;
    }
    // tracing::debug!("Answers {}", answers);
    for _ in 0..answers {
        // debug!("answer {_i} of {answers} offset {offset}");
        offset += parse_answer(
            packet_info,
            packet,
            offset,
            stats,
            config,
            publicsuffixlist,
            skip_list,
        )?;
    }
    if config.authority {
        // tracing::debug!("Authority {}", authority);
        for _ in 0..authority {
            //   debug!("authority {_i} of {authority} offset {offset}");
            offset += parse_answer(
                packet_info,
                packet,
                offset,
                stats,
                config,
                publicsuffixlist,
                skip_list,
            )?;
        }
    }
    if config.additional {
      //  debug!("Additional {}", additional);
        for _i in 0..additional {
            //debug!("additional {_i} of {additional} offset {offset} data: {:x?}", &
            //   packet[offset..offset+4]);
            offset += parse_answer(
                packet_info,
                packet,
                offset,
                stats,
                config,
                publicsuffixlist,
                skip_list,
            )?;
        }
    }
    debug!("{packet_info}");
    Ok(())
}
