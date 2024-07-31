use crate::config::Config;
use crate::dns::{DNSExtendedError, DNS_Opcodes, EDNS0ptionCodes};
use crate::dns_helper::{dns_read_u16, dns_read_u32, dns_read_u8, parse_class, parse_rrtype};
use crate::dns_rr::{dns_parse_name, dns_parse_rdata};
use crate::packet_info::Packet_info;
use crate::statistics::Statistics;
use byteorder::{BigEndian, ByteOrder};
use dns::{dns_reply_type, DNS_RR_type, DNS_record, DnsReplyType};
use errors::Parse_error;
use publicsuffix::Psl;
use regex::Regex;
use skiplist::match_skip_list;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use tcp_connection::TCP_Connections;

use crate::{dns, errors, skiplist, tcp_connection, DNS_Protocol};

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
    tracing::debug!("payload size {payload_size}");
    let e_rcode = dns_read_u8(packet, offset_in + 2)?;
    tracing::debug!("e code {e_rcode}");
    let edns_version = dns_read_u8(packet, offset_in + 3)?;
    tracing::debug!("edns_version {edns_version}");
    let _z = dns_read_u16(packet, offset_in + 4)?;
   // tracing::debug!("z {_z}");
    let data_length = dns_read_u16(packet, offset_in + 6)? as usize;
    if data_length == 0 {
        return Ok(0);
    }
    tracing::debug!("data length {data_length}");
    let rdata = &packet[offset_in + 8..offset_in + 8 + data_length];
    let mut offset: usize = 0;
    while offset < data_length as usize {
        let option_code = EDNS0ptionCodes::find(dns_read_u16(rdata, offset)?)?;
        tracing::debug!("optino code {option_code}");
        let option_length = dns_read_u16(rdata, offset + 2)? as usize;
        tracing::debug!("option length {option_length}");
        match option_code {
            EDNS0ptionCodes::ExtendedDNSError => {
                // Extended DNS error
                let info_code = DNSExtendedError::find(dns_read_u16(rdata, offset + 4)?)?;
                tracing::debug!("info code {info_code}");
                let info_text =
                    std::str::from_utf8(&rdata[offset + 6..offset + 4 + option_length])?;
                tracing::debug!("infotext {info_text}");
                packet_info.dns_records[0].extended_error = info_code;

                stats
                    .extended_error
                    .entry(info_code.to_str())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
            }
            EDNS0ptionCodes::NSID => {
                let nsid = std::str::from_utf8(&rdata[offset + 4..offset + 4 + option_length])?;
                tracing::debug!("infotext {nsid:?}");
            }
            EDNS0ptionCodes::COOKIE => {}
            _ => {
                // TODO
            }
        }
        offset += option_length + 4; // need to add the option code and length fields too
    }

    Ok(0)
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
        let _ = parse_edns(packet_info, packet, offset + 2, stats, config)?;
        return Ok(0);
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

    if !config.rr_type.contains(&rrtype) {
        return Ok(0);
    }
    let ttl = dns_read_u32(packet, offset + 4)?;
    let datalen: usize = dns_read_u16(packet, offset + 8)?.into();
    let data = &packet[offset + 10..offset + 10 + datalen];
    let rdata = dns_parse_rdata(data, rrtype, packet, offset + 10)?;
    offset += 11;

    let domain = publicsuffixlist.domain(name.as_bytes());
    let mut domain_str = String::new();
    match domain {
        Some(d) => {
            let x = d.trim().as_bytes().to_vec();
            domain_str = String::from_utf8(x).unwrap_or_default();
        }
        None => {
            tracing::debug!("Not found {name}");
        }
    }
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
    offset += datalen as usize - 1;
    let len = offset - offset_in;
    Ok(len)
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
    let opcode = (flags >> 11) & 0x000f;
    let tr = (flags >> 9) & 0x0001;
    let _rd = (flags >> 8) & 0x0001;
    let _ra = (flags >> 7) & 0x0001;
    let rcode = flags & 0x000f;

    if DNS_Opcodes::find(opcode)? != DNS_Opcodes::Query {
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
    tracing::debug!("Answers {}", answers);
    for _i in 0..answers {
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    tracing::debug!("Authority {}", authority);
    for _i in 0..authority {
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    tracing::debug!("Additional {}", additional);
    for _i in 0..additional {
        offset += parse_answer(packet_info, packet, offset, stats, config, publicsuffixlist)?;
    }
    Ok(())
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
        return Err(Parse_error::new(errors::ParseErrorType::Invalid_TCP_Header, "").into());
    }
    let sp: u16 = dns_read_u16(packet, 0)?;
    let dp: u16 = dns_read_u16(packet, 2)?;
    if !(dp == 53 || sp == 53 || dp == 5353 || sp == 5353 || dp == 5355 || sp == 5355) {
        return Err(Parse_error::new(errors::ParseErrorType::Invalid_DNS_Packet, "").into());
    }
    let hl: u8 = (packet[12] >> 4) * 4;
    let len: u32 = u32::try_from(packet.len() - usize::from(hl))?;
    let flags = packet[13];
    let _wsize = dns_read_u16(packet, 14)?;
    let seqnr = dns_read_u32(packet, 4)?;

    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(len);

    let Some(dnsdata) = packet.get((hl as usize)..) else {
        return Err(Parse_error::new(errors::ParseErrorType::Invalid_TCP_Packet, "").into());
    };
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
    if let Some(d) = r {
        stats.tcp += 1;
        return parse_dns(
            d.data(),
            packet_info,
            stats,
            config,
            skip_list,
            publicsuffixlist,
        );
    };

    Ok(())
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
        return Err(Parse_error::new(errors::ParseErrorType::Invalid_UDP_Header, "").into());
    }
    let sp: u16 = dns_read_u16(packet, 0)?;
    let dp: u16 = dns_read_u16(packet, 2)?;
    let len: u16 = dns_read_u16(packet, 4)?;
    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(u32::from(len) - 8);

    if dp == 53 || sp == 53 || dp == 5353 || sp == 5353 || dp == 5355 || sp == 5355 {
        stats.udp += 1;
        parse_dns(
            &packet[8..],
            packet_info,
            stats,
            config,
            skip_list,
            publicsuffixlist,
        )
    } else {
        Err(Parse_error::new(
            errors::ParseErrorType::Invalid_DNS_Packet,
            &format!("{dp} {sp}"),
        )
        .into())
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
    if protocol == 6 {
        packet_info.set_protocol(DNS_Protocol::TCP);
        // TCP
        parse_tcp(
            packet,
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        )
    } else if protocol == 17 {
        packet_info.set_protocol(DNS_Protocol::UDP);
        //  UDP
        parse_udp(
            packet,
            packet_info,
            stats,
            config,
            skip_list,
            publicsuffixlist,
        )
    } else {
        Ok(())
    }
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
    if packet.len() < 20 {
        return Err(Parse_error::new(errors::ParseErrorType::Invalid_IPv6_Header, "").into());
    }
    if packet[0] >> 4 != 4 {
        return Err(Parse_error::new(
            errors::ParseErrorType::Invalid_IP_Version,
            &format!("{:x}", &packet[0] >> 4),
        )
        .into());
    }
    let ihl: u16 = (u16::from(packet[0] & 0xf)) * 4;
    let mut t: [u8; 4] = packet[12..16].try_into()?;
    let src = Ipv4Addr::from(t);
    t = packet[16..20].try_into()?;
    let dst = Ipv4Addr::from(t);
    let len: u16 = dns_read_u16(packet, 2)? - ihl;
    let next_header = packet[9];
    packet_info.set_dest_ip(std::net::IpAddr::V4(dst));
    packet_info.set_source_ip(std::net::IpAddr::V4(src));
    packet_info.set_ip_len(len);
    parse_tunneling(
        &packet[ihl as usize..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
        publicsuffixlist,
    )
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
    if next_header == 4 {
        // IPIP
        if packet.len() < 20 {
            return Err(Parse_error::new(
                errors::ParseErrorType::Packet_Too_Small,
                &format!("{}", packet.len()),
            )
            .into());
            //ip packets are always >= 20 bytes
        }
        let ip_ver = packet[0] >> 4;
        if ip_ver == 4 {
            return parse_ipv4(
                packet,
                packet_info,
                stats,
                tcp_list,
                config,
                skip_list,
                publicsuffixlist,
            );
        } else if ip_ver == 6 {
            return parse_ipv6(
                packet,
                packet_info,
                stats,
                tcp_list,
                config,
                skip_list,
                publicsuffixlist,
            );
        } else {
            return Err(Parse_error::new(
                errors::ParseErrorType::Invalid_IP_Version,
                &format!("{ip_ver}"),
            )
            .into());
        }
    } else {
        parse_ip_data(
            packet,
            next_header,
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        )
    }
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
    if packet.len() < 40 {
        return Err(Parse_error::new(
            errors::ParseErrorType::Invalid_IPv6_Header,
            &format!("{}", packet.len()),
        )
        .into());
    }
    let mut t: [u8; 16] = packet[8..24].try_into()?;
    let src = Ipv6Addr::from(t);
    let _len: u16 = dns_read_u16(packet, 4)?;
    t = packet[24..40].try_into()?;
    let dst = Ipv6Addr::from(t);
    if packet[0] >> 4 != 6 {
        return Err(Parse_error::new(
            errors::ParseErrorType::Invalid_IP_Version,
            &format!("{}", &packet[0] >> 4),
        )
        .into());
    }
    packet_info.set_dest_ip(std::net::IpAddr::V6(dst));
    packet_info.set_source_ip(std::net::IpAddr::V6(src));

    let next_header = packet[6];
    parse_tunneling(
        &packet[40..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
        publicsuffixlist,
    )
}

pub(crate) fn parse_eth(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &[Regex],
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    packet_info.frame_len = u32::try_from(packet.len())?;
    let mut offset = 12;
    let mut eth_type_field = dns_read_u16(packet, offset)?;
    offset += 2;

    if eth_type_field == 0x8100 {
        offset += 2;
        eth_type_field = dns_read_u16(packet, offset)?;
        offset += 2;
    }

    if eth_type_field == 0x0800 {
        parse_ipv4(
            &packet[offset..],
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        )
    } else if eth_type_field == 0x86dd {
        parse_ipv6(
            &packet[offset..],
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
            publicsuffixlist,
        )
    } else {
        Err(Parse_error::new(
            errors::ParseErrorType::Invalid_IP_Version,
            &format!("{}", &packet[0] >> 4),
        )
        .into())
    }
}
