use tracing::{debug, error};
use crate::dns::{dnssec_algorithm, dnssec_digest};
use crate::dns_helper::{dns_parse_slice, dns_read_u128, dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8, parse_ipv4_addr, parse_ipv6_addr};
use crate::dns_name::dns_parse_name;
use crate::dns_reply_type::DnsReplyType;
use crate::edns::{DNSExtendedError, EDNSOptionCodes};
use crate::packet_info::PacketInfo;
use crate::statistics::Statistics;

fn parse_edns_extended_dns_error(
    packet_info: &mut PacketInfo,
    rdata: &[u8],
    offset: usize,
    _option_length: usize,
    stats: &mut Statistics,
) -> Result<(), Box<dyn std::error::Error>> {
    let info_code = DNSExtendedError::find(dns_read_u16(rdata, offset + 4)?)?;
    // debug!("info code {info_code}");
    /*let info_text = std::str::from_utf8(dns_parse_slice(
        rdata,
        offset + 6..offset + 4 + option_length,
    )?)?;*/
    // debug!("infotext {info_text}");
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
        let v4addr = parse_ipv4_addr(&addr_)?;
        debug!("{v4addr}/{source_prefix_len}/{scope_prefix_len} (IPv4)");
    } else if family == 2 {
        // ipv6
        let mut addr_: [u8; 16] = [0; 16];
        addr_[..addr.len()].copy_from_slice(addr);
        let v6addr = parse_ipv6_addr(&addr_)?;
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
        let key_lease = dns_read_u32(rdata, offset + 8)?;
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

pub (crate) fn parse_edns(
    packet_info: &mut PacketInfo,
    packet: &[u8],
    offset_in: usize,
    stats: &mut Statistics,
) -> Result<usize, Box<dyn std::error::Error>> {
    //let payload_size = dns_read_u16(packet, offset_in)?;
    let e_rcode = u16::from(dns_read_u8(packet, offset_in + 2)?);
    if e_rcode != 0 {
        if let Some(x) = packet_info.dns_records.first() {
            let mut rec = x.clone();
            rec.error = DnsReplyType::find(rec.error as u16 | (e_rcode << 4))?;
            //    debug!("EDNS error code {}", rec.error);
            packet_info.dns_records[0] = rec;
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
            EDNSOptionCodes::EdnsKeyTag => parse_edns_key_tag(rdata, offset, option_length)?,
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
