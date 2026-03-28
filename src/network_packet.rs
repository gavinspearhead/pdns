use crate::config::Config;
use crate::dns_helper::{self, dns_parse_slice, dns_read_u16, dns_read_u32, dns_read_u8};
use crate::dns_packet::parse_dns;
use crate::dns_protocol::DNSProtocol;
use crate::errors::ParseErrorType;
use crate::errors::ParseErrorType::{Invalid_DNS_Packet, Invalid_Data, Invalid_IP_Version, Invalid_IPv4_Header, Invalid_IPv6_Header, Invalid_TCP_Header, Invalid_UDP_Header, Packet_Too_Small};
use crate::packet_info::PacketInfo;
use crate::skiplist::SkipList;
use crate::statistics::Statistics;
use crate::{errors, tcp_connection};
use errors::ParseError;
use parking_lot::Mutex;
use std::sync::Arc;
use tcp_connection::TCPConnections;
use tracing::debug;

const UDP_MIN_PACKET_LEN: usize = 8;
const IPV4_MIN_PACKET_LEN: usize = 20;
const IPV6_MIN_PACKET_LEN: usize = 40;

fn parse_tcp(
    packet: &[u8],
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 20 {
        return Err(ParseError::new(Invalid_TCP_Header, "packet too short").into());
    }
    let sp = dns_read_u16(packet, 0)?;
    let dp = dns_read_u16(packet, 2)?;
    if !(config.ports.contains(&sp) || config.ports.contains(&dp)) {
        return Err(ParseError::new(Invalid_DNS_Packet, "").into());
    }
    let data_offset = usize::from((dns_read_u8(packet, 12)? >> 4) * 4);
    if data_offset < 20 || data_offset > 60 {
        return Err(ParseError::new(Invalid_TCP_Header, "invalid header length").into());
    }
    let len = u32::try_from(packet.len() - data_offset)?;
    let flags = dns_read_u8(packet, 13)?;
    //let _wsize = dns_read_u16(packet, 14)?;
    let seq_nr = dns_read_u32(packet, 4)?;

    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(len);

    let dns_data = dns_parse_slice(packet, data_offset..)?;
    let tcp_record = tcp_list.lock().process_data(
        sp,
        dp,
        &packet_info.s_addr,
        &packet_info.d_addr,
        seq_nr,
        dns_data,
        flags,
    );
    if let Some(tcp_data) = tcp_record {
        let data = tcp_data.data();
        let data_len = data.len();
        if data_len == 0 {
            return Ok(());
        }
        if data_len < 2 {
            return Err(ParseError::new(
                Invalid_TCP_Header,
                "TCP data too short for DNS length field",
            )
            .into());
        }
        stats.tcp += 1;
        let mut offset = 0;
        loop {
            let len = usize::from(dns_read_u16(data, offset)?);
            if len == 0 {
                break;
            }
            offset += 2;
            let dns_payload = match dns_parse_slice(data, offset..offset.checked_add(len).ok_or_else(|| ParseError::new(Invalid_TCP_Header, "offset overflow"))?) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Invalid TCP payload for DNS: {:?}", e);
                    stats.erroneous += 1;
                    return Ok(());
                }
            };
            let rv = parse_dns(dns_payload, packet_info, stats, config, skip_list);
            if let Err(e) = rv {
                if let Some(parse_error) = e.downcast_ref::<ParseError>() {
                    if parse_error.error_type == ParseErrorType::Skipped_Message {
                        stats.skipped += 1;
                    } else {
                        stats.erroneous += 1;
                        debug!("Error parsing DNS packet: {:?}", e);
                    }
                } else {
                    stats.erroneous += 1;
                    debug!("Other error for DNS packet: {:?}", e);
                }
                return Err(e);
            }

            offset += len;
            if offset >= data_len {
                break;
            }
        }
    }
    Ok(())
}

fn parse_udp(
    packet: &[u8],
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < UDP_MIN_PACKET_LEN {
        return Err(ParseError::new(Invalid_UDP_Header, "").into());
    }
    let sp = dns_read_u16(packet, 0)?;
    let dp = dns_read_u16(packet, 2)?;
    let len = dns_read_u16(packet, 4)?;
    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(u32::from(len) - 8);

    if config.ports.contains(&sp) || config.ports.contains(&dp) {
        stats.udp += 1;
        let dns_payload = match dns_parse_slice(packet, 8..) {
            Ok(s) => s,
            Err(e) => {
                debug!("Invalid UDP payload for DNS: {:?}", e);
                stats.erroneous += 1;
                return Ok(());
            }
        };
        let rv = parse_dns(dns_payload, packet_info, stats, config, skip_list);

        if let Err(e) = rv {
            if let Some(parse_error) = e.downcast_ref::<ParseError>() {
                if parse_error.error_type == ParseErrorType::Skipped_Message {
                    stats.skipped += 1;
                } else {
                    debug!("Error parsing DNS packet: {:?}", e);
                    stats.erroneous += 1;
                }
            } else {
                debug!("Other DNS error: {:?}", e);
                stats.erroneous += 1;
            }
        }
        Ok(())
    } else {
        Err(ParseError::new(Invalid_DNS_Packet, &format!("{dp} {sp}")).into())
    }
}

fn parse_ip_data(
    packet: &[u8],
    protocol: u8,
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    if protocol == DNSProtocol::TCP.as_u8() {
        // TCP
        if config.capture_tcp {
            packet_info.set_protocol(DNSProtocol::TCP);
            parse_tcp(packet, packet_info, stats, tcp_list, config, skip_list)
        } else {
            Ok(())
        }
    } else if protocol == DNSProtocol::UDP.as_u8()  {
        //  UDP
        packet_info.set_protocol(DNSProtocol::UDP);
        parse_udp(packet, packet_info, stats, config, skip_list)
    } else if protocol == DNSProtocol::SCTP.as_u8()  {
        // sctp TODO
        Ok(())
    } else {
        Ok(())
    }
}

fn parse_ipv4(
    packet: &[u8],
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    stats.ipv4 += 1;
    if packet.len() < IPV4_MIN_PACKET_LEN {
        return Err(ParseError::new(Invalid_IPv4_Header, "Incomplete Header").into());
    }
    if packet[0] >> 4 != 4 {
        return Err(ParseError::new(Invalid_IP_Version, &format!("{:x}", &packet[0] >> 4)).into());
    }
    let ihl = (u16::from(packet[0] & 0xf)) * 4;
    if ihl < IPV4_MIN_PACKET_LEN as u16 || ihl > 56 {
        return Err(ParseError::new(Invalid_IPv4_Header, &format!("{ihl}", )).into());
    }
    let src = dns_helper::parse_ipv4_addr(&packet[12..16])?;
    let dst = dns_helper::parse_ipv4_addr(&packet[16..20])?;
    let len = dns_read_u16(packet, 2)? - ihl;
    let next_header = packet[9];
    packet_info.set_dest_ip(dst);
    packet_info.set_source_ip(src);
    packet_info.set_ip_len(len);
    parse_tunneling(
        &packet[usize::from(ihl)..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
    )
}

fn parse_tunneling(
    packet: &[u8],
    next_header: u8,
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    if next_header == 4 || next_header == 41 {
        // IPIP
        if packet.len() < IPV4_MIN_PACKET_LEN {
            return Err(ParseError::new(Packet_Too_Small, &format!("{}", packet.len())).into());
            //ip packets are always >= 20 bytes
        }
        let ip_ver = packet[0] >> 4;
        if ip_ver == 4 {
            parse_ipv4(packet, packet_info, stats, tcp_list, config, skip_list)
        } else if ip_ver == 6 {
            parse_ipv6(packet, packet_info, stats, tcp_list, config, skip_list)
        } else {
            Err(ParseError::new(Invalid_IP_Version, &format!("{ip_ver}")).into())
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
        )
    }
}

fn parse_ipv6(
    packet: &[u8],
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    skip_list: &SkipList,
) -> Result<(), Box<dyn std::error::Error>> {
    stats.ipv6 += 1;
    if packet.len() < IPV6_MIN_PACKET_LEN {
        return Err(ParseError::new(Invalid_IPv6_Header, &format!("{}", packet.len())).into());
    }
    if packet[0] >> 4 != 6 {
        return Err(ParseError::new(Invalid_IP_Version, &format!("{}", &packet[0] >> 4)).into());
    }

    //    let _len  = dns_read_u16(packet, 4)?;
    let next_header = packet[6];
    let src = dns_helper::parse_ipv6_addr(&packet[8..24])?;
    let dst = dns_helper::parse_ipv6_addr(&packet[24..40])?;
    packet_info.set_dest_ip(dst);
    packet_info.set_source_ip(src);
    parse_tunneling(
        &packet[IPV6_MIN_PACKET_LEN..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
    )
}

pub (crate) fn parse_ip(packet: &[u8], packet_info: &mut PacketInfo, stats: &Arc<Mutex<Statistics>>, tcp_list: &Arc<Mutex<TCPConnections>>, config: &Config, skip_list: &SkipList) -> Result<(), Box<dyn std::error::Error>> {
    if packet.is_empty() {
        debug!("Empty packet for link_type");
        stats.lock().erroneous += 1;
        return Err(ParseError::new(Invalid_Data, &"Empty packet".to_string()).into());
    }
    let first_byte = packet[0];
    if first_byte >> 4 == 6 {
        parse_ipv6(& packet, packet_info, &mut stats.lock(), tcp_list, config, skip_list)
    } else {
        parse_ipv4(& packet, packet_info, &mut stats.lock(), tcp_list, config, skip_list)
    }
}

pub(crate) fn parse_eth(
    packet: &[u8],
    packet_info: &mut PacketInfo,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    skip_list: &SkipList,
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
            dns_parse_slice(packet, offset..)?,
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
        )
    } else if eth_type_field == 0x86dd {
        parse_ipv6(
            dns_parse_slice(packet, offset..)?,
            packet_info,
            stats,
            tcp_list,
            config,
            skip_list,
        )
    } else {
        Err(ParseError::new(Invalid_IP_Version, &format!("{}", &packet[0] >> 4)).into())
    }
}
