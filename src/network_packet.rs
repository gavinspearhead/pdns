use crate::config::Config;
use crate::dns_helper::{self, dns_parse_slice, dns_read_u16, dns_read_u32};
use crate::dns_packet::parse_dns;
use crate::dns_protocol::DNS_Protocol;
use crate::errors::ParseErrorType::{
    Invalid_DNS_Packet, Invalid_IP_Version, Invalid_IPv4_Header, Invalid_IPv6_Header,
    Invalid_TCP_Header, Invalid_UDP_Header, Packet_Too_Small,
};
use crate::packet_info::Packet_info;
use crate::skiplist::Skip_List;
use crate::statistics::Statistics;
use crate::{errors, tcp_connection};
use errors::Parse_error;
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::debug;
use tcp_connection::TCP_Connections;
use crate::errors::ParseErrorType;

fn parse_tcp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 20 {
        return Err(Parse_error::new(Invalid_TCP_Header, "").into());
    }
    let sp = dns_read_u16(packet, 0)?;
    let dp = dns_read_u16(packet, 2)?;
    if !(matches!(dp, 53 | 5353 | 5355) || matches!(sp, 53 | 5353 | 5355)) {
        return Err(Parse_error::new(Invalid_DNS_Packet, "").into());
    }
    let hl = usize::from((packet[12] >> 4) * 4);
    let len = u32::try_from(packet.len() - hl)?;
    let flags = packet[13];
    //let _wsize = dns_read_u16(packet, 14)?;
    let seq_nr = dns_read_u32(packet, 4)?;

    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(len);

    let dns_data = dns_parse_slice(packet, hl..)?;
    let r = tcp_list.lock().process_data(
        sp,
        dp,
        &packet_info.s_addr,
        &packet_info.d_addr,
        seq_nr,
        dns_data,
        flags,
    );
    if let Some(d) = r {
        let data = d.data();
        let data_len = data.len();
        if data_len == 0 {
            return Ok(());
        }
        stats.tcp += 1;
        let mut offset = 0;
        loop {
            let len = usize::from(dns_read_u16(data, offset)?);
            if len == 0 {
                break;
            }
            offset += 2;
            let in_data = dns_parse_slice(data, offset..offset + len)?;
            match parse_dns(in_data, packet_info, stats, config, skip_list) {
                Ok(..) => {}
                Err(e) => {
                    if let Some(parse_error) = e.downcast_ref::<Parse_error>() {
                        if parse_error.error_type == ParseErrorType::Skipped_Message {
                            stats.skipped += 1;
                        } else {
                            stats.erronous += 1;
                            debug!("Error parsing DNS packet: {:?}", e);
                        }
                    }
                    return Err(e.into());
                }
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
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 8 {
        return Err(Parse_error::new(Invalid_UDP_Header, "").into());
    }
    let sp = dns_read_u16(packet, 0)?;
    let dp = dns_read_u16(packet, 2)?;
    let len = dns_read_u16(packet, 4)?;
    packet_info.set_dest_port(dp);
    packet_info.set_source_port(sp);
    packet_info.set_data_len(u32::from(len) - 8);

    if matches!(dp, 53 | 5353 | 5355) || matches!(sp, 53 | 5353 | 5355) {
        stats.udp += 1;
        match parse_dns( dns_parse_slice(packet, 8..)?, packet_info, stats, config, skip_list, ) {
            Ok(..) => {}
            Err(e) => {
                if let Some(parse_error) = e.downcast_ref::<Parse_error>() {
                    if parse_error.error_type == ParseErrorType::Skipped_Message {
                        stats.skipped += 1;
                    } else {
                        stats.erronous += 1;
                        debug!("Error parsing DNS packet: {:?}", e);
                    }
                }
            }
        }
        Ok(())
    } else {
        Err(Parse_error::new(Invalid_DNS_Packet, &format!("{dp} {sp}")).into())
    }
}

fn parse_ip_data(
    packet: &[u8],
    protocol: u8,
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    if protocol == 6 {
        // TCP
        if config.capture_tcp {
            packet_info.set_protocol(DNS_Protocol::TCP);
            parse_tcp(packet, packet_info, stats, tcp_list, config, skip_list)
        } else {
            Ok(())
        }
    } else if protocol == 17 {
        //  UDP
        packet_info.set_protocol(DNS_Protocol::UDP);
        parse_udp(packet, packet_info, stats, config, skip_list)
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
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    stats.ipv4 += 1;
    if packet.len() < 20 {
        return Err(Parse_error::new(Invalid_IPv4_Header, "").into());
    }
    if packet[0] >> 4 != 4 {
        return Err(Parse_error::new(Invalid_IP_Version, &format!("{:x}", &packet[0] >> 4)).into());
    }
    let ihl = (u16::from(packet[0] & 0xf)) * 4;
    let src = dns_helper::parse_ipv4(&packet[12..16])?;
    let dst = dns_helper::parse_ipv4(&packet[16..20])?;
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
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    if next_header == 4 {
        // IPIP
        if packet.len() < 20 {
            return Err(Parse_error::new(Packet_Too_Small, &format!("{}", packet.len())).into());
            //ip packets are always >= 20 bytes
        }
        let ip_ver = packet[0] >> 4;
        if ip_ver == 4 {
            parse_ipv4(packet, packet_info, stats, tcp_list, config, skip_list)
        } else if ip_ver == 6 {
            parse_ipv6(packet, packet_info, stats, tcp_list, config, skip_list)
        } else {
            Err(Parse_error::new(Invalid_IP_Version, &format!("{ip_ver}")).into())
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
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
) -> Result<(), Box<dyn std::error::Error>> {
    stats.ipv6 += 1;
    if packet.len() < 40 {
        return Err(Parse_error::new(Invalid_IPv6_Header, &format!("{}", packet.len())).into());
    }
    if packet[0] >> 4 != 6 {
        return Err(Parse_error::new(Invalid_IP_Version, &format!("{}", &packet[0] >> 4)).into());
    }

    //    let _len  = dns_read_u16(packet, 4)?;
    let next_header = packet[6];
    let src = dns_helper::parse_ipv6(&packet[8..24])?;
    let dst = dns_helper::parse_ipv6(&packet[24..40])?;
    packet_info.set_dest_ip(dst);
    packet_info.set_source_ip(src);
    parse_tunneling(
        &packet[40..],
        next_header,
        packet_info,
        stats,
        tcp_list,
        config,
        skip_list,
    )
}

pub(crate) fn parse_eth(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
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
        Err(Parse_error::new(Invalid_IP_Version, &format!("{}", &packet[0] >> 4)).into())
    }
}
