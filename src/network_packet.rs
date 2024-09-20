use crate::config::Config;
use crate::dns_helper::{
    self,  dns_read_u16, dns_read_u32, 
};
use crate::dns_packet::{parse_dns, DNS_Protocol};
use crate::packet_info::Packet_info;
use crate::skiplist::Skip_List;
use crate::statistics::Statistics;
use errors::Parse_error;
use std::sync::{Arc, Mutex};
use tcp_connection::TCP_Connections;

use crate::{ errors,  tcp_connection};


fn parse_tcp(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
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
    skip_list: &Skip_List,
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
    skip_list: &Skip_List,
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
    skip_list: &Skip_List,
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
    let src = dns_helper::parse_ipv4(&packet[12..16])?;
    let dst = dns_helper::parse_ipv4(&packet[16..20])?;
    let len: u16 = dns_read_u16(packet, 2)? - ihl;
    let next_header = packet[9];
    packet_info.set_dest_ip(dst);
    packet_info.set_source_ip(src);
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
    skip_list: &Skip_List,
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
            parse_ipv4(
                packet,
                packet_info,
                stats,
                tcp_list,
                config,
                skip_list,
                publicsuffixlist,
            )
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
    skip_list:&Skip_List, 
    publicsuffixlist: &publicsuffix::List,
) -> Result<(), Box<dyn std::error::Error>> {
    if packet.len() < 40 {
        return Err(Parse_error::new(
            errors::ParseErrorType::Invalid_IPv6_Header,
            &format!("{}", packet.len()),
        )
        .into());
    }
    if packet[0] >> 4 != 6 {
        return Err(Parse_error::new(
            errors::ParseErrorType::Invalid_IP_Version,
            &format!("{}", &packet[0] >> 4),
        )
        .into());
    }

    let _len: u16 = dns_read_u16(packet, 4)?;
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
        publicsuffixlist,
    )
}

pub(crate) fn parse_eth(
    packet: &[u8],
    packet_info: &mut Packet_info,
    stats: &mut Statistics,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    skip_list: &Skip_List,
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