use crate::dns_class::DNS_Class;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::{
    Invalid_DNS_Packet, Invalid_Parameter, Invalid_packet_index, Invalid_timestamp,
};
use crate::errors::{DNS_error, Parse_error};
use byteorder::{BigEndian, ByteOrder as _};
use chrono::DateTime;
use data_encoding::BASE32HEX_NOPAD;
use log::debug;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeBounds;
// Add this at the top of the file
/*
#[inline]
pub(crate) fn is_between<T: PartialOrd>(value: &T, min: &T, max: &T) -> bool {
    value >= min && value <= max
}*/

#[inline]
pub(crate) fn parse_rrtype(rrtype: u16) -> Result<DNS_RR_type, DNS_error> {
    DNS_RR_type::find(rrtype)
}

#[inline]
pub(crate) fn parse_class(class: u16) -> Result<DNS_Class, DNS_error> {
    DNS_Class::find(class)
}

pub(crate) fn timestamp_to_str(timestamp: u32) -> Result<String, Parse_error> {
    let Some(dt) = DateTime::from_timestamp(i64::from(timestamp), 0) else {
        return Err(Parse_error::new(Invalid_timestamp, &timestamp.to_string()));
    };
    Ok(dt.to_string())
}

pub(crate) fn dns_read_u128(packet: &[u8], offset: usize) -> Result<u128, Parse_error> {
    let Some(r) = packet.get(offset..offset + 16) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(BigEndian::read_u128(r))
}
pub(crate) fn dns_read_u48(packet: &[u8], offset: usize) -> Result<u64, Parse_error> {
    let Some(r) = packet.get(offset..offset + 6) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(BigEndian::read_u48(r))
}

pub(crate) fn dns_read_u64(packet: &[u8], offset: usize) -> Result<u64, Parse_error> {
    let Some(r) = packet.get(offset..offset + 8) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(BigEndian::read_u64(r))
}

pub(crate) fn dns_read_u32(packet: &[u8], offset: usize) -> Result<u32, Parse_error> {
    let Some(r) = packet.get(offset..offset + 4) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(BigEndian::read_u32(r))
}

pub(crate) fn dns_read_u16(packet: &[u8], offset: usize) -> Result<u16, Parse_error> {
    let Some(r) = packet.get(offset..offset + 2) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(BigEndian::read_u16(r))
}

pub(crate) fn dns_read_u8(packet: &[u8], offset: usize) -> Result<u8, Parse_error> {
    let Some(&r) = packet.get(offset) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(r)
}

pub fn dns_append_u64(data: &mut Vec<u8>, value: u64) {
    data.extend_from_slice(&value.to_be_bytes());
}

pub fn dns_append_u32(data: &mut Vec<u8>, value: u32) {
    data.extend_from_slice(&value.to_be_bytes());
}

pub fn dns_append_u16(data: &mut Vec<u8>, value: u16) {
    data.extend_from_slice(&value.to_be_bytes());
}

pub fn dns_append_u8(data: &mut Vec<u8>, value: u8) {
    data.extend_from_slice(&value.to_be_bytes());
}
#[inline]
pub(crate) fn base32hex_encode(input: &[u8]) -> String {
    BASE32HEX_NOPAD.encode(input)
}

pub fn parse_nsec_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Parse_error> {
    let len = bitmap.len();
    let mut res: Vec<u16> = Vec::new();
    let mut offset = 0;
    while offset < len {
        let high_byte = (u16::from(dns_read_u8(bitmap, offset)?)) << 8;
        let size = usize::from(dns_read_u8(bitmap, offset + 1)?);
        for i in 0..size {
            let mut pos: u8 = 0x80;
            for j in 0..8 {
                if dns_read_u8(bitmap, offset + 2 + i)? & pos != 0 {
                    let Ok(x) = (usize::from(high_byte) | ((8 * i) + j)).try_into() else {
                        return Err(Parse_error::new(Invalid_Parameter, ""));
                    };
                    res.push(x);
                }
                pos >>= 1;
            }
        }
        offset += size + 2;
    }
    Ok(res)
}

pub fn map_bitmap_to_rr(bitmap: &[u16]) -> Result<String, Parse_error> {
    let mut res = String::new();
    for i in bitmap {
        let Ok(x) = DNS_RR_type::find(*i) else {
            return Err(Parse_error::new(Invalid_Parameter, ""));
        };
        write!(res, "{x} ").map_err(|_| Parse_error::new(Invalid_Parameter, ""))?;
    }
    Ok(res)
}

pub fn parse_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Parse_error> {
    let mut res: Vec<u16> = Vec::new();
    for (i, item) in bitmap.iter().enumerate() {
        let mut pos: u8 = 0x80;
        for j in 0..8 {
            if item & pos != 0 {
                let Ok(x) = ((8 * i) + j).try_into() else {
                    return Err(Parse_error::new(Invalid_Parameter, ""));
                };
                res.push(x);
            }
            pos >>= 1;
        }
    }
    Ok(res)
}

pub fn build_bitmap_from_vec(indices: &[u16]) -> Result<Vec<u8>, Parse_error> {
    if indices.is_empty() {
        return Ok(Vec::new());
    }

    // Find the highest bit index to size the bitmap
    let &max_idx = indices.iter().max().unwrap();
    let needed_len = (usize::from(max_idx) / 8) + 1;
    let mut bitmap = vec![0u8; needed_len];

    // Set bits (MSB-first in each byte, same as parse_bitmap_vec expects)
    for &idx in indices {
        let idx_usize = usize::from(idx);
        let byte = idx_usize / 8;
        let bit_in_byte = idx_usize % 8; // 0..=7
        let shift = 7u8 - (bit_in_byte as u8);
        bitmap[byte] |= 1u8 << shift;
    }

    Ok(bitmap)
}
#[must_use]
pub fn process_bitmap(bitmap: &Vec<u16>) -> Vec<u8> {
    let mut bitmap_bytes = Vec::new();
    let mut window_bytes = Vec::new();
    let mut current_window = bitmap[0] >> 8;

    for &rr_type in bitmap {
        let window = rr_type >> 8;
        if window != current_window {
            if !window_bytes.is_empty() {
                bitmap_bytes.push(current_window as u8);
                bitmap_bytes.push(window_bytes.len() as u8);
                bitmap_bytes.extend_from_slice(&window_bytes);
            }
            current_window = window;
            window_bytes.clear();
        }
        let byte_offset = (rr_type & 0xFF) / 8;
        while window_bytes.len() <= byte_offset as usize {
            window_bytes.push(0);
        }
        window_bytes[byte_offset as usize] |= 1 << (7 - (rr_type & 0x07));
    }

    if !window_bytes.is_empty() {
        bitmap_bytes.push(current_window as u8);
        bitmap_bytes.push(window_bytes.len() as u8);
        bitmap_bytes.extend_from_slice(&window_bytes);
    }

    bitmap_bytes
}

pub(crate) fn dns_parse_slice<T>(packet: &[u8], range: T) -> Result<&[u8], Parse_error>
where
    T: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        std::ops::Bound::Included(&s) => s,
        std::ops::Bound::Excluded(&s) => s + 1,
        std::ops::Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        std::ops::Bound::Included(&e) => e + 1,
        std::ops::Bound::Excluded(&e) => e,
        std::ops::Bound::Unbounded => packet.len(),
    };

    if start <= end && end <= packet.len() {
        Ok(&packet[start..end])
    } else {
        Err(Parse_error::new(Invalid_packet_index, ""))
    }
}

pub(crate) fn parse_dns_str(rdata: &[u8]) -> Result<String, Parse_error> {
    if let Ok(x) = std::str::from_utf8(rdata) {
        Ok(x.to_owned())
    } else {
        Err(Parse_error::new(Invalid_DNS_Packet, ""))
    }
}

pub(crate) fn parse_ipv4(data: &[u8]) -> Result<IpAddr, Parse_error> {
    let r: [u8; 4] = match data.try_into() {
        Ok(x) => x,
        Err(_) => {
            return Err(Parse_error::new(Invalid_DNS_Packet, ""));
        }
    };
    Ok(IpAddr::V4(Ipv4Addr::from(r)))
}

pub(crate) fn parse_ipv6(data: &[u8]) -> Result<IpAddr, Parse_error> {
    let r: [u8; 16] = match data.try_into() {
        Ok(x) => x,
        Err(_) => {
            return Err(Parse_error::new(Invalid_DNS_Packet, ""));
        }
    };
    Ok(IpAddr::V6(Ipv6Addr::from(r)))
}
#[derive(Debug, Clone)]
struct elem {
    name: String,
    pos: usize,
}

impl elem {
    fn new(name: &str, pos: usize) -> elem {
        elem {
            name: name.to_string(),
            pos,
        }
    }
}
#[derive(Debug, Clone, Default)]
pub struct names_list {
    name_list: Vec<elem>,
}

impl names_list {
    #[must_use]
    pub fn new() -> names_list {
        names_list { name_list: vec![] }
    }

    pub(crate) fn add(&mut self, name: &str, pos: usize) {
        self.name_list.push(elem::new(name, pos));
    }
    pub(crate) fn find_longest_match(&self, name: &str) -> (usize, usize) {
        let mut longest = Vec::new();
        let parts: Vec<&str> = name.split('.').collect();
        let mut pos = 0;
        for x in &self.name_list {
            let mut common_suffix = Vec::new();
            let xparts: Vec<&str> = x.name.split('.').collect();
            for (a, b) in parts.iter().rev().zip(xparts.iter().rev()) {
                if a == b {
                    common_suffix.push(*a);
                } else {
                    break;
                }
            }
            if longest.join("").len() < common_suffix.join("").len() {
                longest = common_suffix;
                // println!("{} {} {} {}", x.name.len(), longest.join(".").len(), x.name, longest.join(""));
                pos = x.pos + (x.name.len() - longest.join(".").len());
            }
        }
        longest.reverse();
        let suf = longest.join(".");
        //println!("suffix {suf} pos {pos}");
        (suf.len(), pos)
    }
}

mod tests_names_list {
    use crate::dns_helper::names_list;

    #[test]
    fn test_dns_rr() {
        let mut n = names_list::new();
        n.add("www.homes.com", 1);
        n.add("www.home.com", 1);
        n.add("www.future.com", 1);

        assert_eq!(n.find_longest_match("intra.home.com"), (8, 1));
    }
}

pub(crate) fn dns_format_name(name_in: &str, names: &mut names_list, pos_in: usize) -> Vec<u8> {
    debug_assert!(name_in.len() <= 255 && !name_in.is_empty());

    let mut res: Vec<u8> = Vec::with_capacity(name_in.len() + 2);
    debug!("{names:?}");

    let mut name = name_in.trim_end_matches('.');
    let (len, pos) = names.find_longest_match(name);
    if len != 0 {
        name = &name[0..name.len() - len];
    } else {
        names.add(name_in, pos_in);
    }
    debug!("name now is : {name}");
    let parts: Vec<&str> = name.split('.').collect();
    debug!("name parts is: {parts:?}");
    for x in parts {
        debug_assert!(x.len() <= 63);
        debug!("x: {} {x}", x.len());
        if !x.is_empty() {
            res.push(x.len() as u8);
            // res.push(0xc0);
            res.append(x.as_bytes().to_vec().as_mut());
        }
    }
    if len != 0 {
        let ptr = 0xc000 | (pos as u16);
        res.push((ptr >> 8) as u8);
        res.push((ptr & 0xff) as u8);
    } else {
        res.push(0);
    }
    debug!("RES now is: {res:x?}");
    res
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use crate::dns_helper::{dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8};

    use super::{parse_ipv4, parse_ipv6};

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(
            parse_ipv4(&[192, 168, 178, 254]).unwrap(),
            Ipv4Addr::from_str("192.168.178.254").unwrap()
        );
        assert_eq!(
            parse_ipv4(&[130, 89, 1, 1]).unwrap(),
            Ipv4Addr::from_str("130.89.1.1").unwrap()
        );
        assert!(parse_ipv4(&[130, 89, 1]).is_err());
        assert!(parse_ipv4(&[89, 1]).is_err());
    }
    #[test]
    fn test_parse_ipv6() {
        assert_eq!(
            parse_ipv6(&[
                0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0xc0, 0x4d, 0xff, 0xfe, 0xaf, 0x86,
                0x31
            ])
            .unwrap(),
            Ipv6Addr::from_str("fe80:0:0:0:1ac0:4dff:feaf:8631").unwrap()
        );
        assert!(parse_ipv6(&[
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0xc0, 0x4d, 0xff, 0xfe, 0xaf, 0x86, 0x31
        ])
        .is_err());
        assert!(
            parse_ipv6(&[0x0, 0x0, 0x0, 0x1a, 0xc0, 0x4d, 0xff, 0xfe, 0xaf, 0x86, 0x31]).is_err()
        );
    }

    #[test]
    fn test_dns_read_u32() {
        assert_eq!(
            dns_read_u32(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 0).unwrap(),
            0xdeadbeef
        );
        assert_eq!(
            dns_read_u32(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 4).unwrap(),
            0xcafebabe
        );
        assert!(dns_read_u32(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 7).is_err());
    }
    #[test]
    fn test_dns_read_u16() {
        assert_eq!(
            dns_read_u16(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 2).unwrap(),
            0xbeef
        );
        assert_eq!(
            dns_read_u16(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 4).unwrap(),
            0xcafe
        );
        assert!(dns_read_u16(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 7).is_err());
    }
    #[test]
    fn test_dns_read_u8() {
        assert_eq!(
            dns_read_u8(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 2).unwrap(),
            0xbe
        );
        assert_eq!(
            dns_read_u8(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 5).unwrap(),
            0xfe
        );
        assert!(dns_read_u8(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 8).is_err());
    }
    #[test]
    fn test_dns_read_u64() {
        assert_eq!(
            dns_read_u64(
                &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x23, 0x45, 0x67],
                2
            )
            .unwrap(),
            0xbeefcafebabe1223
        );
        assert_eq!(
            dns_read_u64(
                &[
                    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x23, 0x45, 0x67, 0x89,
                    0xaa
                ],
                5
            )
            .unwrap(),
            0xfebabe1223456789
        );
        assert!(dns_read_u64(
            &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x23, 0x45, 0x67, 0x89, 0xaa],
            15
        )
        .is_err());
    }
}

use std::collections::BTreeMap;

pub(crate) fn encode_nsec3_bitmap(rr_types: &[u16]) -> Vec<u8> {
    let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

    for &rr_type in rr_types {
        let window = (rr_type / 256) as u8;
        let offset = (rr_type % 256) as usize;
        let byte_index = offset / 8;
        let bitmap = windows.entry(window).or_insert_with(|| vec![0u8; 32]);
        let bit_position = 7 - (offset % 8); // MSB is bit 0

        if byte_index >= bitmap.len() {
            bitmap.resize(byte_index + 1, 0);
        }

        bitmap[byte_index] |= 1 << bit_position;
    }

    // Assemble the final result
    let mut result = Vec::new();
    for (window, bitmap) in windows {
        let length = bitmap.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        result.push(window);
        result.push(length as u8);
        result.extend_from_slice(&bitmap[..length]);
    }

    result
}
