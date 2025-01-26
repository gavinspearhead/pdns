use crate::errors::ParseErrorType::{Invalid_DNS_Packet, Invalid_packet_index, Invalid_timestamp};
use crate::{
    dns::{DNS_Class, DNS_RR_type},
    errors::{DNS_error, Parse_error},
};
use byteorder::{BigEndian, ByteOrder as _};
use chrono::DateTime;
use data_encoding::BASE32HEX_NOPAD;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeBounds;
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

pub(crate) fn base32hex_encode(input: &[u8]) -> String {
    BASE32HEX_NOPAD.encode(input)
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
