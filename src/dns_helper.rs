use crate::dns::{DNS_Class, DNS_RR_type};
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, NaiveDateTime, Utc};

pub fn parse_protocol(proto: u8) -> Result<String, Box<dyn std::error::Error>> {
    match proto {
        17 => {
            return Ok("UDP".into());
        }
        6 => {
            return Ok("TCP".into());
        }
        _ => {
            return Err("Unknown protocol".into());
        }
    }
}

pub fn parse_rrtype(rrtype: u16) -> Result<DNS_RR_type, Box<dyn std::error::Error>> {
    return DNS_RR_type::find(rrtype);
}

pub fn parse_class(class: u16) -> Result<DNS_Class, Box<dyn std::error::Error>> {
    return DNS_Class::find(class);
}

pub fn timestame_to_str(timestamp: u32) -> Result<String, Box<dyn std::error::Error>> {
    let Some(naive_datetime) = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0) else {
        return Err("Cannot parse timestamp".into());
    };
    let datetime_again: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive_datetime, Utc);
    return Ok(datetime_again.to_string());
}

pub fn dns_read_u64(packet: &[u8], offset: usize) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 8) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u64(r);
    return Ok(val);
}
pub fn dns_read_u16(packet: &[u8], offset: usize) -> Result<u16, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 2) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u16(r);
    return Ok(val);
}

pub fn dns_read_u8(packet: &[u8], offset: usize) -> Result<u8, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset) else {
        return Err("Invalid index !".into());
    };
    return Ok(*r);
}
pub fn dns_read_u32(packet: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 4) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u32(r);
    return Ok(val);
}
pub fn base32hex_encode(input: &[u8]) -> String {
    static BASE32HEX_NOPAD: data_encoding::Encoding = data_encoding::BASE32HEX_NOPAD;
    let mut output = String::new();
    let mut enc = BASE32HEX_NOPAD.new_encoder(&mut output);
    enc.append(input);
    enc.finalize();
    return output;
}

#[cfg(test)]
mod tests {
    use crate::dns_helper::{dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8};

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
