use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::dns::{DNS_Class, DNS_RR_type};


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
pub fn base32hex_encode(input: &[u8]) -> String {
    static BASE32HEX_NOPAD: data_encoding::Encoding = data_encoding::BASE32HEX_NOPAD;

    let mut output = String::new();
    let mut enc = BASE32HEX_NOPAD.new_encoder(&mut output);
    enc.append(input);
    enc.finalize();
    return output;
}
pub fn dns_read_u32(packet: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let Some(r) = packet.get(offset..offset + 4) else {
        return Err("Invalid index !".into());
    };
    let val = BigEndian::read_u32(r);
    return Ok(val);
}
