use crate::dns_helper::{dns_read_u32, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

fn decode_gpos_size(val: u8) -> String {
    let mut base = u64::from((val & 0xf0) >> 4);
    let exp = usize::from(val & 0x0f);
    if exp < 2 {
        if exp == 1 {
            base *= 10;
        }
        return format!("0.{base}");
    }
    format!("{base}{}", "0".repeat(exp - 2))
}

use std::str::FromStr;

// The struct to hold the parsed binary representation of the LOC record.
// This structure directly maps to the on-the-wire format specified in RFC 1876.
#[derive(Debug, PartialEq, Clone)]
pub struct RR_LOC {
    version: u8,
    size: u8,
    hor_prec: u8,
    ver_prec: u8,
    lat: u32,
    lon: u32,
    alt: u32,
}

impl Default for RR_LOC {
    fn default() -> RR_LOC {
        let default_size_encoded = encode_precision_value(1.0).unwrap_or(0);
        let default_hor_prec_encoded = encode_precision_value(10000.0).unwrap_or(0);
        let default_ver_prec_encoded = encode_precision_value(10.0).unwrap_or(0);

        RR_LOC {
            version: 0,
            size: default_size_encoded,
            hor_prec: default_hor_prec_encoded,
            ver_prec: default_ver_prec_encoded,
            lat:  0x80000000, // Equator (0 degrees latitude)
            lon: 0x80000000, // Prime Meridian (0 degrees longitude)
            alt: (100000.0_f64 * 100.0).round() as u32, // Altitude of 0m, relative to -100000m
        }
    }
}
// A custom error type for parsing failures.
#[derive(Debug, PartialEq, Clone)]
enum ParseError {
    InvalidFormat,
    InvalidNumber(String),
    InvalidDirection,
    InvalidUnit,
    InvalidValue(String),
}

// Helper function to encode size/precision values as per RFC 1876.
// The value is stored as a pair of four-bit unsigned integers,
// representing a base and a power of ten.
fn encode_precision_value(value_m: f64) -> Result<u8, ParseError> {
    if value_m < 0.0 {
        return Err(ParseError::InvalidValue(
            "Precision value cannot be negative.".into(),
        ));
    }

    // Convert meters to centimeters for encoding.
    let value_cm = value_m * 100.0;

    // Find the base and power
    for exp in 0..10 {
        let max_val = 9.0 * 10.0f64.powi(exp);
        if value_cm <= max_val {
            let base = (value_cm / 10.0f64.powi(exp)).ceil() as u8;
            return Ok((base << 4) | exp as u8);
        }
    }
    Err(ParseError::InvalidValue(
        "Precision value too large to encode.".into(),
    ))
}

/// Parses a string representation of a DNS LOC record into an `RR_LOC` struct.
///
/// The function expects the input string to follow the format:
/// "degrees minutes seconds direction degrees minutes seconds direction altitude size `h_prec` `v_prec`"
/// with units (e.g., "m") attached to the last four values.
///
/// Example Input: "34 03 00.000 N 118 14 00.000 W -10.00m 20.00m 5.00m 10.00m"
///
fn parse_loc_record(loc_str: &str) -> Result<RR_LOC, ParseError> {
    let parts: Vec<&str> = loc_str.split_whitespace().collect();
    if parts.len() < 10 {
        return Err(ParseError::InvalidFormat);
    }

    // --- Parsing Latitude ---
    let lat_deg = parts[0]
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber(parts[0].to_string()))?;
    let lat_min = parts[1]
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber(parts[1].to_string()))?;
    let lat_sec = parts[2]
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber(parts[2].to_string()))?;
    let lat_dir = parts[3];

    let lat_seconds = (lat_deg * 3600.0) + (lat_min * 60.0) + lat_sec;
    let mut lat_val = (lat_seconds * 1000.0).round() as u32;

    // RFC 1876: Latitude of the equator is 2^31. North is above, South is below.
    let equator: u32 = 0x80000000;
    if lat_dir == "N" {
        lat_val += equator;
    } else if lat_dir == "S" {
        lat_val = equator - lat_val;
    } else {
        return Err(ParseError::InvalidDirection);
    }

    // --- Parsing Longitude ---
    let lon_deg = parts[4]
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber(parts[4].to_string()))?;
    let lon_min = parts[5]
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber(parts[5].to_string()))?;
    let lon_sec = parts[6]
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber(parts[6].to_string()))?;
    let lon_dir = parts[7];

    let lon_seconds = (lon_deg * 3600.0) + (lon_min * 60.0) + lon_sec;
    let mut lon_val = (lon_seconds * 1000.0).round() as u32;

    // RFC 1876: Longitude of the prime meridian is 2^31. East is above, West is below.
    let prime_meridian: u32 = 0x80000000;
    if lon_dir == "E" {
        lon_val += prime_meridian;
    } else if lon_dir == "W" {
        lon_val = prime_meridian - lon_val;
    } else {
        return Err(ParseError::InvalidDirection);
    }

    // --- Parsing Altitude ---
    let alt_str = parts[8];
    if !alt_str.ends_with('m') {
        return Err(ParseError::InvalidUnit);
    }
    let alt_m = f64::from_str(&alt_str[..alt_str.len() - 1])
        .map_err(|_| ParseError::InvalidNumber(alt_str.to_string()))?;

    // RFC 1876: Altitude is in centimeters, offset by 100,000m.
    let alt_cm = (alt_m + 100000.0) * 100.0;
    let alt_val = alt_cm.round() as u32;

    // --- Parsing Size and Precision ---
    let size_str = parts[9];
    if !size_str.ends_with('m') {
        return Err(ParseError::InvalidUnit);
    }
    let size_m = f64::from_str(&size_str[..size_str.len() - 1])
        .map_err(|_| ParseError::InvalidNumber(size_str.to_string()))?;
    let size_val = encode_precision_value(size_m)?;

    let hor_prec_str = parts.get(10).copied().unwrap_or("10000m");
    if !hor_prec_str.ends_with('m') {
        return Err(ParseError::InvalidUnit);
    }
    let hor_prec_m = f64::from_str(&hor_prec_str[..hor_prec_str.len() - 1])
        .map_err(|_| ParseError::InvalidNumber(hor_prec_str.to_string()))?;
    let hor_prec_val = encode_precision_value(hor_prec_m)?;

    let ver_prec_str = parts.get(11).copied().unwrap_or("10m");
    if !ver_prec_str.ends_with('m') {
        return Err(ParseError::InvalidUnit);
    }
    let ver_prec_m = f64::from_str(&ver_prec_str[..ver_prec_str.len() - 1])
        .map_err(|_| ParseError::InvalidNumber(ver_prec_str.to_string()))?;
    let ver_prec_val = encode_precision_value(ver_prec_m)?;

    // According to RFC 1876, the version is 0.
    Ok(RR_LOC {
        version: 0,
        size: size_val,
        hor_prec: hor_prec_val,
        ver_prec: ver_prec_val,
        lat: lat_val,
        lon: lon_val,
        alt: alt_val,
    })
}

impl RR_LOC {
    #[must_use]
    pub fn new() -> RR_LOC {
        RR_LOC::default()
    }
    pub fn set(&mut self, loc_str: &str) {
        match parse_loc_record(loc_str) {
            Ok(x) => *self = x,
            Err(_) => {
                *self = RR_LOC::new();
            }
        }
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_LOC, Parse_error> {
        let mut a = RR_LOC::new();
        a.version = dns_read_u8(rdata, 0)?;
        if a.version != 0 {
            return Err(Parse_error::new(Invalid_Parameter, "Unknown LOC version"));
        }
        a.size = dns_read_u8(rdata, 1)?;
        a.hor_prec = dns_read_u8(rdata, 2)?;
        a.ver_prec = dns_read_u8(rdata, 3)?;
        a.lat = dns_read_u32(rdata, 4)?;
        a.lon = dns_read_u32(rdata, 8)?;
        a.alt = dns_read_u32(rdata, 12)?;

        Ok(a)
    }
}

impl Display for RR_LOC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (north, east): (char, char);
        let equator: i64 = 1 << 31;
        let mut lat = i64::from(self.lat);
        let mut lon = i64::from(self.lon);
        let alt = i64::from(self.alt);
        if lat > equator {
            north = 'N';
            lat -= equator;
        } else {
            north = 'S';
            lat = equator - lat;
        }
        if lon > equator {
            east = 'E';
            lon -= equator;
        } else {
            east = 'W';
            lon = equator - lon;
        }
        let ho = lon / (1000 * 60 * 60);
        lon %= 1000 * 60 * 60;
        let mo = lon / (1000 * 60);
        lon %= 1000 * 60;
        let so = lon as f64 / 1000.0;
        let ha = lat / (1000 * 60 * 60);
        lat %= 1000 * 60 * 60;
        let ma = lat / (1000 * 60);
        lat %= 1000 * 60;
        let sa = lat as f64 / 1000.0;
        let a = (alt as f64 / 100.0) - 100_000.0;

        write!(
            f,
            "{ha} {ma} {sa} {north} {ho} {mo} {so} {east} {a}m {}m {}m {}m ",
            decode_gpos_size(self.size),
            decode_gpos_size(self.hor_prec),
            decode_gpos_size(self.ver_prec)
        )
    }
}

impl DNSRecord for RR_LOC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::LOC
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.push(self.version);
        bytes.push(self.size);
        bytes.push(self.hor_prec);
        bytes.push(self.ver_prec);
        bytes.extend_from_slice(&self.lat.to_be_bytes());
        bytes.extend_from_slice(&self.lon.to_be_bytes());
        bytes.extend_from_slice(&self.alt.to_be_bytes());
        bytes
    }
}
