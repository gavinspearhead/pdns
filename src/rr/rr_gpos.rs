use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_GPOS {
    lon: Vec<u8>,
    lat: Vec<u8>,
    alt: Vec<u8>,
}

impl RR_GPOS {
    #[must_use]
    pub fn new() -> RR_GPOS {
        RR_GPOS {
            lon: Vec::new(),
            lat: Vec::new(),
            alt: Vec::new(),
        }
    }
    pub fn set(&mut self, lon: &str, lat: &str, alt: &str) {
        self.lon = lon.as_bytes().to_vec();
        self.lat = lat.as_bytes().to_vec();
        self.alt = alt.as_bytes().to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_GPOS, Parse_error> {
        let mut a = RR_GPOS::new();
        let mut offset = 0;
        let lon_len = usize::from(dns_read_u8(rdata, offset)?);
        offset += 1;
        a.lon = dns_parse_slice(rdata, offset..offset + lon_len)?.into();
        offset += lon_len;
        let lat_len = usize::from(dns_read_u8(rdata, offset)?);
        offset += 1;
        a.lat = dns_parse_slice(rdata, offset..offset + lat_len)?.into();
        offset += lat_len;
        let alt_len = usize::from(dns_read_u8(rdata, offset)?);
        offset += 1;
        a.alt = dns_parse_slice(rdata, offset..offset + alt_len)?.into();
        Ok(a)
    }
}

impl Display for RR_GPOS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            parse_dns_str(&self.lon).unwrap_or_default(),
            parse_dns_str(&self.lat).unwrap_or_default(),
            parse_dns_str(&self.alt).unwrap_or_default()
        )
    }
}

impl DNSRecord for RR_GPOS {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::GPOS
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.lon.len() as u8);
        result.extend_from_slice(&self.lon);
        result.push(self.lat.len() as u8);
        result.extend_from_slice(&self.lat);
        result.push(self.alt.len() as u8);
        result.extend_from_slice(&self.alt);
        result
    }
}
