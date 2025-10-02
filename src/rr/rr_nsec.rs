use crate::dns_helper::{
    dns_format_name, dns_parse_slice, map_bitmap_to_rr, names_list, parse_nsec_bitmap_vec,
    process_bitmap,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct RR_NSEC {
    domain: String,
    bitmap: Vec<u16>,
}

impl Default for RR_NSEC {
    fn default() -> Self {
        Self::new()
    }
}

impl RR_NSEC {
    #[must_use]
    pub fn new() -> RR_NSEC {
        RR_NSEC {
            domain: String::new(),
            bitmap: Vec::new(),
        }
    }
    pub fn set(&mut self, domain: String, bitmap: Vec<DNS_RR_type>) {
        self.domain = domain;
        let mut sorted_bitmap = bitmap;
        sorted_bitmap.sort_by_key(|x| u16::from(*x));
        self.bitmap = sorted_bitmap.iter().map(u16::from).collect();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NSEC, Parse_error> {
        let mut a = RR_NSEC::new();
        let mut offset = 0;
        (a.domain, offset) = dns_parse_name(rdata, offset)?;
        a.bitmap = parse_nsec_bitmap_vec(dns_parse_slice(rdata, offset..)?)?;
        Ok(a)
    }
}

impl Display for RR_NSEC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bitmap_str = map_bitmap_to_rr(&self.bitmap).unwrap_or_default();
        write!(f, "{} {bitmap_str}", self.domain)
    }
}

impl DNSRecord for RR_NSEC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NSEC
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.append(&mut dns_format_name(&self.domain, names, offset));
        let bitmap_bytes = process_bitmap(&self.bitmap);
        res.extend_from_slice(&bitmap_bytes);

        res
    }
}
