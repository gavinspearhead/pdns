use crate::dns_helper::{dns_parse_slice, dns_read_u8, parse_dns_str, NamesList};
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub(crate) struct RR_CAA {
    flag: u8,
    tag: String,
    value: String,
}

impl RR_CAA {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, flag: u8, tag: &str, value: &str) {
        self.flag = flag;
        self.tag = tag.to_string();
        self.value = value.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<Self, ParseError> {
        let mut caa = Self::new();
        caa.flag = dns_read_u8(rdata, 0)?;
        let tag_len = usize::from(dns_read_u8(rdata, 1)?);
        let tag = dns_parse_slice(rdata, 2..2 + tag_len)?;
        caa.tag = parse_dns_str(tag)?;
        let value = dns_parse_slice(rdata, 2 + tag_len..)?;
        caa.value = parse_dns_str(value)?;
        Ok(caa)
    }
}

impl Display for RR_CAA {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.flag, self.tag, self.value)
    }
}

impl DnsRecord for RR_CAA {
    #[inline]
    fn get_type(&self) -> DnsRRType {
        DnsRRType::CAA
    }
    fn to_bytes(&self, _names: &mut NamesList, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.flag);
        result.push(self.tag.len() as u8);
        result.extend_from_slice(self.tag.as_bytes());
        result.extend_from_slice(self.value.as_bytes());
        result
    }
}
