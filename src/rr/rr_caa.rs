use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::{ParseErrorType, Parse_error};
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
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_CAA, Parse_error> {
        let mut caa = RR_CAA::new();
        caa.flag = dns_read_u8(rdata, 0)?;
        let tag_len = usize::from(dns_read_u8(rdata, 1)?);
        let r = dns_parse_slice(rdata, 2..2 + tag_len)?;
        let Ok(tag) = std::str::from_utf8(r) else {
            return Err(Parse_error::new(ParseErrorType::Invalid_DNS_Packet, ""));
        };
        caa.tag = tag.to_string();
        let r = dns_parse_slice(rdata, 2 + tag_len..)?;
        caa.value = parse_dns_str(r)?;
        Ok(caa)
    }
}

impl Display for RR_CAA {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.flag, self.tag, self.value)
    }
}

impl DNSRecord for RR_CAA {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::CAA
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.flag);
        result.push(self.tag.len() as u8);
        result.extend_from_slice(self.tag.as_bytes());
        result.extend_from_slice(self.value.as_bytes());
        result
    }
}
