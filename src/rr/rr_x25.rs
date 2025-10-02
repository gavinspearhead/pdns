use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_X25 {
    addr: String,
}

impl RR_X25 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, address: &str) {
        self.addr = address.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_X25, Parse_error> {
        let len = usize::from(dns_read_u8(rdata, 0)?);
        if len + 1 != rdata.len() {
            return Err(Parse_error::new(Invalid_Parameter, "Invalid X25 format"));
        }
        let addr = dns_parse_slice(rdata, 1..=len)?;
        let mut a = RR_X25::new();
        a.addr = parse_dns_str(addr)?;
        Ok(a)
    }
}

impl Display for RR_X25 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl DNSRecord for RR_X25 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::X25
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.push(self.addr.len() as u8);
        res.extend_from_slice(self.addr.as_bytes());
        res
    }
}
