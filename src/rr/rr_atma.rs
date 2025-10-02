use crate::dns_helper::{dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_ATMA {
    format: u8,
    address: Vec<u8>,
}

impl RR_ATMA {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, format: u8, address: &[u8]) {
        self.format = format;
        self.address = address.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_ATMA, Parse_error> {
        let mut rr = RR_ATMA::new();
        rr.format = dns_read_u8(rdata, 0)?;
        rr.address = rdata[1..].to_vec();
        Ok(rr)
    }
}

impl Display for RR_ATMA {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.format, hex::encode(&self.address))
    }
}

impl DNSRecord for RR_ATMA {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::ATMA
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(&self.format.to_be_bytes());
        res.extend_from_slice(self.address.as_slice());
        res
    }
}
