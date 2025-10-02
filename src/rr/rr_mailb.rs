use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_maila::RR_MAILA;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct RR_MAILB(RR_MAILA);

impl RR_MAILB {
    #[must_use]
    pub fn new() -> Self {
        RR_MAILB(RR_MAILA::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(RR_MAILB(RR_MAILA::parse(rdata)?))
    }

    pub fn set(&mut self, addr: Ipv4Addr) {
        self.0.set(addr);
    }
}
impl DNSRecord for RR_MAILB {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MAILB
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.0.addr.octets().to_vec()
    }
}

impl Display for RR_MAILB {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.addr)
    }
}
