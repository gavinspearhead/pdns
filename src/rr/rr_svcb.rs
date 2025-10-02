use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_https::{HttpsSvcParam, RR_HTTPS};

#[derive(Debug, Clone, Default)]
pub struct RR_SVCB(RR_HTTPS);

impl RR_SVCB {
    #[must_use]
    pub fn new() -> Self {
        RR_SVCB(RR_HTTPS::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(RR_SVCB(RR_HTTPS::parse(rdata,)?))
    }

    pub fn set(&mut self, domain: &str, prio:u16, params: &[HttpsSvcParam]) {
        self.0.set(domain, prio, params);
    }
}

impl DNSRecord for RR_SVCB {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SVCB
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::fmt::Display for RR_SVCB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
