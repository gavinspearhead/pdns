use crate::dns_helper::names_list;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use crate::rr::rr_https::{HttpsSvcParam, RR_HTTPS};
use crate::statistics::Statistics;

#[derive(Debug, Clone, Default)]
pub struct RR_SVCB(RR_HTTPS);

impl RR_SVCB {
    #[must_use]
    pub fn new() -> Self {
        RR_SVCB(RR_HTTPS::new())
    }

    pub(crate) fn parse(rdata: &[u8], statistics: &mut Statistics) -> Result<Self, ParseError> {
        Ok(RR_SVCB(RR_HTTPS::parse(rdata, statistics)?))
    }

    pub(crate) fn set(&mut self, domain: &str, prio: u16, params: &[HttpsSvcParam]) {
        self.0.set(domain, prio, params);
    }
}

impl DnsRecord for RR_SVCB {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::SVCB
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
