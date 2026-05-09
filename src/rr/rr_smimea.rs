use crate::rr::rr_tlsa::RR_TLSA;

use crate::dns_helper::names_list;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct RR_SMIMEA(RR_TLSA);

impl RR_SMIMEA {
    #[must_use]
    pub fn new() -> Self {
        RR_SMIMEA(RR_TLSA::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, ParseError> {
        Ok(RR_SMIMEA(RR_TLSA::parse(rdata)?))
    }

    pub fn set(&mut self, certificate_usage: u8, selector: u8, alg_type: u8, cad: &[u8]) {
        self.0.set(certificate_usage, selector, alg_type, cad);
    }
}

impl DnsRecord for RR_SMIMEA {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::SMIMEA
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_SMIMEA {
    type Target = RR_TLSA;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_SMIMEA {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
