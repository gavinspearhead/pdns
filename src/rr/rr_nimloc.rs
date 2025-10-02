use crate::rr::rr_nsap::RR_NSAP;

use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;

#[derive(Debug, Clone, Default)]
pub struct RR_NIMLOC(RR_NSAP);

impl RR_NIMLOC {
    #[must_use]
    pub fn new() -> Self {
        RR_NIMLOC(RR_NSAP::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(RR_NIMLOC(RR_NSAP::parse(rdata)?))
    }

    pub fn set(&mut self, data: &[u8]) {
        self.0.set(data);
    }
}

impl DNSRecord for RR_NIMLOC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NIMLOC
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_NIMLOC {
    type Target = RR_NSAP;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_NIMLOC {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
