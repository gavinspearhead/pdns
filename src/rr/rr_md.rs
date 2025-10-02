use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_mb::RR_MB;

#[derive(Debug, Clone, Default)]
pub struct RR_MD(RR_MB);

impl RR_MD {
    #[must_use]
    pub fn new() -> Self {
        RR_MD(RR_MB::new())
    }

    pub fn parse(rdata: &[u8], offset: usize) -> Result<Self, Parse_error> {
        Ok(RR_MD(RR_MB::parse(rdata, offset)?))
    }

    pub fn set(&mut self, domain: &str) {
        self.0.set(domain);
    }
}

impl DNSRecord for RR_MD {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MD
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_MD {
    type Target = RR_MB;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_MD {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
