use crate::dns_rr::RR_TXT;

use crate::dns_helper::names_list;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;

#[derive(Debug, Clone, Default)]
pub struct RR_UINFO(RR_TXT);

impl RR_UINFO {
    #[must_use]
    pub fn new() -> Self {
        RR_UINFO(RR_TXT::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, ParseError> {
        Ok(RR_UINFO(RR_TXT::parse(rdata)?))
    }

    pub fn set(&mut self, txt: &str) {
        self.0.set(txt);
    }
}

impl DnsRecord for RR_UINFO {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::UINFO
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_UINFO {
    type Target = RR_TXT;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_UINFO {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
