use crate::dns_rr::RR_TXT;


use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;

#[derive(Debug, Clone, Default)]
pub struct RR_UINFO(RR_TXT);

impl RR_UINFO {
    #[must_use]
    pub fn new() -> Self {
        RR_UINFO(RR_TXT::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(RR_UINFO(RR_TXT::parse(rdata)?))
    }

    pub fn set(&mut self, txt: &str) {
        self.0.set(txt);
    }
}

impl DNSRecord for RR_UINFO {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::UINFO
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
