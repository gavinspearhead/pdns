use crate::rr::rr_null::RR_NULL;
use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;

#[derive(Debug, Clone, Default)]
pub struct RR_UNSPEC(RR_NULL);

impl RR_UNSPEC {
    #[must_use]
    pub fn new() -> Self {
        RR_UNSPEC(RR_NULL ::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(RR_UNSPEC(RR_NULL::parse(rdata)?))
    }

    pub fn set(&mut self, txt: &[u8]) {
        self.0.set(txt);
    }
}

impl DNSRecord for RR_UNSPEC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::UNSPEC
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_UNSPEC {
    type Target = RR_NULL;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_UNSPEC {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
