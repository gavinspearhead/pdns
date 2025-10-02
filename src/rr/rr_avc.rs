use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr::RR_TXT;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;

#[derive(Debug, Clone, Default)]
pub struct RR_AVC(RR_TXT);

impl RR_AVC {
    #[must_use]
    pub fn new() -> Self {
        Self(RR_TXT::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(Self(RR_TXT::parse(rdata)?))
    }

    pub fn set(&mut self, text: &str) {
        self.0.set(text);
    }
}

impl DNSRecord for RR_AVC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::AVC
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_AVC {
    type Target = RR_TXT;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_AVC {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
