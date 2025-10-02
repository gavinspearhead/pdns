use crate::rr::rr_cds::RR_CDS;

use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;

#[derive(Debug, Clone, Default)]
pub struct RR_TA(RR_CDS);

impl RR_TA {
    #[must_use]
    pub fn new() -> Self {
        RR_TA(RR_CDS::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(RR_TA(RR_CDS::parse(rdata)?))
    }

    pub fn set(&mut self, key_id: u16, alg: u8, dig_t: u8, dig: &[u8]) {
        self.0.set(key_id, alg, dig_t, dig);
    }
}

impl DNSRecord for RR_TA {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::TA
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_TA {
    type Target = RR_CDS;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_TA {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
