use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_cds::RR_CDS;

#[derive(Debug, Clone, Default)]
pub struct RR_DLV(RR_CDS);

impl RR_DLV {
    #[must_use]
    pub fn new() -> Self {
        Self(RR_CDS::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(Self(RR_CDS::parse(rdata)?))
    }

    pub fn set(&mut self, key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) {
        self.0.set(key_tag, algorithm, digest_type, digest);
    }
}

impl DNSRecord for RR_DLV {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DLV
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_DLV {
    type Target = RR_CDS;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_DLV {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
