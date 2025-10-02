use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_cdnskey::RR_CDNSKEY;

#[derive(Debug, Clone, Default)]
pub struct RR_DNSKEY(RR_CDNSKEY);

impl RR_DNSKEY {
    #[must_use]
    pub fn new() -> Self {
        Self(RR_CDNSKEY::new())
    }

    pub fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        Ok(Self(RR_CDNSKEY::parse(rdata)?))
    }
}

impl DNSRecord for RR_DNSKEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DNSKEY
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.0.to_bytes(names, offset)
    }
}

impl std::ops::Deref for RR_DNSKEY {
    type Target = RR_CDNSKEY;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RR_DNSKEY {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
