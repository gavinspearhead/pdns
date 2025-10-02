use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_cds::RR_CDS;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_DS {
    inner: RR_CDS,
}

impl RR_DS {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) {
        self.inner.set(key_tag, algorithm, digest_type, digest);
    }

    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_DS, Parse_error> {
        Ok(RR_DS {
            inner: RR_CDS::parse(rdata)?,
        })
    }
}

impl Display for RR_DS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl DNSRecord for RR_DS {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DS
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.inner.to_bytes(names, offset)
    }
}
