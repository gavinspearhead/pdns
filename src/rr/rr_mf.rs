use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_mb::RR_MB;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_MF {
    inner: RR_MB,
}

impl RR_MF {
    #[must_use]
    pub fn new() -> RR_MF {
        RR_MF::default()
    }

    pub fn set(&mut self, madname: &str) {
        self.inner.set(madname);
    }

    pub(crate) fn parse(rdata: &[u8], offset: usize) -> Result<RR_MF, Parse_error> {
        Ok(RR_MF {
            inner: RR_MB::parse(rdata, offset)?,
        })
    }
}

impl Display for RR_MF {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl DNSRecord for RR_MF {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MF
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.inner.to_bytes(names, offset)
    }
}
