use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_mb::RR_MB;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_MR {
    mb: RR_MB,
}

impl RR_MR {
    #[must_use]
    pub fn new() -> RR_MR {
        RR_MR::default()
    }

    pub fn set(&mut self, mb: &str) {
        self.mb.set(mb);
    }

    pub(crate) fn parse(rdata: &[u8], offset: usize) -> Result<RR_MR, Parse_error> {
        Ok(RR_MR {
            mb: RR_MB::parse(rdata, offset)?,
        })
    }
}

impl Display for RR_MR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mb)
    }
}

impl DNSRecord for RR_MR {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MR
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.mb.to_bytes(names, offset)
    }
}
