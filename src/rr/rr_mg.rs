use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use crate::rr::rr_mb::RR_MB;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_MG {
    mb: RR_MB,
}

impl RR_MG {
    #[must_use]
    pub fn new() -> RR_MG {
        RR_MG { mb: RR_MB::new() }
    }

    pub fn set(&mut self, madname: &str) {
        self.mb.set(madname);
    }

    pub(crate) fn parse(rdata: &[u8], offset: usize) -> Result<RR_MG, Parse_error> {
        Ok(RR_MG {
            mb: RR_MB::parse(rdata, offset)?,
        })
    }
}

impl Display for RR_MG {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mb)
    }
}

impl DNSRecord for RR_MG {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MG
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.mb.to_bytes(names, offset)
    }
}
