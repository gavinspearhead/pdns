use crate::dns_helper::names_list;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use crate::rr::rr_mb::RR_MB;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
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

    pub(crate) fn parse(packet: &[u8], offset: usize) -> Result<RR_MR, ParseError> {
        Ok(RR_MR {
            mb: RR_MB::parse(packet, offset)?,
        })
    }
}

impl Display for RR_MR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mb)
    }
}

impl DnsRecord for RR_MR {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::MR
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.mb.to_bytes(names, offset)
    }
}
