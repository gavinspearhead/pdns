use crate::dns_helper::names_list;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct RR_Private {}

impl RR_Private {
    #[must_use]
    pub fn new() -> RR_Private {
        RR_Private::default()
    }
    pub fn set(&mut self) {}
    pub(crate) fn parse(_rdata: &[u8]) -> Result<RR_Private, ParseError> {
        let a = RR_Private::new();
        Ok(a)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl Display for RR_Private {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl DnsRecord for RR_Private {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::Private
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        vec![]
    }
}
