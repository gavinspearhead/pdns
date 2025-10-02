use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use tracing::debug;

#[derive(Debug, Clone, Default)]
pub struct RR_NXNAME {}

// this is not a real RR type. But only used in ???

impl RR_NXNAME {
    #[must_use]
    pub fn new() -> RR_NXNAME {
        RR_NXNAME::default()
    }
    pub fn set(&mut self) {}
    pub(crate) fn parse(_rdata: &[u8]) -> Result<RR_NXNAME, Parse_error> {
        debug!("Can't happen : NXNAME");
        let a = RR_NXNAME::new();
        Ok(a)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl Display for RR_NXNAME {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl DNSRecord for RR_NXNAME {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NXNAME
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        vec![]
    }
}
