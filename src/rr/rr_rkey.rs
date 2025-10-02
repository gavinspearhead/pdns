use crate::rr::rr_key::RR_KEY;

use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_RKEY {
    rr_key: RR_KEY,
}

impl RR_RKEY {
    #[must_use]
    pub fn new() -> RR_RKEY {
        RR_RKEY::default()
    }

    pub fn set(&mut self, flags: u16, protocol: u8, algorithm: u8, key: &[u8]) {
        self.rr_key.set(flags, protocol, algorithm, key);
    }

    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_RKEY, Parse_error> {
        Ok(RR_RKEY {
            rr_key: RR_KEY::parse(rdata)?,
        })
    }
}

impl Display for RR_RKEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.rr_key)
    }
}

impl DNSRecord for RR_RKEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::RKEY
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.rr_key.to_bytes(names, offset)
    }
}
