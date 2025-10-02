use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct RR_NSAP {
    nsap: Vec<u8>,
}

impl Default for RR_NSAP {
    fn default() -> Self {
        Self::new()
    }
}

impl RR_NSAP {
    #[must_use]
    pub fn new() -> RR_NSAP {
        RR_NSAP { nsap: Vec::new() }
    }
    pub fn set(&mut self, nsap: &[u8]) {
        self.nsap = nsap.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NSAP, Parse_error> {
        let mut a = RR_NSAP::new();
        a.nsap = rdata.to_vec();
        Ok(a)
    }
}

impl Display for RR_NSAP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.nsap).to_uppercase())
    }
}

impl DNSRecord for RR_NSAP {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NSAP
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.nsap.clone()
    }
}
