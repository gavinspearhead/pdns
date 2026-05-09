use crate::dns_helper::names_list;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, Hash)]
pub struct RR_EID {
    eid: Vec<u8>,
}

impl RR_EID {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, nsap: &[u8]) {
        self.eid = nsap.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_EID, ParseError> {
        Ok(RR_EID {
            eid: rdata.to_vec(),
        })
    }
}

impl Display for RR_EID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.eid).to_uppercase())
    }
}

impl DnsRecord for RR_EID {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::EID
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.eid.clone()
    }
}
