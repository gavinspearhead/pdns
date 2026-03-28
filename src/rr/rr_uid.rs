use crate::dns_helper::{dns_read_u32, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_UID {
    uid: u32,
}

impl RR_UID {
    #[must_use]
    pub fn new() -> RR_UID {
        RR_UID::default()
    }
    pub fn set(&mut self, uid: u32) {
        self.uid = uid;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_UID, ParseError> {
        let mut uid = RR_UID::new();
        uid.uid = dns_read_u32(rdata, 0)?;
        Ok(uid)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.uid.to_be_bytes().to_vec()
    }
}

impl Display for RR_UID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.uid)
    }
}

impl DNSRecord for RR_UID {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::UID
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.uid.to_be_bytes().to_vec()
    }
}
