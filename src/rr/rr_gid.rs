use crate::dns_helper::{dns_read_u32, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_GID {
    gid: u32,
}

impl RR_GID {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, uid: u32) {
        self.gid = uid;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_GID, Parse_error> {
        let mut a = RR_GID::new();
        a.gid = dns_read_u32(rdata, 0)?;
        Ok(a)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.gid.to_be_bytes());
        bytes
    }
}

impl Display for RR_GID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.gid)
    }
}

impl DNSRecord for RR_GID {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::GID
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.gid.to_be_bytes());
        bytes
    }
}
