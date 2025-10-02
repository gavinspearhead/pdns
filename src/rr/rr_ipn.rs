use crate::dns_helper::{dns_read_u64, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_IPN {
    pub ipn: u64,
}

impl RR_IPN {
    #[must_use]
    pub fn new() -> RR_IPN {
        RR_IPN { ipn: 0 }
    }
    pub fn set(&mut self, ipn: u64) {
        self.ipn = ipn;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_IPN, Parse_error> {
        let ipn = dns_read_u64(rdata, 0)?;
        Ok(RR_IPN { ipn })
    }
}

impl Display for RR_IPN {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ipn)
    }
}

impl DNSRecord for RR_IPN {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::IPN
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&self.ipn.to_be_bytes());
        buf
    }
}
