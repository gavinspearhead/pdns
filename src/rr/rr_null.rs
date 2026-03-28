use crate::dns_helper::{base32hex_encode, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::{ParseErrorType, ParseError};
use std::fmt::{Display, Formatter};
#[derive(Default, Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct RR_NULL {
    rdata: Vec<u8>,
}

impl RR_NULL {
    #[must_use]
    pub fn new() -> RR_NULL {
        RR_NULL::default()
    }
    pub fn set(&mut self, rdata: &[u8]) {
        self.rdata = rdata.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NULL, ParseError> {
        if rdata.len() > 65535 {
            return Err(ParseError::new(
                ParseErrorType::Invalid_Data,
                &format!("Data too large: {} B", rdata.len()),
            ));
        }
        Ok(RR_NULL {
            rdata: rdata.to_vec(),
        })
    }
}

impl Display for RR_NULL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base32hex_encode(self.rdata.as_slice()))
    }
}

impl DNSRecord for RR_NULL {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NULL
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.rdata.clone()
    }
}
