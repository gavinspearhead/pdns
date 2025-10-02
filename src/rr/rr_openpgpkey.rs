use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_OPENPGPKEY {
    key: Vec<u8>,
}

impl RR_OPENPGPKEY {
    #[must_use]
    pub fn new() -> RR_OPENPGPKEY {
        RR_OPENPGPKEY::default()
    }
    pub fn set(&mut self, openpgpkey: &[u8]) {
        self.key = openpgpkey.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_OPENPGPKEY, Parse_error> {
        let mut openpgpkey = RR_OPENPGPKEY::new();
        openpgpkey.key = rdata.to_vec();
        Ok(openpgpkey)
    }
}

impl Display for RR_OPENPGPKEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", STANDARD_NO_PAD.encode(&self.key))
    }
}

impl DNSRecord for RR_OPENPGPKEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::OPENPGPKEY
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.key.clone()
    }
}
