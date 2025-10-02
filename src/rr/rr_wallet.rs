use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr::RR_TXT;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_WALLET {
    txt: RR_TXT,
}

impl RR_WALLET {
    #[must_use]
    pub fn new() -> Self {
        Self { txt: RR_TXT::new() }
    }

    pub fn set(&mut self, txt: &str) {
        self.txt.set(txt);
    }

    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_WALLET, Parse_error> {
        Ok(RR_WALLET {
            txt: RR_TXT::parse(rdata)?,
        })
    }
}

impl Display for RR_WALLET {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.txt.fmt(f)
    }
}

impl DNSRecord for RR_WALLET {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::WALLET
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        self.txt.to_bytes(names, offset)
    }
}
