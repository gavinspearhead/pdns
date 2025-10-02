use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_RP {
    mailbox: String,
    txt: String,
}

impl RR_RP {
    #[must_use]
    pub fn new() -> RR_RP {
        RR_RP::default()
    }
    pub fn set(&mut self, mailbox: &str, txt: &str) {
        self.mailbox = mailbox.into();
        self.txt = txt.into();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_RP, Parse_error> {
        let mut a = RR_RP::new();
        let mut offset = 0;
        (a.mailbox, offset) = dns_parse_name(rdata, offset)?;
        (a.txt, _) = dns_parse_name(rdata, offset)?;
        Ok(a)
    }
}

impl Display for RR_RP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.mailbox, self.txt)
    }
}

impl DNSRecord for RR_RP {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::RP
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(dns_format_name(&self.mailbox, names, offset).as_slice());
        res.extend_from_slice(dns_format_name(&self.txt, names, offset).as_slice());
        res
    }
}
