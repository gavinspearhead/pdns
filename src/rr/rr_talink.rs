use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_TALINK {
    previous_signer: String,
    next_signer: String,
}

impl RR_TALINK {
    #[must_use]
    pub fn new() -> RR_TALINK {
        RR_TALINK::default()
    }
    pub fn set(&mut self, name1: &str, name2: &str) {
        self.previous_signer = name1.to_string();
        self.next_signer = name2.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_TALINK, Parse_error> {
        let mut a = RR_TALINK::new();
        let mut offset_out = offset_in;
        (a.previous_signer, offset_out) = dns_parse_name(packet, offset_out)?;
        (a.next_signer, _) = dns_parse_name(packet, offset_out)?;
        Ok(a)
    }
}

impl Display for RR_TALINK {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.previous_signer, self.next_signer)
    }
}

impl DNSRecord for RR_TALINK {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::TALINK
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(&dns_format_name(&self.previous_signer, names, offset));
        res.extend_from_slice(&dns_format_name(&self.next_signer, names, offset));
        res
    }
}
