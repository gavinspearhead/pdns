use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_MB {
    mb: String,
}

impl RR_MB {
    #[must_use]
    pub fn new() -> RR_MB {
        RR_MB::default()
    }
    pub fn set(&mut self, mb: &str) {
        self.mb = mb.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_MB, Parse_error> {
        let mut a = RR_MB::new();
        (a.mb, _) = dns_parse_name(packet, offset_in)?;
        Ok(a)
    }
}

impl Display for RR_MB {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mb)
    }
}

impl DNSRecord for RR_MB {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MB
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.mb, names, offset)
    }
}
