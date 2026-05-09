use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};
#[derive(Default, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RR_PTR {
    ptr: String,
}

impl RR_PTR {
    #[must_use]
    pub fn new() -> RR_PTR {
        RR_PTR::default()
    }
    pub fn set(&mut self, ptr: &str) {
        self.ptr = ptr.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_PTR, ParseError> {
        let (s, _) = dns_parse_name(packet, offset_in)?;
        Ok(RR_PTR { ptr: s })
    }
}

impl Display for RR_PTR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ptr)
    }
}

impl DnsRecord for RR_PTR {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::PTR
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.ptr, names, offset)
    }
}
