use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Default, Clone, Debug)]
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
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_PTR, Parse_error> {
        let (s, _offset_out) = dns_parse_name(packet, offset_in)?;
        Ok(RR_PTR { ptr: s })
    }
}

impl Display for RR_PTR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ptr)
    }
}

impl DNSRecord for RR_PTR {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::PTR
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.ptr, names, offset)
    }
}
