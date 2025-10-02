use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_NSAP_PTR {
    nsap_ptr: String,
}

impl RR_NSAP_PTR {
    #[must_use]
    pub fn new() -> RR_NSAP_PTR {
        RR_NSAP_PTR {
            nsap_ptr: String::new(),
        }
    }
    pub fn set(&mut self, nsap_ptr: &str) {
        self.nsap_ptr = nsap_ptr.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_NSAP_PTR, Parse_error> {
        let mut a = RR_NSAP_PTR::new();
        (a.nsap_ptr, _) = dns_parse_name(packet, offset_in)?.clone();
        Ok(a)
    }

    pub fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.nsap_ptr, names, offset)
    }
}

impl Display for RR_NSAP_PTR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.nsap_ptr)
    }
}

impl DNSRecord for RR_NSAP_PTR {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NSAP_PTR
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.nsap_ptr, names, offset)
    }
}
