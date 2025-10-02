use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Default, Clone, Debug)]
pub struct RR_RT {
    pref: u16,
    rt: String,
}

impl RR_RT {
    #[must_use]
    pub fn new() -> RR_RT {
        RR_RT::default()
    }
    pub fn set(&mut self, pref: u16, rt: &str) {
        self.pref = pref;
        self.rt = rt.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_RT, Parse_error> {
        let mut rt = RR_RT::new();
        rt.pref = dns_read_u16(rdata, 0)?;
        (rt.rt, _) = dns_parse_name(rdata, 2)?;
        Ok(rt)
    }
}

impl Display for RR_RT {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.pref, self.rt)
    }
}

impl DNSRecord for RR_RT {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::RT
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.pref.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.rt, names, offset).as_slice());
        result
    }
}
