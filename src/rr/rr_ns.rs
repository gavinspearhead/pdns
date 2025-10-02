use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Default, Clone, Debug)]
pub struct RR_NS {
    ns: String,
}

impl RR_NS {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set(&mut self, ns: &str) {
        self.ns = ns.into();
    }

    #[inline]
    pub(crate) fn parse(packet: &[u8], offset: usize) -> Result<RR_NS, Parse_error> {
        let (ns, _offset) = dns_parse_name(packet, offset)?;
        Ok(Self { ns })
    }
}

impl Display for RR_NS {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ns)
    }
}

impl DNSRecord for RR_NS {
    #[inline]
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NS
    }

    #[inline]
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.ns, names, offset)
    }
}
