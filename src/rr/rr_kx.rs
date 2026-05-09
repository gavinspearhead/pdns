use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RR_KX {
    pref: u16,
    kx: String,
}

impl RR_KX {
    #[must_use]
    pub fn new() -> RR_KX {
        RR_KX::default()
    }
    pub fn set(&mut self, pref: u16, kx: &str) {
        self.pref = pref;
        self.kx = kx.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_KX, ParseError> {
        let mut kx = RR_KX::new();
        let offset = offset_in;
        kx.pref = dns_read_u16(packet, offset)?;
        (kx.kx, _) = dns_parse_name(packet, offset + 2)?;
        Ok(kx)
    }
}

impl Display for RR_KX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.pref, self.kx)
    }
}

impl DnsRecord for RR_KX {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::KX
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.pref.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.kx, names, offset).as_slice());
        result
    }
}
