use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Default, Debug, Clone)]
pub struct RR_DNAME {
    dname: String,
}

impl RR_DNAME {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, dname: &str) {
        self.dname = dname.into();
    }
    pub fn parse(packet: &[u8], offset: usize) -> Result<RR_DNAME, ParseError> {
        let (dname, _) = dns_parse_name(packet, offset)?;
        Ok(Self { dname })
    }
}

impl Display for RR_DNAME {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dname)
    }
}

impl DnsRecord for RR_DNAME {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::DNAME
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.dname, names, offset)
    }
}
