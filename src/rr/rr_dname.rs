use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
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
    pub fn parse(packet: &[u8], offset: usize) -> Result<RR_DNAME, Parse_error> {
        let (dname, _offset) = dns_parse_name(packet, offset)?;
        Ok(Self { dname })
    }
}

impl Display for RR_DNAME {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dname)
    }
}

impl DNSRecord for RR_DNAME {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DNAME
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        dns_format_name(&self.dname, names, offset)
    }
}
