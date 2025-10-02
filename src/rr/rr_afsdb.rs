use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_AFSDB {
    subtype: u16,
    hostname: String,
}

impl RR_AFSDB {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subtype: 0,
            hostname: String::new(),
        }
    }
    pub fn set(&mut self, pref: u16, afsdb: &str) {
        self.subtype = pref;
        self.hostname = afsdb.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_AFSDB, Parse_error> {
        let mut afsdb = RR_AFSDB::new();
        afsdb.subtype = dns_read_u16(rdata, 0)?;
        (afsdb.hostname, _) = dns_parse_name(rdata, 2)?;
        Ok(afsdb)
    }
}

impl Display for RR_AFSDB {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.subtype, self.hostname)
    }
}

impl DNSRecord for RR_AFSDB {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::AFSDB
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.subtype.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.hostname, names, offset).as_slice());
        result
    }
}
