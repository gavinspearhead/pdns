use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_LP {
    prio: u16,
    fqdn: String,
}

impl RR_LP {
    #[must_use]
    pub fn new() -> RR_LP {
        RR_LP::default()
    }
    pub fn set(&mut self, pref: u16, fqdn: &str) {
        self.prio = pref;
        self.fqdn = fqdn.to_string();
    }

    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_LP, Parse_error> {
        let mut lp = RR_LP::new();
        lp.prio = dns_read_u16(rdata, 0)?;
        (lp.fqdn, _) = dns_parse_name(rdata, 2)?;
        Ok(lp)
    }
}

impl Display for RR_LP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.prio, self.fqdn)
    }
}
impl DNSRecord for RR_LP {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::LP
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.prio.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.fqdn, names, offset).as_slice());
        result
    }
}
