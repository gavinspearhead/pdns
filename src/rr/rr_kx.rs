use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_KX {
    pref: u16,
    kx: String,
}

impl RR_KX {
    #[must_use]
    pub fn new() -> RR_KX {
        RR_KX {
            pref: 0,
            kx: String::new(),
        }
    }
    pub fn set(&mut self, pref: u16, kx: &str) {
        self.pref = pref;
        self.kx = kx.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_KX, Parse_error> {
        let mut kx = RR_KX::new();
        kx.pref = dns_read_u16(rdata, 0)?;
        (kx.kx, _) = dns_parse_name(rdata, 2)?;
        Ok(kx)
    }
}

impl Display for RR_KX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.pref, self.kx)
    }
}

impl DNSRecord for RR_KX {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::KX
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.pref.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.kx, names, offset).as_slice());
        result
    }
}
