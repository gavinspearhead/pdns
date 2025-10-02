use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Default, Clone, Debug)]
pub struct RR_MX {
    pref: u16,
    mx: String,
}

impl RR_MX {
    #[must_use]
    pub fn new() -> RR_MX {
        RR_MX {
            pref: 0,
            mx: String::new(),
        }
    }
    pub fn set(&mut self, pref: u16, mx: &str) {
        self.pref = pref;
        self.mx = mx.to_string();
    }
    pub(crate) fn parse(rdata: &[u8], packet: &[u8], offset: usize) -> Result<RR_MX, Parse_error> {
        let pref = dns_read_u16(rdata, 0)?;
        let (mx, _) = dns_parse_name(packet, offset + 2)?;
        Ok(RR_MX { pref, mx })
    }

    pub fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.pref.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.mx, names, offset).as_slice());
        result
    }
}

impl Display for RR_MX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.pref, self.mx)
    }
}

impl DNSRecord for RR_MX {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MX
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.pref.to_be_bytes());
        result.extend_from_slice(dns_format_name(&self.mx, names, offset).as_slice());
        result
    }
}
