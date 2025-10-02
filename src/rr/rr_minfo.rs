use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_MINFO {
    res_mb: String,
    err_mb: String,
}

impl RR_MINFO {
    #[must_use]
    pub fn new() -> RR_MINFO {
        RR_MINFO {
            res_mb: String::new(),
            err_mb: String::new(),
        }
    }
    pub fn set(&mut self, res_mb: &str, err_mb: &str) {
        self.res_mb = res_mb.to_string();
        self.err_mb = err_mb.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_MINFO, Parse_error> {
        let mut a = RR_MINFO::new();
        let mut offset = offset_in;
        (a.res_mb, offset) = dns_parse_name(packet, offset)?;
        (a.err_mb, _) = dns_parse_name(packet, offset)?;
        Ok(a)
    }

    pub fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(dns_format_name(&self.res_mb, names, offset).as_slice());
        res.extend_from_slice(dns_format_name(&self.err_mb, names, offset).as_slice());
        res
    }
}

impl Display for RR_MINFO {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.res_mb, self.err_mb)
    }
}

impl DNSRecord for RR_MINFO {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MINFO
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(dns_format_name(&self.res_mb, names, offset).as_slice());
        res.extend_from_slice(dns_format_name(&self.err_mb, names, offset).as_slice());
        res
    }
}
