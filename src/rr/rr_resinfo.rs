use crate::dns_helper::{dns_parse_slice, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::Display;

#[derive(Debug, Clone, Default)]
pub struct RR_RESINFO {
    resinfo: Vec<String>,
}

impl RR_RESINFO {
    #[must_use]
    pub fn new() -> RR_RESINFO {
        RR_RESINFO::default()
    }
    pub fn set(&mut self, resinfo: &str) {
        self.resinfo.push(resinfo.to_string());
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_RESINFO, Parse_error> {
        let mut resinfo = RR_RESINFO::new();
        let mut pos = 0;
        while pos < rdata.len() {
            let tlen = usize::from(rdata[pos]);
            let r = dns_parse_slice(rdata, (1 + pos)..=(pos + tlen))?;
            resinfo.set(&parse_dns_str(r)?);
            pos += 1 + tlen;
        }

        Ok(resinfo)
    }
}

impl Display for RR_RESINFO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.resinfo.join(" "))
    }
}

impl DNSRecord for RR_RESINFO {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::RESINFO
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for s in &self.resinfo {
            let bytes = s.as_bytes();
            let len = bytes.len();
            debug_assert!(len < 256);
            result.push(len as u8); // Prefix with length
            result.extend_from_slice(bytes); // Append string bytes
        }
        result
    }
}
