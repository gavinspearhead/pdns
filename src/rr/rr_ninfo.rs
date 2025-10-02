use crate::dns_helper::{dns_parse_slice, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::Display;

#[derive(Default, Clone, Debug)]
pub struct RR_NINFO {
    ninfo: Vec<String>,
}

impl RR_NINFO {
    #[must_use]
    pub fn new() -> RR_NINFO {
        RR_NINFO::default()
    }
    pub fn set(&mut self, ninfo: &str) {
        self.ninfo.push(ninfo.to_string());
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NINFO, Parse_error> {
        let mut ninfo = RR_NINFO::new();
        let mut pos = 0;
        while pos < rdata.len() {
            let tlen = usize::from(rdata[pos]);
            let r = dns_parse_slice(rdata, (1 + pos)..=(pos + tlen))?;
            ninfo.set(&parse_dns_str(r)?);
            pos += 1 + tlen;
        }

        Ok(ninfo)
    }
}

impl Display for RR_NINFO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ninfo.join(" "))
    }
}
impl DNSRecord for RR_NINFO {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NINFO
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for s in &self.ninfo {
            let bytes = s.as_bytes();
            let len = bytes.len();
            debug_assert!(len < 255);
            result.push(len as u8); // Prefix with length
            result.extend_from_slice(bytes); // Append string bytes
        }
        result
    }
}
