use crate::dns_helper::{dns_parse_slice, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::Display;

#[derive(Default, Clone, Debug)]
pub struct RR_SPF {
    spf: Vec<String>,
}

impl RR_SPF {
    #[must_use]
    pub fn new() -> RR_SPF {
        RR_SPF::default()
    }
    pub fn set(&mut self, spf: &str) {
        self.spf.push(spf.to_string());
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_SPF, Parse_error> {
        let mut spf = RR_SPF::new();
        let mut pos = 0;
        while pos < rdata.len() {
            let tlen = usize::from(rdata[pos]);
            let r = dns_parse_slice(rdata, (1 + pos)..=(pos + tlen))?;
            spf.set(&parse_dns_str(r)?);
            pos += 1 + tlen;
        }

        Ok(spf)
    }
}

impl Display for RR_SPF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spf.join(" "))
    }
}
impl DNSRecord for RR_SPF {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SPF
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for s in &self.spf {
            let bytes = s.as_bytes();
            let len = bytes.len();
            result.push(len as u8); // Prefix with length
            result.extend_from_slice(bytes); // Append string bytes
        }
        result
    }
}
