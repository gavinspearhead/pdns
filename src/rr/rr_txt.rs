use crate::dns_helper::{dns_parse_slice, names_list, parse_dns_str};
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::Display;

#[derive(Default, Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct RR_TXT {
    txt: Vec<String>,
}

impl RR_TXT {
    #[must_use]
    pub fn new() -> RR_TXT {
        RR_TXT { txt: Vec::new() }
    }
    pub fn set(&mut self, txt: &str) {
        self.txt.push(txt.to_string());
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_TXT, ParseError> {
        let mut txt = RR_TXT::new();
        let mut pos = 0;
        while pos < rdata.len() {
            let tlen = usize::from(rdata[pos]);
            let r = dns_parse_slice(rdata, (1 + pos)..=(pos + tlen))?;
            txt.set(&parse_dns_str(r)?);
            pos += 1 + tlen;
        }
        Ok(txt)
    }
}

impl Display for RR_TXT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.txt
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

impl DnsRecord for RR_TXT {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::TXT
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for s in &self.txt {
            let bytes = s.as_bytes();
            let len = bytes.len();
            debug_assert!(len < 256);
            result.push(len as u8); // Prefix with length
            result.extend_from_slice(bytes); // Append string bytes
        }
        result
    }
}
