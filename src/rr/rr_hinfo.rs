use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_HINFO {
    cpu: String,
    os: String,
}

impl RR_HINFO {
    #[must_use]
    pub fn new() -> RR_HINFO {
        RR_HINFO {
            cpu: String::new(),
            os: String::new(),
        }
    }
    pub fn set(&mut self, cpu: &str, os: &str) {
        assert!(cpu.len() < 256 && os.len() < 256);
        self.cpu = cpu.to_string();
        self.os = os.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_HINFO, Parse_error> {
        let mut a = RR_HINFO::new();
        let cpu_len = usize::from(dns_read_u8(rdata, 0)?);
        let mut offset = 1;
        let r = dns_parse_slice(rdata, offset..offset + cpu_len)?;
        a.cpu = parse_dns_str(r)?;
        offset += cpu_len;
        let os_len = usize::from(dns_read_u8(rdata, offset)?);
        offset += 1;
        let r = dns_parse_slice(rdata, offset..offset + os_len)?;
        a.os = parse_dns_str(r)?;
        Ok(a)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        debug_assert!(self.cpu.len() < 256 && self.os.len() < 256);
        let mut result = Vec::new();
        result.push(self.cpu.len() as u8);
        result.extend_from_slice(self.cpu.as_bytes());
        result.push(self.os.len() as u8);
        result.extend_from_slice(self.os.as_bytes());
        result
    }
}

impl Display for RR_HINFO {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\" \"{}\"", self.cpu, self.os)
    }
}

impl DNSRecord for RR_HINFO {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::HINFO
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.cpu.len() as u8);
        result.extend_from_slice(self.cpu.as_bytes());
        result.push(self.os.len() as u8);
        result.extend_from_slice(self.os.as_bytes());
        result
    }
}
