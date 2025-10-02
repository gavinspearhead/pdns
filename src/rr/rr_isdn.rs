use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_ISDN {
    addr: String,
    sub_addr_str: String,
}

impl RR_ISDN {
    #[must_use]
    pub fn new() -> RR_ISDN {
        RR_ISDN {
            addr: String::new(),
            sub_addr_str: String::new(),
        }
    }
    pub fn set(&mut self, addr: &str, sub_addr_str: &str) {
        self.addr = addr.to_string();
        self.sub_addr_str = sub_addr_str.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_ISDN, Parse_error> {
        let mut a = RR_ISDN::new();
        let addr_len = usize::from(dns_read_u8(rdata, 0)?);
        a.addr = String::from_utf8_lossy(dns_parse_slice(rdata, 1..=addr_len)?).to_string();
        a.sub_addr_str = String::new();
        if rdata.len() > 1 + addr_len {
            let subaddr_len = usize::from(dns_read_u8(rdata, 1 + addr_len)?);
            let sub_addr = dns_parse_slice(rdata, 2 + addr_len..1 + addr_len + 1 + subaddr_len)?;
            a.sub_addr_str = String::from_utf8_lossy(sub_addr).into();
        }
        Ok(a)
    }
}

impl Display for RR_ISDN {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}' '{}'", self.addr, self.sub_addr_str)
    }
}

impl DNSRecord for RR_ISDN {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::ISDN
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.addr.len() as u8);
        bytes.extend(self.addr.as_bytes());
        bytes.push(self.sub_addr_str.len() as u8);
        bytes.extend(self.sub_addr_str.as_bytes());
        bytes
    }
}
