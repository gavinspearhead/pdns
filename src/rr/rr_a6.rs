use crate::dns_helper::{dns_format_name, dns_read_u8, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use std::net::Ipv6Addr;
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RR_A6 {
    prefix_len: usize,
    addr_suffix: Ipv6Addr,
    prefix_name: String,
}

impl Default for RR_A6 {
    fn default() -> Self {
        Self {
            prefix_len: 0,
            addr_suffix: Ipv6Addr::UNSPECIFIED,
            prefix_name: String::new(),
        }
    }
}

impl DNSRecord for RR_A6 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::A6
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.prefix_len as u8);

        let addr_bytes = self.addr_suffix.octets();
        let suffix_bytes = (128 - self.prefix_len) / 8;
        result.extend_from_slice(&addr_bytes[(16 - suffix_bytes)..]);

        if self.prefix_len != 0 {
            result.extend_from_slice(dns_format_name(&self.prefix_name, names, offset).as_slice());
        }

        result
    }
}
impl RR_A6 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, prefix_len: usize, addr_suffix: Ipv6Addr, prefix_name: &str) {
        self.prefix_len = prefix_len;
        self.addr_suffix = addr_suffix;
        self.prefix_name = prefix_name.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_A6, Parse_error> {
        let prefix_len = usize::from(dns_read_u8(packet, offset_in)?);
        let len = (128 - prefix_len) / 8;
        let mut addr_suffix = [0u8; 16];
        let mut prefix_name = String::new();

        for i in 0..len {
            addr_suffix[15 - i] = dns_read_u8(packet, offset_in + len - i)?;
        }

        if prefix_len != 0 {
            (prefix_name, _) = dns_parse_name(packet, offset_in + 1 + len)?;
        }

        Ok(RR_A6 {
            addr_suffix: addr_suffix.into(),
            prefix_name,
            prefix_len,
        })
    }
}

impl Display for RR_A6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.prefix_len, self.addr_suffix, self.prefix_name
        )
    }
}
