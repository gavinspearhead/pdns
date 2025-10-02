use crate::dns_helper::{names_list, parse_ipv4};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct RR_MAILA {
    pub(crate) addr: Ipv4Addr,
}

impl Default for RR_MAILA {
    fn default() -> Self {
        RR_MAILA {
            addr: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl RR_MAILA {
    #[must_use]
    pub fn new() -> RR_MAILA {
        RR_MAILA::default()
    }
    pub fn set(&mut self, addr: Ipv4Addr) {
        self.addr = addr;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_MAILA, Parse_error> {
        let mut a = RR_MAILA::new();
        a.addr = match parse_ipv4(rdata)? {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(Parse_error::new(Invalid_Parameter, "")),
        };
        Ok(a)
    }
}

impl Display for RR_MAILA {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl DNSRecord for RR_MAILA {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::MAILA
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.addr.octets().to_vec()
    }
}
