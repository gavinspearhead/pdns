use crate::dns_helper::{names_list, parse_ipv4_addr};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Copy)]
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
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_MAILA, ParseError> {
        let addr = match parse_ipv4_addr(rdata)? {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(ParseError::new(Invalid_Parameter, "")),
        };
        Ok(RR_MAILA { addr })
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
