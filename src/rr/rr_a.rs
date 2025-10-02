use super::super::dns_record_trait::DNSRecord;
use crate::dns_helper::{names_list, parse_ipv4};
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::{Invalid_Parameter, Invalid_Resource_Record};
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct RR_A {
    addr: Ipv4Addr,
}

impl DNSRecord for RR_A {
    #[inline]
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::A
    }

    #[inline]
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(4);
        result.extend_from_slice(&self.addr.octets());
        result
    }
}

impl Default for RR_A {
    #[inline]
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl RR_A {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set(&mut self, addr: &Ipv4Addr) {
        self.addr = *addr;
    }

    #[inline]
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_A, Parse_error> {
        if rdata.len() != 4 {
            return Err(Parse_error::new(
                Invalid_Resource_Record,
                &format!("Invalid A record length: {rdata:?}"),
            ));
        }

        match parse_ipv4(rdata)? {
            IpAddr::V4(v4_addr) => Ok(RR_A { addr: v4_addr }),
            IpAddr::V6(_) => Err(Parse_error::new(Invalid_Parameter, "Expected IPv4 address")),
        }
    }
}

impl Display for RR_A {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}
