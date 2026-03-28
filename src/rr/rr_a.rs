use super::super::dns_record_trait::DNSRecord;
use crate::dns_helper::names_list;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_A, ParseError> {
        if rdata.len() != 4 {
            return Err(ParseError::new(
                Invalid_Resource_Record,
                &format!("Invalid A record length: {rdata:?}"),
            ));
        }

        Ok(RR_A {
            addr: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
        })
    }
}

impl Display for RR_A {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}
