use crate::dns_helper::{parse_ipv6_addr, NamesList};
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use crate::errors::ParseErrorType::{InvalidParameter, InvalidResourceRecord};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RR_AAAA {
    pub(crate) addr: Ipv6Addr,
}

impl Default for RR_AAAA {
    #[inline]
    fn default() -> Self {
        Self {
            addr: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl RR_AAAA {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set(&mut self, addr: &Ipv6Addr) {
        self.addr = *addr;
    }

    #[inline]
    pub(crate) fn parse(rdata: &[u8]) -> Result<Self, ParseError> {
        if rdata.len() != 16 {
            return Err(ParseError::new(
                InvalidResourceRecord,
                &format!("{rdata:?}"),
            ));
        }
        match parse_ipv6_addr(rdata)? {
            IpAddr::V6(v6) => Ok(Self { addr: v6 }),
            IpAddr::V4(_) => Err(ParseError::new(InvalidParameter, "")),
        }
    }
}

impl Display for RR_AAAA {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl DnsRecord for RR_AAAA {
    #[inline]
    fn get_type(&self) -> DnsRRType {
        DnsRRType::AAAA
    }

    #[inline]
    fn to_bytes(&self, _names: &mut NamesList, _offset: usize) -> Vec<u8> {
        self.addr.octets().to_vec()
    }
}
