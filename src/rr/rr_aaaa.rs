use crate::dns_helper::{names_list, parse_ipv6};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::{Invalid_Parameter, Invalid_Resource_Record};
use crate::errors::Parse_error;
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
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_AAAA, Parse_error> {
        if rdata.len() != 16 {
            return Err(Parse_error::new(
                Invalid_Resource_Record,
                &format!("{rdata:?}"),
            ));
        }
        match parse_ipv6(rdata)? {
            IpAddr::V6(v6) => Ok(RR_AAAA { addr: v6 }),
            IpAddr::V4(_) => Err(Parse_error::new(Invalid_Parameter, "")),
        }
    }
}

impl Display for RR_AAAA {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl DNSRecord for RR_AAAA {
    #[inline]
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::AAAA
    }

    #[inline]
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.addr.octets().to_vec()
    }
}
