use crate::dns_helper::{dns_read_u16, names_list, parse_ipv4};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::{ParseErrorType, Parse_error};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};
#[derive(Debug, Clone)]
pub struct RR_L32 {
    pub prio: u16,
    pub addr: Ipv4Addr,
}
impl Default for RR_L32 {
    fn default() -> Self {
        RR_L32 {
            prio: 0,
            addr: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl RR_L32 {
    #[must_use]
    pub fn new() -> RR_L32 {
        RR_L32::default()
    }
    pub fn set(&mut self, prio: u16, addr: Ipv4Addr) {
        self.prio = prio;
        self.addr = addr;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_L32, Parse_error> {
        let mut a = RR_L32::new();
        a.prio = dns_read_u16(rdata, 0)?;
        a.addr = match parse_ipv4(&rdata[2..])? {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Parse_error::new(
                    ParseErrorType::Invalid_Data,
                    &format!("{:?}", &rdata[2..]),
                ))
            }
        };
        Ok(a)
    }
}

impl Display for RR_L32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.prio, self.addr)
    }
}

impl DNSRecord for RR_L32 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::L32
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.prio.to_be_bytes());
        result.extend_from_slice(&self.addr.octets());
        result
    }
}
