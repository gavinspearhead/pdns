use crate::dns_helper::{dns_parse_slice, dns_read_u16, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use std::net::Ipv6Addr;

#[derive(Debug, Clone)]
pub struct RR_L64 {
    pub prio: u16,
    pub addr: Ipv6Addr,
}

impl Default for RR_L64 {
    fn default() -> Self {
        RR_L64 {
            prio: 0,
            addr: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl RR_L64 {
    #[must_use]
    pub fn new() -> RR_L64 {
        RR_L64::default()
    }
    pub fn set(&mut self, prio: u16, addr: Ipv6Addr) {
        self.prio = prio;
        self.addr = addr;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_L64, Parse_error> {
        let mut a = RR_L64::new();
        a.prio = dns_read_u16(rdata, 0)?;
        let mut r: [u8; 16] = [0; 16];
        r[..8].copy_from_slice(dns_parse_slice(rdata, 2..(8 + 2))?);
        a.addr = Ipv6Addr::from(r);
        Ok(a)
    }

    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.prio.to_be_bytes());
        let addr_bytes = self.addr.octets();
        result.extend_from_slice(&addr_bytes[..8]);
        result
    }
}

impl Display for RR_L64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            self.prio,
            self.addr.to_string().trim_end_matches(':')
        )
    }
}

impl DNSRecord for RR_L64 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::L64
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.prio.to_be_bytes());
        let addr_bytes = self.addr.octets();
        result.extend_from_slice(&addr_bytes[..8]);
        result
    }
}
