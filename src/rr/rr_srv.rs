use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_SRV {
    pub prio: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

impl RR_SRV {
    #[must_use]
    pub fn new() -> RR_SRV {
        RR_SRV::default()
    }
    pub fn set(&mut self, prio: u16, weight: u16, port: u16, target: &str) {
        self.prio = prio;
        self.weight = weight;
        self.port = port;
        self.target = target.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_SRV, ParseError> {
        let mut srv = RR_SRV::new();
        let offset = offset_in;
        srv.prio = dns_read_u16(packet, offset)?;
        srv.weight = dns_read_u16(packet, offset + 2)?;
        srv.port = dns_read_u16(packet, offset + 4)?;
        (srv.target, _) = dns_parse_name(packet, offset + 6)?;
        Ok(srv)
    }
}

impl Display for RR_SRV {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.prio, self.weight, self.port, self.target
        )
    }
}

impl DNSRecord for RR_SRV {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SRV
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.prio.to_be_bytes());
        bytes.extend_from_slice(&self.weight.to_be_bytes());
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.extend_from_slice(dns_format_name(&self.target, names, offset).as_slice());
        bytes
    }
}
