use crate::dns_helper::{dns_parse_slice, dns_read_u16, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_URI {
    prio: u16,
    weight: u16,
    target_data: Vec<u8>,
}

impl RR_URI {
    #[must_use]
    pub fn new() -> RR_URI {
        RR_URI::default()
    }
    pub fn set(&mut self, prio: u16, weight: u16, target_data: &[u8]) {
        self.prio = prio;
        self.weight = weight;
        self.target_data = target_data.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_URI, Parse_error> {
        let mut a = RR_URI::new();

        a.prio = dns_read_u16(rdata, 0)?;
        a.weight = dns_read_u16(rdata, 2)?;
        a.target_data = dns_parse_slice(rdata, 4..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_URI {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let target = parse_dns_str(&self.target_data).unwrap_or_default();
        write!(
            f,
            "{prio} {weight} {target}",
            prio = self.prio,
            weight = self.weight,
            target = target
        )
    }
}

impl DNSRecord for RR_URI {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::URI
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.prio.to_be_bytes());
        bytes.extend_from_slice(&self.weight.to_be_bytes());
        bytes.extend_from_slice(&self.target_data);
        bytes
    }
}
