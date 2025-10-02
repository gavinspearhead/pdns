use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_SINK {
    coding: u8,
    subcoding: u8,
    val: Vec<u8>,
}

impl RR_SINK {
    #[must_use]
    pub fn new() -> RR_SINK {
        RR_SINK::default()
    }
    pub fn set(&mut self, coding: u8, subcoding: u8, val: &[u8]) {
        self.coding = coding;
        self.subcoding = subcoding;
        self.val = val.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_SINK, Parse_error> {
        let mut a = RR_SINK::new();
        a.coding = dns_read_u8(rdata, 0)?;
        let mut offset = 1;
        if a.coding == 0 {
            // weird bind thing
            a.coding = dns_read_u8(rdata, 1)?;
            offset = 2;
        }
        a.subcoding = dns_read_u8(rdata, offset)?;
        a.val = dns_parse_slice(rdata, offset + 1..)?.to_vec();

        Ok(a)
    }
}

impl Display for RR_SINK {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.coding,
            self.subcoding,
            STANDARD.encode(&self.val)
        )
    }
}

impl DNSRecord for RR_SINK {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SINK
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.coding);
        bytes.push(self.subcoding);
        bytes.extend_from_slice(&self.val);
        bytes
    }
}
