use crate::dns::{dnssec_algorithm, key_protocol};
use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_KEY {
    flags: u16,
    protocol: u8,
    alg: u8,
    key: Vec<u8>,
}

impl RR_KEY {
    #[must_use]
    pub fn new() -> RR_KEY {
        RR_KEY {
            flags: 0,
            protocol: 0,
            alg: 0,
            key: Vec::new(),
        }
    }
    pub fn set(&mut self, flags: u16, protocol: u8, alg: u8, key: &[u8]) {
        self.flags = flags;
        self.protocol = protocol;
        self.alg = alg;
        self.key = Vec::from(key);
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_KEY, Parse_error> {
        let mut a = RR_KEY::new();
        a.flags = dns_read_u16(rdata, 0)?;
        a.protocol = dns_read_u8(rdata, 2)?;
        a.alg = dns_read_u8(rdata, 3)?;
        a.key = dns_parse_slice(rdata, 4..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_KEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.flags,
            key_protocol(self.protocol).unwrap_or_default(),
            dnssec_algorithm(self.alg).unwrap_or_default(),
            STANDARD.encode(&self.key)
        )
    }
}

impl DNSRecord for RR_KEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::KEY
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.push(self.protocol);
        bytes.push(self.alg);
        bytes.extend_from_slice(&self.key);
        bytes
    }
}
