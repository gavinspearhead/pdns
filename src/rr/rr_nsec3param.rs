use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_NSEC3PARAM {
    hash: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
}

impl RR_NSEC3PARAM {
    #[must_use]
    pub fn new() -> RR_NSEC3PARAM {
        RR_NSEC3PARAM::default()
    }
    pub fn set(&mut self, hash: u8, flags: u8, iterations: u16, salt: &[u8]) {
        assert!(salt.len() < 256);
        self.hash = hash;
        self.flags = flags;
        self.iterations = iterations;
        self.salt = salt.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NSEC3PARAM, ParseError> {
        let a = RR_NSEC3PARAM {
            hash: dns_read_u8(rdata, 0)?,
            flags: dns_read_u8(rdata, 1)?,
            iterations: dns_read_u16(rdata, 2)?,
            salt: {
                let salt_len = usize::from(dns_read_u8(rdata, 4)?);
                dns_parse_slice(rdata, 5..5 + salt_len)?.to_vec()
            },
        };
        Ok(a)
    }
}

impl Display for RR_NSEC3PARAM {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.hash,
            self.flags,
            self.iterations,
            hex::encode(&self.salt).to_uppercase()
        )
    }
}

impl DNSRecord for RR_NSEC3PARAM {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NSEC3PARAM
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        debug_assert!(self.salt.len() < 256);
        let mut bytes = Vec::new();
        bytes.push(self.hash);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.push(self.salt.len() as u8);
        bytes.extend_from_slice(&self.salt);
        bytes
    }
}
