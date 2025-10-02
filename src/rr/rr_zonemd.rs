use crate::dns::zonemd_digest;
use crate::dns_helper::{dns_parse_slice, dns_read_u32, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_ZONEMD {
    serial: u32,
    scheme: u8,
    alg: u8,
    digest: Vec<u8>,
}

impl RR_ZONEMD {
    #[must_use]
    pub fn new() -> RR_ZONEMD {
        RR_ZONEMD::default()
    }
    pub fn set(&mut self, serial: u32, scheme: u8, alg: u8, digest: &[u8]) {
        self.serial = serial;
        self.scheme = scheme;
        self.alg = alg;
        self.digest = digest.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_ZONEMD, Parse_error> {
        let mut a = RR_ZONEMD::new();
        a.serial = dns_read_u32(rdata, 0)?;
        a.scheme = dns_read_u8(rdata, 4)?;
        a.alg = dns_read_u8(rdata, 5)?;
        a.digest = dns_parse_slice(rdata, 6..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_ZONEMD {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.serial,
            self.scheme,
            zonemd_digest(self.alg).unwrap(),
            hex::encode(&self.digest).to_uppercase()
        )
    }
}

impl DNSRecord for RR_ZONEMD {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::ZONEMD
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.serial.to_be_bytes());
        bytes.push(self.scheme);
        bytes.push(self.alg);
        bytes.extend_from_slice(&self.digest);
        bytes
    }
}
