use crate::dns::{cert_type_str, dnssec_algorithm};
use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_CERT {
    cert_type: u16,
    key_tag: u16,
    alg: u8,
    cert: Vec<u8>,
}

impl RR_CERT {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, cert_type: u16, key_tag: u16, alg: u8, cert: &[u8]) {
        self.cert_type = cert_type;
        self.key_tag = key_tag;
        self.alg = alg;
        self.cert = STANDARD.decode(cert).unwrap_or_default();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_CERT, Parse_error> {
        let mut a = RR_CERT::new();
        a.cert_type = dns_read_u16(rdata, 0)?;
        a.key_tag = dns_read_u16(rdata, 2)?;
        a.alg = dns_read_u8(rdata, 4)?;
        a.cert = dns_parse_slice(rdata, 5..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_CERT {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            cert_type_str(self.cert_type).unwrap_or_default(),
            self.key_tag,
            dnssec_algorithm(self.alg).unwrap_or_default(),
            STANDARD.encode(&self.cert)
        )
    }
}

impl DNSRecord for RR_CERT {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::CERT
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.cert_type.to_be_bytes());
        bytes.extend_from_slice(&self.key_tag.to_be_bytes());
        bytes.extend_from_slice(&self.alg.to_be_bytes());
        bytes.extend_from_slice(&self.cert);
        bytes
    }
}
