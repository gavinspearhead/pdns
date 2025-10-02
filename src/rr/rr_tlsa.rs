use crate::dns::{tlsa_algorithm, tlsa_cert_usage, tlsa_selector};
use crate::dns_helper::{dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_TLSA {
    cert_usage: u8,
    selector: u8,
    alg_type: u8,
    cad: Vec<u8>,
}

impl RR_TLSA {
    #[must_use]
    pub fn new() -> RR_TLSA {
        RR_TLSA::default()
    }
    pub fn set(&mut self, cert_usage: u8, selector: u8, alg_type: u8, cad: &[u8]) {
        self.cert_usage = cert_usage;
        self.selector = selector;
        self.alg_type = alg_type;
        self.cad = cad.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_TLSA, Parse_error> {
        let mut a = RR_TLSA::new();
        if rdata.len() < 4 {
            return Err(Parse_error::new(Invalid_Resource_Record, ""));
        }
        a.cert_usage = dns_read_u8(rdata, 0)?;
        a.selector = dns_read_u8(rdata, 1)?;
        a.alg_type = dns_read_u8(rdata, 2)?;
        a.cad = rdata[3..].into();
        Ok(a)
    }
}

impl Display for RR_TLSA {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let cert_usage = tlsa_cert_usage(self.cert_usage).unwrap_or_default();
        let selector = tlsa_selector(self.selector).unwrap_or_default();
        let alg_typ = tlsa_algorithm(self.alg_type).unwrap_or_default();
        write!(
            f,
            "{cert_usage} {selector} {alg_typ} {}",
            hex::encode(&self.cad)
        )
    }
}

impl DNSRecord for RR_TLSA {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::TLSA
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.cert_usage);
        result.push(self.selector);
        result.push(self.alg_type);
        result.extend_from_slice(&self.cad);
        result
    }
}
