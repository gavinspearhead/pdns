use crate::dns::{dnssec_algorithm, dnssec_digest};
use crate::dns_helper::{dns_read_u16, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_CDS {
    key_id: u16,
    alg: u8,
    dig_t: u8,
    dig: Vec<u8>,
}

impl RR_CDS {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, key_id: u16, alg: u8, dig_t: u8, dig: &[u8]) {
        self.key_id = key_id;
        self.alg = alg;
        self.dig_t = dig_t;
        self.dig = hex::decode(dig).unwrap_or_default();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_CDS, Parse_error> {
        if rdata.len() < 5 {
            return Err(Parse_error::new(Invalid_Resource_Record, ""));
        }
        let mut cds = RR_CDS::new();
        cds.key_id = dns_read_u16(rdata, 0)?;
        cds.alg = dns_read_u8(rdata, 2)?;
        cds.dig_t = dns_read_u8(rdata, 3)?;
        cds.dig = rdata[4..].into();
        Ok(cds)
    }
}

impl Display for RR_CDS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let alg = dnssec_algorithm(self.alg).unwrap_or_default();
        let dig_t = dnssec_digest(self.dig_t).unwrap_or_default();
        write!(
            f,
            "{} {alg} {dig_t} {}",
            self.key_id,
            hex::encode(&self.dig).to_uppercase()
        )
    }
}

impl DNSRecord for RR_CDS {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::CDS
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.key_id.to_be_bytes());
        result.push(self.alg);
        result.push(self.dig_t);
        result.extend_from_slice(&self.dig);
        result
    }
}
