use crate::dns::dhcid_alg;
use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_DHCID {
    id_type_code: u16,
    digest_type_code: u8,
    digest: Vec<u8>,
}

impl RR_DHCID {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, id_type_code: u16, digest_type_code: u8, digest: &[u8]) {
        self.id_type_code = id_type_code;
        self.digest_type_code = digest_type_code;
        self.digest = digest.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_DHCID, Parse_error> {
        let mut a = RR_DHCID::new();
        a.id_type_code = dns_read_u16(rdata, 0)?;
        a.digest_type_code = dns_read_u8(rdata, 2)?;
        a.digest = dns_parse_slice(rdata, 3..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_DHCID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf: Vec<u8> = vec![];
        buf.extend_from_slice(&self.id_type_code.to_be_bytes());
        buf.push(self.digest_type_code);
        buf.extend_from_slice(self.digest.as_slice());
        write!(
            f,
            "{} {} {}",
            self.id_type_code,
            dhcid_alg(self.digest_type_code).unwrap_or_default(),
            Base64Display::new(buf.as_ref(), &STANDARD)
        )
    }
}

impl DNSRecord for RR_DHCID {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DHCID
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(&self.id_type_code.to_be_bytes());
        res.push(self.digest_type_code);
        res.extend_from_slice(&self.digest);
        res
    }
}
