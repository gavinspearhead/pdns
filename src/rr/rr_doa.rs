use crate::dns_helper::{dns_parse_slice, dns_read_u32, dns_read_u8, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_DOA {
    doa_ent: u32,
    doa_type: u32,
    doa_location: u8,
    doa_media_type: Vec<u8>,
    doa_data: Vec<u8>,
}

impl RR_DOA {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(
        &mut self,
        doa_ent: u32,
        doa_type: u32,
        doa_location: u8,
        doa_media_type: &str,
        doa_data: &[u8],
    ) {
        self.doa_ent = doa_ent;
        self.doa_type = doa_type;
        self.doa_location = doa_location;
        self.doa_media_type = doa_media_type.as_bytes().to_vec();
        self.doa_data = doa_data.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_DOA, ParseError> {
        let mut a = RR_DOA::new();
        a.doa_ent = dns_read_u32(rdata, 0)?;
        a.doa_type = dns_read_u32(rdata, 4)?;
        a.doa_location = dns_read_u8(rdata, 8)?;
        let doa_media_type_len = usize::from(dns_read_u8(rdata, 9)?);
        a.doa_media_type = dns_parse_slice(rdata, 10..10 + doa_media_type_len)?.to_vec();
        a.doa_data = dns_parse_slice(rdata, 10 + doa_media_type_len..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_DOA {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{doa_ent} {doa_type} {doa_location} {media_type:?} {doa_data_str} ",
            doa_ent = self.doa_ent,
            doa_type = self.doa_type,
            doa_location = self.doa_location,
            media_type = parse_dns_str(&self.doa_media_type),
            doa_data_str = if self.doa_data.is_empty() {
                "-".to_string()
            } else {
                STANDARD.encode(&self.doa_data)
            }
        )
    }
}

impl DNSRecord for RR_DOA {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DOA
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.doa_ent.to_be_bytes());
        bytes.extend_from_slice(&self.doa_type.to_be_bytes());
        bytes.push(self.doa_location);
        bytes.push(self.doa_media_type.len() as u8);
        bytes.extend_from_slice(&self.doa_media_type);
        bytes.extend_from_slice(&self.doa_data);
        bytes
    }
}
