use crate::dns_helper::{
    base32hex_encode, dns_format_name, dns_parse_slice, dns_read_u16, dns_read_u32, names_list,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_TKEY {
    pub name: String,
    pub inception: u32,
    pub expiration: u32,
    pub mode: u16,
    pub error: u16,
    pub key: Vec<u8>,
    pub other: Vec<u8>,
}

impl RR_TKEY {
    #[must_use]
    pub fn new() -> RR_TKEY {
        RR_TKEY::default()
    }
    pub fn set(
        &mut self,
        name: String,
        inception: u32,
        expiration: u32,
        mode: u16,
        error: u16,
        key: Vec<u8>,
        other: Vec<u8>,
    ) {
        self.name = name;
        self.inception = inception;
        self.expiration = expiration;
        self.mode = mode;
        self.error = error;
        self.key = key;
        self.other = other;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_TKEY, Parse_error> {
        let mut a = RR_TKEY::new();
        let mut pos = 0;
        (a.name, pos) = dns_parse_name(rdata, pos)?;
        a.inception = dns_read_u32(rdata, pos)?;
        pos += 4;
        a.expiration = dns_read_u32(rdata, pos)?;
        pos += 4;
        a.mode = dns_read_u16(rdata, pos)?;
        pos += 2;
        a.error = dns_read_u16(rdata, pos)?;
        pos += 2;
        let key_size = usize::from(dns_read_u16(rdata, pos)?);
        pos += 2;
        a.key = dns_parse_slice(rdata, pos..pos + key_size)?.to_vec();
        pos += key_size;
        let other_len = usize::from(dns_read_u16(rdata, pos)?);
        pos += 2;
        a.other = dns_parse_slice(rdata, pos..pos + other_len)?.to_vec();

        Ok(a)
    }
}

impl Display for RR_TKEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{name} {inception} {expiration} {mode} {error} {key} {other:?} ",
            name = self.name,
            inception = self.inception,
            expiration = self.expiration,
            mode = self.mode,
            error = self.error,
            key = base32hex_encode(&self.key),
            other = self.other
        )
    }
}

impl DNSRecord for RR_TKEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::TKEY
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&dns_format_name(&self.name, names, offset));
        bytes.extend_from_slice(&self.inception.to_be_bytes());
        bytes.extend_from_slice(&self.expiration.to_be_bytes());
        bytes.extend_from_slice(&self.mode.to_be_bytes());
        bytes.extend_from_slice(&self.error.to_be_bytes());
        let key_len: u16 = self.key.len().try_into().unwrap_or(0);
        bytes.extend_from_slice(&key_len.to_be_bytes());
        bytes.extend_from_slice(&self.key[0..key_len as usize]);
        let other_len: u16 = self.other.len().try_into().unwrap_or(0);
        bytes.extend_from_slice(&other_len.to_be_bytes());
        bytes.extend_from_slice(&self.other[0..other_len as usize]);
        bytes
    }
}
