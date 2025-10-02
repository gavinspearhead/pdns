use crate::dns_helper::{
    base32hex_encode, dns_parse_slice, dns_read_u16, dns_read_u32, dns_read_u8, names_list,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_SIG {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub orig_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub name: String,
    pub signature: Vec<u8>,
}

impl RR_SIG {
    #[must_use]
    pub fn new() -> RR_SIG {
        RR_SIG::default()
    }
    pub fn set(
        &mut self,
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        orig_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        name: String,
        signature: Vec<u8>,
    ) {
        self.type_covered = type_covered;
        self.algorithm = algorithm;
        self.labels = labels;
        self.orig_ttl = orig_ttl;
        self.expiration = expiration;
        self.inception = inception;
        self.key_tag = key_tag;
        self.name = name;
        self.signature = signature;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_SIG, Parse_error> {
        let mut a = RR_SIG::new();
        let mut pos = 0;
        a.type_covered = dns_read_u16(rdata, pos)?;
        pos += 2;
        a.algorithm = dns_read_u8(rdata, pos)?;
        pos += 1;
        a.labels = dns_read_u8(rdata, pos)?;
        pos += 1;
        a.orig_ttl = dns_read_u32(rdata, pos)?;
        pos += 4;
        a.expiration = dns_read_u32(rdata, pos)?;
        pos += 4;
        a.inception = dns_read_u32(rdata, pos)?;
        pos += 4;
        a.key_tag = dns_read_u16(rdata, pos)?;
        pos += 2;
        (a.name, pos) = dns_parse_name(rdata, pos)?;
        a.signature = dns_parse_slice(rdata, pos..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_SIG {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{name} {type_covered} {algorithm} {labels} {orig_ttl} {expiration} {inception} {key_tag} {name} {signature}",
               type_covered = self.type_covered,
               algorithm = self.algorithm,
               labels = self.labels,
               orig_ttl = self.orig_ttl,
               expiration = self.expiration,
               inception = self.inception,
               key_tag = self.key_tag,
               name = self.name,
               signature= base32hex_encode(&self.signature))
    }
}

impl DNSRecord for RR_SIG {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SIG
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.type_covered.to_be_bytes());
        bytes.extend_from_slice(&self.algorithm.to_be_bytes());
        bytes.extend_from_slice(&self.labels.to_be_bytes());
        bytes.extend_from_slice(&self.orig_ttl.to_be_bytes());
        bytes.extend_from_slice(&self.expiration.to_be_bytes());
        bytes.extend_from_slice(&self.inception.to_be_bytes());
        bytes.extend_from_slice(&self.key_tag.to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}
