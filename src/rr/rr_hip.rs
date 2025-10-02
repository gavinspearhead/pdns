use crate::dns_helper::{dns_format_name, dns_parse_slice, dns_read_u16, dns_read_u8, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_HIP {
    hit_len: u8,
    hit_alg: u8,
    pk_len: u16,
    hit: Vec<u8>,
    hip_pk: Vec<u8>,
    rendezvous: String,
}

impl RR_HIP {
    #[must_use]
    pub fn new() -> RR_HIP {
        RR_HIP {
            hit_len: 0,
            hit_alg: 0,
            pk_len: 0,
            hit: vec![],
            hip_pk: vec![],
            rendezvous: String::new(),
        }
    }
    pub fn set(&mut self, hit_alg: u8, hit: &[u8], hip_pk: &[u8], rendezvous: &str) {
        self.hit_len = hit.len() as u8;
        self.hit_alg = hit_alg;
        self.pk_len = hip_pk.len() as u16;
        self.hit = hit.into();
        self.hip_pk = hip_pk.into();
        self.rendezvous = rendezvous.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_HIP, Parse_error> {
        let mut a = RR_HIP::new();
        a.hit_len = dns_read_u8(rdata, 0)?;
        a.hit_alg = dns_read_u8(rdata, 1)?;
        a.pk_len = dns_read_u16(rdata, 2)?;
        let hit_len = usize::from(a.hit_len);
        let pk_len = usize::from(a.pk_len);
        a.hit = dns_parse_slice(rdata, 4..4 + hit_len)?.to_vec();
        a.hip_pk = dns_parse_slice(rdata, 4 + hit_len..4 + hit_len + pk_len)?.to_vec();
        (a.rendezvous, _) = dns_parse_name(rdata, 4 + hit_len + pk_len)?;
        Ok(a)
    }
}

impl Display for RR_HIP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {:x?} {:x?} {}",
            self.hit_alg,
            hex::encode(&self.hit),
            STANDARD_NO_PAD.encode(&self.hip_pk),
            &self.rendezvous
        )
    }
}

impl DNSRecord for RR_HIP {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::HIP
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.hit_len);
        bytes.push(self.hit_alg);
        bytes.extend_from_slice(&self.pk_len.to_be_bytes());
        bytes.extend_from_slice(&self.hit);
        bytes.extend_from_slice(&self.hip_pk);
        bytes.extend_from_slice(&dns_format_name(&self.rendezvous, names, offset));
        bytes
    }
}
