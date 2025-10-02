use crate::dns::dnssec_digest;
use crate::dns_helper::{
    base32hex_encode, dns_parse_slice, dns_read_u16, dns_read_u8, map_bitmap_to_rr, names_list,
    parse_nsec_bitmap_vec, process_bitmap,
};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct RR_NSEC3 {
    hash_alg: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_owner: Vec<u8>,
    bitmap: Vec<u16>,
}

impl Default for RR_NSEC3 {
    fn default() -> Self {
        Self::new()
    }
}

impl RR_NSEC3 {
    #[must_use]
    pub fn new() -> RR_NSEC3 {
        RR_NSEC3 {
            hash_alg: 0,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
            next_owner: Vec::new(),
            bitmap: Vec::new(),
        }
    }
    pub fn set(
        &mut self,
        hash_alg: u8,
        flags: u8,
        iterations: u16,
        salt: &[u8],
        next_owner: &[u8],
        bitmap: Vec<DNS_RR_type>,
    ) {
        assert!(salt.len() < 256 && next_owner.len() < 256);
        self.hash_alg = hash_alg;
        self.flags = flags;
        self.iterations = iterations;
        self.salt = salt.to_vec();
        self.next_owner = next_owner.to_vec();
        let mut sorted_bitmap: Vec<DNS_RR_type> = bitmap;
        sorted_bitmap.sort_by_key(|x| u16::from(*x));
        self.bitmap = sorted_bitmap.iter().map(u16::from).collect();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NSEC3, Parse_error> {
        let mut a = RR_NSEC3::new();
        a.hash_alg = dns_read_u8(rdata, 0)?;
        a.flags = dns_read_u8(rdata, 1)?;
        a.iterations = dns_read_u16(rdata, 2)?;
        let salt_len = usize::from(dns_read_u8(rdata, 4)?);
        a.salt = dns_parse_slice(rdata, 5..5 + salt_len)?.to_vec();
        let hash_len = usize::from(dns_read_u8(rdata, 5 + salt_len)?);
        a.next_owner = dns_parse_slice(rdata, 6 + salt_len..6 + salt_len + hash_len)?.to_vec();
        a.bitmap = parse_nsec_bitmap_vec(&rdata[6 + salt_len + hash_len..])?;
        Ok(a)
    }
}

impl Display for RR_NSEC3 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bitmap_str = map_bitmap_to_rr(&self.bitmap).unwrap_or_default();
        write!(
            f,
            "{} {} {} {} {} {bitmap_str}",
            dnssec_digest(self.hash_alg).unwrap_or_default(),
            self.flags,
            self.iterations,
            hex::encode(&self.salt),
            base32hex_encode(&self.next_owner),
        )
    }
}

impl DNSRecord for RR_NSEC3 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NSEC3
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        debug_assert!(self.salt.len() < 256 && self.next_owner.len() < 256);
        let mut res: Vec<u8> = Vec::new();
        res.push(self.hash_alg);
        res.push(self.flags);
        res.extend_from_slice(&self.iterations.to_be_bytes());
        res.push(self.salt.len() as u8);
        res.append(&mut self.salt.clone());
        res.push(self.next_owner.len() as u8);
        res.append(&mut self.next_owner.clone());
        let mut bitmap_bytes: Vec<u8> = process_bitmap(&self.bitmap);
        res.append(&mut bitmap_bytes);
        res
    }
}
