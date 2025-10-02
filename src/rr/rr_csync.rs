use crate::dns_helper::{
    dns_parse_slice, dns_read_u16, dns_read_u32, encode_nsec3_bitmap, map_bitmap_to_rr, names_list,
    parse_nsec_bitmap_vec,
};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_CSYNC {
    soa: u32,
    flags: u16,
    bitmap: Vec<u16>,
}

impl RR_CSYNC {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, soa: u32, flags: u16, bitmap: &[DNS_RR_type]) {
        self.soa = soa;
        self.flags = flags;
        self.bitmap = bitmap.iter().map(|x| *x as u16).collect();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_CSYNC, Parse_error> {
        let mut a = RR_CSYNC::new();
        a.soa = dns_read_u32(rdata, 0)?;
        a.flags = dns_read_u16(rdata, 4)?;
        a.bitmap = parse_nsec_bitmap_vec(dns_parse_slice(rdata, 6..)?)?;
        Ok(a)
    }
}

impl Display for RR_CSYNC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bitmap_str = map_bitmap_to_rr(&self.bitmap).unwrap_or_default();
        write!(f, "{} {} {bitmap_str}", self.soa, self.flags)
    }
}

impl DNSRecord for RR_CSYNC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::CSYNC
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.soa.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(encode_nsec3_bitmap(&self.bitmap).as_slice());
        bytes
    }
}
