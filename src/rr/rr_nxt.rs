use crate::dns_helper::{
    build_bitmap_from_vec, dns_format_name, map_bitmap_to_rr, names_list, parse_bitmap_vec,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_NXT {
    next: String,
    bitmap: Vec<u16>,
}

impl RR_NXT {
    #[must_use]
    pub fn new() -> RR_NXT {
        RR_NXT::default()
    }
    pub fn set(&mut self, next: String, bitmap: Vec<DNS_RR_type>) {
        self.next = next;
        let mut sorted_bitmap: Vec<DNS_RR_type> = bitmap;
        sorted_bitmap.sort_by_key(|x| u16::from(*x));
        self.bitmap = sorted_bitmap.iter().map(u16::from).collect();
    }
    pub(crate) fn parse(
        rdata: &[u8],
        packet: &[u8],
        offset_in: usize,
    ) -> Result<RR_NXT, Parse_error> {
        let mut a = RR_NXT::new();
        (a.next, _) = dns_parse_name(packet, offset_in)?;
        a.bitmap = parse_bitmap_vec(&rdata[a.next.len() + 2..])?;
        Ok(a)
    }
}

impl Display for RR_NXT {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            self.next,
            map_bitmap_to_rr(&self.bitmap).unwrap_or_default()
        )
    }
}

impl DNSRecord for RR_NXT {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NXT
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.append(&mut dns_format_name(&self.next, names, offset));
        let bm = build_bitmap_from_vec(&self.bitmap).unwrap_or_default();
        res.extend_from_slice(&bm);

        res
    }
}
