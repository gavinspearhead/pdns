use crate::dns_helper::{dns_format_name, dns_read_u32, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub(crate) struct RR_SOA {
    ns: String,
    mb: String,
    sn: u32,
    refr: u32,
    ret: u32,
    exp: u32,
    ttl: u32,
}

impl RR_SOA {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set(&mut self, ns: &str, mb: &str, sn: u32, refr: u32, ret: u32, exp: u32, ttl: u32) {
        self.ns = ns.into();
        self.mb = mb.into();
        self.sn = sn;
        self.refr = refr;
        self.ret = ret;
        self.exp = exp;
        self.ttl = ttl;
    }

    #[inline]
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_SOA, Parse_error> {
        let mut soa = RR_SOA::new();
        let mut offset = offset_in;
        (soa.ns, offset) = dns_parse_name(packet, offset)?;
        (soa.mb, offset) = dns_parse_name(packet, offset)?;
        soa.sn = dns_read_u32(packet, offset)?;
        soa.refr = dns_read_u32(packet, offset + 4)?;
        soa.ret = dns_read_u32(packet, offset + 8)?;
        soa.exp = dns_read_u32(packet, offset + 12)?;
        soa.ttl = dns_read_u32(packet, offset + 16)?;

        Ok(soa)
    }
}

impl Display for RR_SOA {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.ns, self.mb, self.sn, self.refr, self.ret, self.exp, self.ttl
        )
    }
}

impl DNSRecord for RR_SOA {
    #[inline]
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SOA
    }

    #[inline]
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(32);
        result.extend_from_slice(dns_format_name(&self.ns, names, offset).as_slice());
        let offset = result.len();
        result.extend_from_slice(dns_format_name(&self.mb, names, offset).as_slice());
        result.extend_from_slice(&self.sn.to_be_bytes());
        result.extend_from_slice(&self.refr.to_be_bytes());
        result.extend_from_slice(&self.ret.to_be_bytes());
        result.extend_from_slice(&self.exp.to_be_bytes());
        result.extend_from_slice(&self.ttl.to_be_bytes());
        result
    }
}
