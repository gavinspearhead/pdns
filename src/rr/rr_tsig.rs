use crate::dns_helper::{
    base32hex_encode, dns_format_name, dns_parse_slice, dns_read_u16, dns_read_u48, names_list,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_TSIG {
    name: String,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    orig_id: u16,
    error: u16,
    other: Vec<u8>,
}

impl RR_TSIG {
    #[must_use]
    pub fn new() -> RR_TSIG {
        RR_TSIG::default()
    }
    pub fn set(
        &mut self,
        name: String,
        time_signed: u64,
        fudge: u16,
        mac: Vec<u8>,
        orig_id: u16,
        error: u16,
        other: Vec<u8>,
    ) {
        self.name = name;
        self.time_signed = time_signed;
        self.fudge = fudge;
        self.mac = mac;
        self.orig_id = orig_id;
        self.error = error;
        self.other = other;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_TSIG, Parse_error> {
        let mut a = RR_TSIG::new();
        let mut pos = 0;
        (a.name, pos) = dns_parse_name(rdata, pos)?;
        a.time_signed = dns_read_u48(rdata, pos)?;
        pos += 6;
        a.fudge = dns_read_u16(rdata, pos)?;
        pos += 2;
        let mac_size = usize::from(dns_read_u16(rdata, pos)?);
        pos += 2;
        a.mac = dns_parse_slice(rdata, pos..pos + mac_size)?.to_vec();
        pos += mac_size;
        a.orig_id = dns_read_u16(rdata, pos)?;
        pos += 2;
        a.error = dns_read_u16(rdata, pos)?;
        pos += 2;
        let other_len = usize::from(dns_read_u16(rdata, pos)?);
        pos += 2;
        a.other = dns_parse_slice(rdata, pos..pos + other_len)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_TSIG {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{name} {time_signed} {fudge} {mac} {orig_id} {error} {other:?} ",
            name = self.name,
            time_signed = self.time_signed,
            fudge = self.fudge,
            mac = base32hex_encode(&self.mac),
            orig_id = self.orig_id,
            error = self.error,
            other = self.other,
        )
    }
}

impl DNSRecord for RR_TSIG {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::TSIG
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&dns_format_name(&self.name, names, offset));
        bytes.extend_from_slice(&self.time_signed.to_be_bytes());
        bytes.extend_from_slice(&self.fudge.to_be_bytes());
        // Convert usize to u16 safely
        let mac_len: u16 = self.mac.len().try_into().unwrap_or(0);
        bytes.extend_from_slice(&mac_len.to_be_bytes());
        bytes.extend_from_slice(&self.mac[0..mac_len as usize]);
        bytes.extend_from_slice(&self.orig_id.to_be_bytes());
        bytes.extend_from_slice(&self.error.to_be_bytes());
        let other_len: u16 = self.other.len().try_into().unwrap_or(0);
        bytes.extend_from_slice(&other_len.to_be_bytes());
        bytes.extend_from_slice(&self.other[0..other_len as usize]);
        bytes
    }
}
