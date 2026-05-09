use crate::dns_helper::{dns_parse_slice, dns_read_u32, names_list};
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_HHIT {
    pub prefix: u32,          // Only lowest 28 bits used
    pub hid: u32,             // Hierarchical ID (32 bits)
    pub orchid_hash: [u8; 8], // 64-bit truncated hash
}

impl RR_HHIT {
    #[must_use]
    pub fn new() -> RR_HHIT {
        Self::default()
    }

    pub fn set(&mut self, prefix: u32, hid: u32, orchid_hash: [u8; 8]) {
        self.prefix = prefix;
        self.hid = hid;
        self.orchid_hash = orchid_hash;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_HHIT, ParseError> {
        let mut a = RR_HHIT::new();
        a.prefix = dns_read_u32(rdata, 0)?;
        a.hid = dns_read_u32(rdata, 4)?;
        let slice = dns_parse_slice(rdata, 8..16)?;
        a.orchid_hash = slice
            .try_into()
            .map_err(|_| ParseError::new(Invalid_Resource_Record, "Invalid orchid_hash length"))?;
        Ok(a)
    }
}

impl Display for RR_HHIT {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {:x?}", self.prefix, self.hid, self.orchid_hash)
    }
}

impl DnsRecord for RR_HHIT {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::HHIT
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.prefix.to_be_bytes());
        bytes.extend_from_slice(&self.hid.to_be_bytes());
        bytes.extend_from_slice(&self.orchid_hash);
        bytes
    }
}
