use crate::dns_helper::{dns_read_u16, dns_read_u8, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_DSYNC {
    rrtype: u16,
    scheme: u8,
    port: u16,
    target: String,
}

impl RR_DSYNC {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, rrtype: u16, scheme: u8, port: u16, target: &str) {
        self.rrtype = rrtype;
        self.scheme = scheme;
        self.port = port;
        self.target = target.to_string();
    }

    pub(crate) fn parse(rdata: &[u8]) -> Result<Self, Parse_error> {
        let (target, _) = dns_parse_name(rdata, 5)?;
        Ok(Self {
            rrtype: dns_read_u16(rdata, 0)?,
            scheme: dns_read_u8(rdata, 2)?,
            port: dns_read_u16(rdata, 3)?,
            target,
        })
    }
}

impl Display for RR_DSYNC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match DNS_RR_type::find(self.rrtype) {
            Ok(rrtype) => write!(
                f,
                "{} {} {} {}",
                rrtype, self.scheme, self.port, self.target
            ),
            Err(_) => write!(f, "  {} {} {}", self.scheme, self.port, self.target),
        }
    }
}

impl DNSRecord for RR_DSYNC {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::DSYNC
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.rrtype.to_be_bytes());
        bytes.push(self.scheme);
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.extend(self.target.as_bytes());
        bytes
    }
}
