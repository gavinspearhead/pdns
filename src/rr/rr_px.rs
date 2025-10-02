use crate::dns_helper::{dns_format_name, dns_read_u16, names_list};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_PX {
    pub pref: u16,
    pub map822: String,
    pub mapx400: String,
}

impl RR_PX {
    #[must_use]
    pub fn new() -> RR_PX {
        RR_PX::default()
    }
    pub fn set(&mut self, pref: u16, map822: &str, mapx400: &str) {
        self.pref = pref;
        self.map822 = map822.to_string();
        self.mapx400 = mapx400.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_PX, Parse_error> {
        let mut a = RR_PX::new();
        let mut offset = 0;
        a.pref = dns_read_u16(rdata, offset)?;
        offset += 2;
        (a.map822, offset) = dns_parse_name(rdata, offset)?;
        (a.mapx400, _) = dns_parse_name(rdata, offset)?;
        Ok(a)
    }
}

impl Display for RR_PX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{pref} {map822} {mapx400}",
            pref = self.pref,
            map822 = self.map822,
            mapx400 = self.mapx400
        )
    }
}

impl DNSRecord for RR_PX {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::PX
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.pref.to_be_bytes());
        bytes.extend_from_slice(&dns_format_name(&self.map822, names, offset));
        bytes.extend_from_slice(&dns_format_name(&self.mapx400, names, offset));
        bytes
    }
}
