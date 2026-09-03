use crate::dns_helper::{
    dns_format_name, dns_parse_slice, dns_read_u16, dns_read_u8, parse_dns_str, NamesList,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RR_NAPTR {
    order: u16,
    preference: u16,
    flags: String,
    services: String,
    regexp: String,
    replacement: String,
}
impl RR_NAPTR {
    #[must_use]
    pub fn new() -> RR_NAPTR {
        RR_NAPTR::default()
    }
    pub fn set(&mut self, order: u16, pref: u16, flags: &str, srv: &str, re: &str, repl: &str) {
        assert!(srv.len() < 256 && re.len() < 256 && repl.len() < 256);
        self.order = order;
        self.preference = pref;
        self.flags = flags.to_string();
        self.services = srv.to_string();
        self.regexp = re.to_string();
        self.replacement = repl.to_string();
    }
    pub(crate) fn parse(packet: &[u8], offset_in: usize) -> Result<RR_NAPTR, ParseError> {
        let mut a = RR_NAPTR::new();
        let mut offset: usize = offset_in;
        a.order = dns_read_u16(packet, offset)?;
        a.preference = dns_read_u16(packet, offset + 2)?;
        let flag_len = usize::from(dns_read_u8(packet, offset + 4)?);
        offset += 5;
        a.flags = parse_dns_str(dns_parse_slice(packet, offset..offset + flag_len)?)?;
        offset += flag_len;
        let srv_len = usize::from(dns_read_u8(packet, offset)?);
        offset += 1;
        a.services = parse_dns_str(dns_parse_slice(packet, offset..offset + srv_len)?)?;
        offset += srv_len;
        let re_len = usize::from(dns_read_u8(packet, offset)?);
        offset += 1;
        if re_len > 0 {
            a.regexp
                .clone_from(&(parse_dns_str(dns_parse_slice(packet, offset..offset + re_len)?)?));
        }
        offset += re_len;
        (a.replacement, _) = dns_parse_name(packet, offset)?;
        Ok(a)
    }
}

impl Display for RR_NAPTR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{order} {pref} {flags} {srv} {re} {repl}",
            order = self.order,
            pref = self.preference,
            flags = self.flags,
            srv = self.services,
            re = self.regexp,
            repl = self.replacement
        )
    }
}

impl DnsRecord for RR_NAPTR {
    #[inline]
    fn get_type(&self) -> DnsRRType {
        DnsRRType::NAPTR
    }

    fn to_bytes(&self, names: &mut NamesList, offset: usize) -> Vec<u8> {
        debug_assert!(
            self.services.len() < 256 && self.regexp.len() < 256 && self.replacement.len() < 256
        );
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(&self.order.to_be_bytes());
        res.extend_from_slice(&self.preference.to_be_bytes());
        res.push(self.flags.len() as u8);
        res.extend_from_slice(self.flags.as_bytes());
        res.push(self.services.len() as u8);
        res.extend_from_slice(self.services.as_bytes());
        res.push(self.regexp.len() as u8);
        res.extend_from_slice(self.regexp.as_bytes());
        res.extend_from_slice(dns_format_name(&self.replacement, names, offset).as_slice());
        res
    }
}
