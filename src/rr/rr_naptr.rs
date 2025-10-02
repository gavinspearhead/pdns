use crate::dns_helper::{
    dns_format_name, dns_parse_slice, dns_read_u16, dns_read_u8, names_list, parse_dns_str,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_NAPTR {
    order: u16,
    pref: u16,
    flags: String,
    srv: String,
    re: String,
    repl: String,
}
impl RR_NAPTR {
    #[must_use]
    pub fn new() -> RR_NAPTR {
        RR_NAPTR::default()
    }
    pub fn set(&mut self, order: u16, pref: u16, flags: &str, srv: &str, re: &str, repl: &str) {
        assert!(srv.len() < 256 && re.len() < 256 && repl.len() < 256);
        self.order = order;
        self.pref = pref;
        self.flags = flags.to_string();
        self.srv = srv.to_string();
        self.re = re.to_string();
        self.repl = repl.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NAPTR, Parse_error> {
        let mut a = RR_NAPTR::new();
        a.order = dns_read_u16(rdata, 0)?;
        a.pref = dns_read_u16(rdata, 2)?;
        let flag_len = usize::from(dns_read_u8(rdata, 4)?);
        let mut offset: usize = 5;
        a.flags = parse_dns_str(dns_parse_slice(rdata, offset..offset + flag_len)?)?;
        offset += flag_len;
        let srv_len = usize::from(dns_read_u8(rdata, offset)?);
        offset += 1;
        a.srv = parse_dns_str(dns_parse_slice(rdata, offset..offset + srv_len)?)?;
        offset += srv_len;
        let re_len = usize::from(dns_read_u8(rdata, offset)?);
        offset += 1;
        if re_len > 0 {
            a.re.clone_from(&(parse_dns_str(dns_parse_slice(rdata, offset..offset + re_len)?)?));
        }
        offset += re_len;
        (a.repl, _) = dns_parse_name(rdata, offset)?;
        Ok(a)
    }
}

impl Display for RR_NAPTR {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{order} {pref} {flags} {srv} {re} {repl}",
            order = self.order,
            pref = self.pref,
            flags = self.flags,
            srv = self.srv,
            re = self.re,
            repl = self.repl
        )
    }
}

impl DNSRecord for RR_NAPTR {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NAPTR
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        debug_assert!(self.srv.len() < 256 && self.re.len() < 256 && self.repl.len() < 256);
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(&self.order.to_be_bytes());
        res.extend_from_slice(&self.pref.to_be_bytes());
        res.push(self.flags.len() as u8);
        res.extend_from_slice(self.flags.as_bytes());
        res.push(self.srv.len() as u8);
        res.extend_from_slice(self.srv.as_bytes());
        res.push(self.re.len() as u8);
        res.extend_from_slice(self.re.as_bytes());
        res.extend_from_slice(dns_format_name(&self.repl, names, offset).as_slice());
        res
    }
}
