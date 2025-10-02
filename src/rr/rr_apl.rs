use crate::dns_helper::{
    dns_append_u16, dns_append_u8, dns_parse_slice, dns_read_u16, dns_read_u8, names_list,
};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::{ParseErrorType, Parse_error};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApItem {
    address_family: u16,
    prefix_length: u8,
    negation: u8,
    afd_length: u8,
    afd_part: IpAddr,
}

impl Default for ApItem {
    fn default() -> Self {
        Self {
            address_family: 0,
            prefix_length: 0,
            negation: 0,
            afd_length: 0,
            afd_part: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl ApItem {
    #[must_use]
    pub fn new() -> ApItem {
        ApItem {
            address_family: 0,
            prefix_length: 0,
            negation: 0,
            afd_length: 0,
            afd_part: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RR_APL {
    ap_items: Vec<ApItem>,
}

impl RR_APL {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ap_items: Vec::new(),
        }
    }
    pub fn set(&mut self, ap: &ApItem) {
        self.ap_items.push(*ap);
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_APL, Parse_error> {
        let mut a = RR_APL::new();
        let mut pos = 0;
        while pos < rdata.len() {
            let mut af = ApItem::new();
            af.address_family = dns_read_u16(rdata, pos)?;
            af.prefix_length = dns_read_u8(rdata, pos + 2)?;

            af.afd_length = dns_read_u8(rdata, pos + 3)?;
            af.negation = af.afd_length >> 7;
            af.afd_length &= 0x7f;
            let addr = dns_parse_slice(rdata, pos + 4..pos + 4 + usize::from(af.afd_length))?;
            if af.address_family == 1 {
                // ipv4
                let mut ip: [u8; 4] = [0; 4];
                ip[..usize::from(af.afd_length)]
                    .copy_from_slice(&addr[..usize::from(af.afd_length)]);
                af.afd_part = IpAddr::V4(Ipv4Addr::from(ip));
            } else if af.address_family == 2 {
                // Ipv6
                let mut ip: [u8; 16] = [0; 16];
                ip[..usize::from(af.afd_length)]
                    .copy_from_slice(&addr[..usize::from(af.afd_length)]);
                af.afd_part = IpAddr::V6(Ipv6Addr::from(ip));
            } else {
                return Err(Parse_error::new(
                    ParseErrorType::Unknown_Address_Family,
                    &af.to_string(),
                ));
            }
            pos += 4 + usize::from(af.afd_length);
            a.set(&af);
        }
        Ok(a)
    }
}

impl Display for RR_APL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        //let mut res = String::new();
        for x in &self.ap_items {
            write!(
                f,
                "{}{}/{} ",
                if x.negation > 0 { "!" } else { "" },
                x.afd_part,
                x.prefix_length
            )?;
        }
        write!(f, "") //res
    }
}

impl Display for ApItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}/{}",
            if self.negation > 0 { "!" } else { "" },
            self.afd_part,
            self.prefix_length
        )
    }
}

impl DNSRecord for RR_APL {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::APL
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut res = Vec::new();
        for item in &self.ap_items {
            dns_append_u16(&mut res, item.address_family);
            dns_append_u8(&mut res, item.prefix_length);
            //todo fix write afd_length
            let addr_bytes = match item.afd_part {
                IpAddr::V4(addr) => addr.octets().to_vec(),
                IpAddr::V6(addr) => addr.octets().to_vec(),
            };

            let afd_len = if item.negation > 0 {
                addr_bytes.len() as u8 | 0x80
            } else {
                addr_bytes.len() as u8
            };

            dns_append_u8(&mut res, afd_len);
            res.extend_from_slice(&addr_bytes);
        }
        res
    }
}
