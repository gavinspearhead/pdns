use crate::dns_helper::{dns_format_name, dns_read_u8, names_list, parse_ipv4, parse_ipv6};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
#[derive(Debug, Clone, Default)]
pub struct RR_AMTRELAY {
    precedence: u8,
    dbit: u8,
    rtype: u8,
    relay: String,
}

impl RR_AMTRELAY {
    #[must_use]
    pub fn new() -> RR_AMTRELAY {
        RR_AMTRELAY {
            precedence: 0,
            dbit: 0,
            rtype: 0,
            relay: String::new(),
        }
    }
    pub fn set(&mut self, precedence: u8, dbit: u8, rtype: u8, relay: &str) {
        self.precedence = precedence;
        self.dbit = dbit;
        self.rtype = rtype;
        self.relay = relay.to_string();
    }
    pub(crate) fn parse(
        rdata: &[u8],
        packet: &[u8],
        offset: usize,
    ) -> Result<RR_AMTRELAY, Parse_error> {
        let mut a = RR_AMTRELAY::new();
        a.precedence = dns_read_u8(rdata, 0)?;
        a.rtype = dns_read_u8(rdata, 1)?;
        a.dbit = a.rtype >> 7;
        a.rtype &= 0x7f;
        a.relay = match a.rtype {
            3 => dns_parse_name(packet, offset + 2)?.0,
            2 => parse_ipv6(&rdata[2..18])?.to_string(),
            1 => parse_ipv4(&rdata[2..6])?.to_string(),
            _ => return Err(Parse_error::new(Invalid_Parameter, &a.rtype.to_string())),
        };
        Ok(a)
    }
}

impl Display for RR_AMTRELAY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.precedence, self.dbit, self.rtype, self.relay
        )
    }
}

impl DNSRecord for RR_AMTRELAY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::AMTRELAY
    }
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.precedence);
        result.push(self.dbit << 7 | self.rtype);

        match self.rtype {
            1 => {
                if let Ok(addr) = self.relay.parse::<Ipv4Addr>() {
                    result.extend_from_slice(&addr.octets());
                }
            }
            2 => {
                if let Ok(addr) = self.relay.parse::<std::net::Ipv6Addr>() {
                    result.extend_from_slice(&addr.octets());
                }
            }
            3 => {
                result.extend_from_slice(&dns_format_name(&self.relay, names, offset));
            }
            _ => {}
        }
        result
    }
}
