use crate::dns::ipsec_alg;
use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list, parse_ipv4, parse_ipv6};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
#[derive(Debug, Clone, Default)]

pub struct RR_IPSECKEY {
    precedence: u8,
    gw_type: u8,
    alg: u8,
    name: String,
    pubkey: Vec<u8>,
}

impl RR_IPSECKEY {
    #[must_use]
    pub fn new() -> RR_IPSECKEY {
        RR_IPSECKEY {
            precedence: 0,
            gw_type: 0,
            alg: 0,
            //     pk_offset: 0,
            name: String::new(),
            pubkey: Vec::new(),
        }
    }
    pub fn set(&mut self, precedence: u8, gw_type: u8, alg: u8, name: &str, pubkey: &[u8]) {
        self.precedence = precedence;
        self.gw_type = gw_type;
        self.alg = alg;
        self.pubkey = pubkey.into();
        self.name = name.to_string();
    }
    pub(crate) fn parse(
        rdata: &[u8],
        packet: &[u8],
        offset_in: usize,
    ) -> Result<RR_IPSECKEY, Parse_error> {
        let mut ipseckey = RR_IPSECKEY::new();
        ipseckey.precedence = dns_read_u8(rdata, 0)?;
        ipseckey.gw_type = dns_read_u8(rdata, 1)?;
        ipseckey.alg = dns_read_u8(rdata, 2)?;
        let mut pk_offset = 3;
        match ipseckey.gw_type {
            0 => {
                ipseckey.name.push('.');
            } // No Gateway
            1 => {
                pk_offset += 4;
                ipseckey.name = parse_ipv4(dns_parse_slice(rdata, 3..7)?)?.to_string();
            } // IPv4 address
            2 => {
                pk_offset += 16;
                ipseckey.name = parse_ipv6(dns_parse_slice(rdata, 3..19)?)?.to_string();
            } // IPv6 Address
            3 => {
                (ipseckey.name, pk_offset) = dns_parse_name(packet, offset_in + 3)?;
                pk_offset -= offset_in;
            } // a FQDN
            e => {
                return Err(Parse_error::new(Invalid_Resource_Record, &e.to_string()));
            }
        }
        ipseckey.pubkey = dns_parse_slice(rdata, pk_offset..)?.to_vec();
        Ok(ipseckey)
    }
}

impl Display for RR_IPSECKEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let alg_name = ipsec_alg(self.alg).unwrap_or_default();
        write!(
            f,
            "{} {} {alg_name} {} {}",
            self.precedence,
            self.gw_type,
            self.name,
            STANDARD.encode(&self.pubkey)
        )
    }
}

impl DNSRecord for RR_IPSECKEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::IPSECKEY
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.precedence);
        bytes.push(self.gw_type);
        bytes.push(self.alg);

        match self.gw_type {
            0 => {
                bytes.push(0);
            } // No Gateway
            1 => {
                bytes.extend_from_slice(&self.name.parse::<Ipv4Addr>().unwrap().octets());
            }
            2 => {
                bytes.extend_from_slice(&self.name.parse::<Ipv6Addr>().unwrap().octets());
            }
            3 => {
                bytes.extend_from_slice(self.name.as_bytes());
            }
            _ => {}
        }
        bytes.extend_from_slice(&self.pubkey);
        bytes
    }
}
