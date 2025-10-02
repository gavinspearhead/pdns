use crate::dns_helper::{dns_parse_slice, dns_read_u8, names_list, parse_bitmap_vec, parse_ipv4};
use crate::dns_protocol::DNS_Protocol;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct RR_WKS {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: Vec<u8>,
}

impl Default for RR_WKS {
    fn default() -> Self {
        RR_WKS {
            address: Ipv4Addr::UNSPECIFIED,
            protocol: 0,
            bitmap: Vec::default(),
        }
    }
}

fn create_wks_bitmap(ports: &[u16]) -> Vec<u8> {
    let max_port = ports.iter().copied().max().unwrap_or(0);
    let num_bytes = (max_port / 8 + 1) as usize;
    let mut bitmap = vec![0u8; num_bytes];

    for &port in ports {
        let byte_index = (port / 8) as usize;
        let bit_position = port % 8;
        bitmap[byte_index] |= 1 << (7 - bit_position); // MSB first
    }

    bitmap
}

impl RR_WKS {
    #[must_use]
    pub fn new() -> RR_WKS {
        RR_WKS::default()
    }
    pub fn set(&mut self, address: Ipv4Addr, protocol: u8, ports: &[u16]) {
        self.address = address;
        self.protocol = protocol;
        self.bitmap = create_wks_bitmap(ports);
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_WKS, Parse_error> {
        let mut a:RR_WKS = RR_WKS::new();

        a.address = match parse_ipv4(dns_parse_slice(rdata, 0..4)?)? {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => return Err(Parse_error::new(Invalid_Parameter, "")),
        };
        a.protocol = dns_read_u8(rdata, 4)?;
        a.bitmap = dns_parse_slice(rdata, 5..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_WKS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let protocol = DNS_Protocol::find(self.protocol.into()).unwrap_or_default();
        write!(
            f,
            "{} {} {}",
            self.address,
            protocol.to_str(),
            parse_bitmap_vec(&self.bitmap)
                .unwrap_or_default()
                .iter()
                .fold(String::new(), |a, &n| a + &n.to_string() + " ")
        )
    }
}

impl DNSRecord for RR_WKS {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::WKS
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.address.octets());
        bytes.push(self.protocol);
        bytes.extend_from_slice(&self.bitmap);
        bytes
    }
}
