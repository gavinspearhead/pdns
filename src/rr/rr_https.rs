use crate::dns::SvcParamKeys;
use crate::dns_helper::{
    dns_parse_slice, dns_read_u16, dns_read_u8, names_list, parse_dns_str, parse_ipv4_addr,
    parse_ipv6_addr,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DnsRecord;
use crate::dns_rr_type::DnsRRType;
use crate::ech::ECHConfig;
use crate::errors::ParseError;
use crate::errors::ParseErrorType::Invalid_Parameter;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Add;
use strum_macros::{Display, EnumString};
use crate::statistics::Statistics;

#[derive(Debug, Clone, EnumString, PartialEq, Eq, Display)]
pub enum HttpsSvcParam {
    Alpn(Vec<String>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<Ipv4Addr>),
    Ipv6Hint(Vec<Ipv6Addr>),
    ECH(Vec<u8>),
    Mandatory(Vec<SvcParamKeys>),
    DohPath(String),
    KeyValue(u16, Vec<u8>), // Catch-all for unknown or private keys
    Ohttp,
    TlsSupportedGroups(Vec<u16>), // list of 16 bit numbers
    DocPath(Vec<String>),           // like txt record 8 bit length / n byte string
}

#[derive(Debug, Clone, Default)]
pub struct RR_HTTPS {
    pub(crate) prio: u16,
    pub(crate) target: String,
    pub(crate) param: Vec<HttpsSvcParam>,
}

impl RR_HTTPS {
    #[must_use]
    pub fn new() -> RR_HTTPS {
        RR_HTTPS::default()
    }
    pub fn set(&mut self, target: &str, prio: u16, param: &[HttpsSvcParam]) {
        self.prio = prio;
        self.param = param.to_vec();
        self.target = target.to_string();
    }
    pub(crate) fn parse(rdata: &[u8], statistics: &mut Statistics) -> Result<RR_HTTPS, ParseError> {
        let mut params: Vec<HttpsSvcParam> = vec![];
        let prio = dns_read_u16(rdata, 0)?;
        let (target, mut offset) = dns_parse_name(rdata, 2)?;
        let rdata_len = rdata.len();
        while offset < rdata_len {
            let svc_val = dns_read_u16(rdata, offset)?;
            offset += 2;
            let svc_param_key = SvcParamKeys::find(svc_val).unwrap_or_default();
            let svc_param_len = dns_read_u16(rdata, offset)? as usize;
            offset += 2;
            *statistics.svc_stats.entry(svc_param_key).or_insert(0) += 1;
            match svc_param_key {
                SvcParamKeys::key_value => {
                    let value = dns_parse_slice( rdata, offset ..offset  + svc_param_len)?;
                    params.push(HttpsSvcParam::KeyValue(svc_val, value.to_vec()));
                }
                SvcParamKeys::doh_path => {
                    let doh_path = parse_dns_str(dns_parse_slice(
                        rdata,
                        offset ..offset + svc_param_len,
                    )?)?;

                    params.push(HttpsSvcParam::DohPath(doh_path));
                }
                SvcParamKeys::mandatory => {
                    let mut pos = 0;
                    let mut keys: Vec<SvcParamKeys> = vec![];
                    while pos < svc_param_len {
                        let man_val = SvcParamKeys::find(dns_read_u16(rdata, offset + pos)?)
                            .map_err(|_| ParseError::new(Invalid_Parameter, "mandatory"))?;
                        keys.push(man_val);
                        pos += 2;
                    }
                    params.push(HttpsSvcParam::Mandatory(keys));
                }
                SvcParamKeys::docpath | SvcParamKeys::alpn => {
                    let mut pos = 0;
                    let mut values: Vec<String> = vec![];
                    while pos < svc_param_len {
                        let docpath_len = usize::from(dns_read_u8(rdata, offset + pos)?);
                        let docpath = parse_dns_str(dns_parse_slice(
                            rdata,
                            offset + pos + 1..offset + pos + 1 + docpath_len,
                        )?)?; // Convert to owned String
                        values.push(docpath);
                        pos += 1 + docpath_len;
                    }
                    if svc_param_key == SvcParamKeys::docpath {
                        params.push(HttpsSvcParam::DocPath(values));
                    }
                    else {
                        for i in values.iter() {
                            *statistics.alpn_stats.entry(i.clone()).or_insert(0) += 1;
                        }
                        params.push(HttpsSvcParam::Alpn(values));
                    }
                }
                SvcParamKeys::ech => {
                    let data_str = dns_parse_slice(rdata, offset ..offset + svc_param_len)?;
                    params.push(HttpsSvcParam::ECH(data_str.into()));
                }
                SvcParamKeys::ipv4hint => {
                    let mut pos: usize = 0;
                    let mut ipv4hints: Vec<Ipv4Addr> = vec![];
                    while pos + 4 <= svc_param_len {
                        let loc = offset + pos;
                        let addr: Ipv4Addr =
                            match parse_ipv4_addr(dns_parse_slice(rdata, loc..loc + 4)?)? {
                                IpAddr::V4(v4) => v4,
                                IpAddr::V6(_) => {
                                    return Err(ParseError::new(
                                        Invalid_Parameter,
                                        "Expected IPv4 address",
                                    ))
                                }
                            };
                        ipv4hints.push(addr);
                        pos += 4;
                    }
                    params.push(HttpsSvcParam::Ipv4Hint(ipv4hints));
                }
                SvcParamKeys::ipv6hint => {
                    let mut pos: usize = 0;
                    let mut ipv6hints: Vec<Ipv6Addr> = vec![];
                    while pos + 16 <= svc_param_len {
                        let loc = offset +  pos;
                        let addr: Ipv6Addr =
                            match parse_ipv6_addr(dns_parse_slice(rdata, loc..loc + 16)?)? {
                                IpAddr::V6(v6) => v6,
                                IpAddr::V4(_) => {
                                    return Err(ParseError::new(
                                        Invalid_Parameter,
                                        "Expected IPv6 address",
                                    ))
                                }
                            };
                        pos += 16;
                        ipv6hints.push(addr);
                    }
                    params.push(HttpsSvcParam::Ipv6Hint(ipv6hints));
                }
                SvcParamKeys::no_default_alpn => {
                    params.push(HttpsSvcParam::NoDefaultAlpn);
                }
                SvcParamKeys::ohttp => {
                    params.push(HttpsSvcParam::Ohttp);
                }
                SvcParamKeys::tls_supported_groups => {
                    let mut pos = 0;
                    let mut values: Vec<u16> = vec![];
                    while pos < svc_param_len {
                        let value = dns_read_u16(rdata, offset + pos)?;
                        values.push(value);
                        pos += 2;
                    }
                    params.push(HttpsSvcParam::TlsSupportedGroups(values));
                }
                SvcParamKeys::port => {
                    let port = dns_read_u16(rdata, offset)?;
                    params.push(HttpsSvcParam::Port(port));
                }
            }
            offset += svc_param_len;
        }
        let res = RR_HTTPS {
            prio,
            target,
            param: params,
        };
        Ok(res)
    }
}

impl std::fmt::Display for RR_HTTPS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.prio, self.target)?;
        for param in &self.param {
            match param {
                HttpsSvcParam::Mandatory(values) => {
                    let value = values
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    write!(f, " mandatory={value}")?;
                }

                HttpsSvcParam::Alpn(values) => {
                    let value = values
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    write!(f, " alpn={value}")?;
                }
                HttpsSvcParam::DohPath(values) => {
                    write!(f, " dohpath={values}")?;
                }
                HttpsSvcParam::Ohttp => {
                    write!(f, " ohttp")?;
                }
                HttpsSvcParam::NoDefaultAlpn => {
                    write!(f, " no-default-alpn")?;
                }
                HttpsSvcParam::Port(port) => {
                    write!(f, " port={port}")?;
                }
                HttpsSvcParam::TlsSupportedGroups(values) => {
                     let value = values
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    write!(f, " tls-supported-groups={value}")?;
                }
                HttpsSvcParam::Ipv4Hint(addrs) => {
                    let value = addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    write!(f, " ipv4hint={value}")?;
                }
                HttpsSvcParam::DocPath(addrs) => {
                    let value = String::from("/");
                    let value = value.add(&addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("/,"));
                    write!(f, " docpath={value}")?;
                }
                HttpsSvcParam::Ipv6Hint(addrs) => {
                    let value = addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    write!(f, " ipv6hint={value}")?;
                }
                HttpsSvcParam::ECH(data) => {
                    let ech = ECHConfig::parse(data);
                    let ech = if let Ok(item) = ech {
                        item
                    } else {
                        return Err(std::fmt::Error);
                    };

                    write!(f, " ech=")?;
                    for i in ech {
                        write!(f, "{i}")?;
                    }
                }
                HttpsSvcParam::KeyValue(key, value) => {
                    write!(f, " key{key}=")?;
                    for &byte in value {
                        if byte >= 32 && byte <= 126 {
                            // Printable ASCII
                            write!(f, "{}", byte as char)?;
                        } else {
                            // Non-printable - use octal notation
                            write!(f, "\\{byte:03}")?;
                        }
                    }
                }
            }
        }
        write!(f, "")
    }
}

impl DnsRecord for RR_HTTPS {
    fn get_type(&self) -> DnsRRType {
        DnsRRType::HTTPS
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.prio.to_be_bytes());

        // Add the target name
        for part in self.target.split('.') {
            if !part.is_empty() {
                assert!(part.len() < 256);
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
        }
        result.push(0); // null terminator

        // Add parameters
        for param in &self.param {
            match param {
                HttpsSvcParam::Mandatory(keys) => {
                    result.extend_from_slice(&(SvcParamKeys::mandatory as u16).to_be_bytes());
                    let param_len = keys.len() * 2;
                    result.extend_from_slice(&(param_len as u16).to_be_bytes());
                    for key in keys {
                        result.extend_from_slice(&(*key as u16).to_be_bytes());
                    }
                }
                HttpsSvcParam::TlsSupportedGroups(values) => {
                    result.extend_from_slice(
                        &(SvcParamKeys::tls_supported_groups as u16).to_be_bytes(),
                    );
                    let param_len = 2 * values.len(); // length byte + string
                    result.extend_from_slice(&(param_len as u16).to_be_bytes());
                    for val in values {
                        result.extend_from_slice(&val.to_be_bytes());
                    }
                }
                HttpsSvcParam::Alpn(values) => {
                    result.extend_from_slice(&(SvcParamKeys::alpn as u16).to_be_bytes());
                    let mut param_len = 0;
                    for val in values {
                        param_len += val.len() + 1; // length byte + string
                    }
                    result.extend_from_slice(&(param_len as u16).to_be_bytes());
                    for val in values {
                        assert!(val.len() < 256);
                        result.push(val.len() as u8);
                        result.extend_from_slice(val.as_bytes());
                    }
                }
                HttpsSvcParam::DohPath(values) => {
                    result.extend_from_slice(&(SvcParamKeys::doh_path as u16).to_be_bytes());
                    result.extend_from_slice(&(values.len() as u16).to_be_bytes());
                    result.extend_from_slice(values.as_bytes());
                }

                HttpsSvcParam::Ohttp => {
                    result.extend_from_slice(&(SvcParamKeys::ohttp as u16).to_be_bytes());
                    result.extend_from_slice(&0u16.to_be_bytes());
                }
                HttpsSvcParam::NoDefaultAlpn => {
                    result
                        .extend_from_slice(&(SvcParamKeys::no_default_alpn as u16).to_be_bytes());
                    result.extend_from_slice(&0u16.to_be_bytes());
                }
                HttpsSvcParam::Port(port) => {
                    result.extend_from_slice(&(SvcParamKeys::port as u16).to_be_bytes());
                    result.extend_from_slice(&2u16.to_be_bytes());
                    result.extend_from_slice(&port.to_be_bytes());
                }
                HttpsSvcParam::Ipv4Hint(addrs) => {
                    result.extend_from_slice(&(SvcParamKeys::ipv4hint as u16).to_be_bytes());
                    result.extend_from_slice(&((addrs.len() * 4) as u16).to_be_bytes());
                    for addr in addrs {
                        result.extend_from_slice(&addr.octets());
                    }
                }
                HttpsSvcParam::DocPath(addrs) => {
                    result.extend_from_slice(&(SvcParamKeys::docpath as u16).to_be_bytes());
                    let mut param_len: u16 = 0;
                    for addr in addrs {
                        param_len += addr.len() as u16 + 1;
                    }
                    result.extend_from_slice(&param_len.to_be_bytes());
                    for addr in addrs {
                        result.push(addr.len() as u8);
                        result.extend_from_slice(addr.as_bytes());
                    }
                }
                HttpsSvcParam::Ipv6Hint(addrs) => {
                    result.extend_from_slice(&(SvcParamKeys::ipv6hint as u16).to_be_bytes());
                    result.extend_from_slice(&((addrs.len() * 16) as u16).to_be_bytes());
                    for addr in addrs {
                        result.extend_from_slice(&addr.octets());
                    }
                }
                HttpsSvcParam::ECH(data) => {
                    result.extend_from_slice(&(SvcParamKeys::ech as u16).to_be_bytes());
                    let msg = Engine::decode(&STANDARD, data).unwrap();
                    result.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    result.extend_from_slice(&msg);
                }
                HttpsSvcParam::KeyValue(key, value) => {
                    result.extend_from_slice(&key.to_be_bytes());
                    result.extend_from_slice(&(value.len() as u16).to_be_bytes());
                    result.extend_from_slice(value);
                }
            }
        }
        result
    }
}
