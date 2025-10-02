use crate::dns::SVC_Param_Keys;
use crate::dns_helper::{
    dns_parse_slice, dns_read_u16, dns_read_u8, names_list, parse_ipv4, parse_ipv6,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[derive(Debug, Clone)]
pub enum HttpsSvcParam {
    Alpn(Vec<String>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<Ipv4Addr>),
    Ipv6Hint(Vec<Ipv6Addr>),
    ECH(Vec<u8>),
    Mandatory(Vec<SVC_Param_Keys>),
    DohPath(String),
    KeyValue(u16, Vec<u8>), // Catch-all for unknown or private keys
    Ohttp,
    Tls_supported_groups(Vec<u16>), // list of 16 bit numbers
    DocPath(Vec<String>),  // like txt record 8 bit length / n byte string
}

#[derive(Debug, Clone, Default)]
pub struct RR_HTTPS {
    pub(crate) prio: u16,
    pub(crate) target: String,
    pub(crate) param: Vec<HttpsSvcParam>,
}

impl RR_HTTPS {
    pub(crate) fn new() -> RR_HTTPS {
        RR_HTTPS::default()
    }
    pub(crate) fn set(&mut self, target: &str, prio: u16, param: &[HttpsSvcParam]) {
        self.prio = prio;
        self.param = param.to_vec();
        self.target = target.to_string();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_HTTPS, Parse_error> {
        let mut params: Vec<HttpsSvcParam> = vec![];
        let prio = dns_read_u16(rdata, 0)?;
        let (target, mut offset) = dns_parse_name(rdata, 2)?;
        let rdata_len = rdata.len();
        while offset < rdata_len {
            let svc_val = dns_read_u16(rdata, offset)?;
            let svc_param_key = SVC_Param_Keys::find(svc_val).unwrap_or_default();
            let svc_param_len = dns_read_u16(rdata, offset + 2)? as usize;
            match svc_param_key {
                SVC_Param_Keys::key_value => {
                    let value = String::from_utf8_lossy(dns_parse_slice(
                        rdata,
                        offset + 4..offset + 4 + svc_param_len,
                    )?);
                    params.push(HttpsSvcParam::KeyValue(
                        svc_val as u16,
                        value.into_owned().into_bytes(),
                    ));
                }
                SVC_Param_Keys::doh_path => {
                    let doh_path = String::from_utf8_lossy(dns_parse_slice(
                        rdata,
                        offset + 4..offset + 4 + svc_param_len,
                    )?)
                        .into_owned(); // Convert to owned String

                    params.push(HttpsSvcParam::DohPath(doh_path));
                }
                SVC_Param_Keys::mandatory => {
                    let mut pos = 0;
                    let mut keys: Vec<SVC_Param_Keys> = vec![];
                    while pos < svc_param_len {
                        let man_val = SVC_Param_Keys::find(dns_read_u16(rdata, offset + pos + 4)?)
                            .map_err(|_| Parse_error::new(Invalid_Parameter, ""))?;
                        keys.push(man_val);
                        pos += 2;
                    }
                    params.push(HttpsSvcParam::Mandatory(keys));
                }
                SVC_Param_Keys::docpath => {
                    let mut pos = 0;
                    let mut values: Vec<String> = vec![];
                    while pos < svc_param_len {
                        let docpath_len = usize::from(dns_read_u8(rdata, offset + pos + 4)?);
                        let docpath = String::from_utf8_lossy(dns_parse_slice(
                            rdata,
                            offset + pos + 4 + 1..offset + pos + 4 + 1 + docpath_len,
                        )?)
                            .into_owned(); // Convert to owned String
                        values.push(docpath);
                        pos += 1 + docpath_len;
                    }
                    params.push(HttpsSvcParam::Alpn(values));
                }
                SVC_Param_Keys::alpn => {
                    let mut pos = 0;
                    let mut values: Vec<String> = vec![];
                    while pos < svc_param_len {
                        let alpn_len = usize::from(dns_read_u8(rdata, offset + pos + 4)?);
                        let alpn = String::from_utf8_lossy(dns_parse_slice(
                            rdata,
                            offset + pos + 4 + 1..offset + pos + 4 + 1 + alpn_len,
                        )?)
                            .into_owned(); // Convert to owned String
                        values.push(alpn);
                        pos += 1 + alpn_len;
                    }
                    params.push(HttpsSvcParam::Alpn(values));
                }
                SVC_Param_Keys::ech => {
                    let data_str = dns_parse_slice(rdata, offset + 4..offset + 4 + svc_param_len)?;
                    params.push(HttpsSvcParam::ECH(data_str.into()));
                }
                SVC_Param_Keys::ipv4hint => {
                    let mut pos: usize = 0;
                    let mut ipv4hints: Vec<Ipv4Addr> = vec![];
                    while pos + 4 <= svc_param_len {
                        let loc = offset + 4 + pos;
                        let addr: Ipv4Addr =
                            match parse_ipv4(dns_parse_slice(rdata, loc..loc + 4)?)? {
                                IpAddr::V4(v4) => v4,
                                IpAddr::V6(_) => {
                                    return Err(Parse_error::new(
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
                SVC_Param_Keys::ipv6hint => {
                    let mut pos: usize = 0;
                    let mut ipv6hints: Vec<Ipv6Addr> = vec![];
                    while pos + 16 <= svc_param_len {
                        let loc = offset + 4 + pos;
                        let addr: Ipv6Addr =
                            match parse_ipv6(dns_parse_slice(rdata, loc..loc + 16)?)? {
                                IpAddr::V6(v6) => v6,
                                IpAddr::V4(_) => {
                                    return Err(Parse_error::new(
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
                SVC_Param_Keys::no_default_alpn => {
                    params.push(HttpsSvcParam::NoDefaultAlpn);
                }
                SVC_Param_Keys::ohttp => {
                    params.push(HttpsSvcParam::Ohttp);
                }
                SVC_Param_Keys::tls_supported_groups => {
                    let mut pos = 0;
                    let mut values: Vec<u16> = vec![];
                    while pos < svc_param_len {
                        let value = dns_read_u16(rdata, offset + pos + 4)?;
                        values.push(value);
                        pos += 2;
                    }
                    params.push(HttpsSvcParam::Tls_supported_groups(values));
                }
                SVC_Param_Keys::port => {
                    let port = dns_read_u16(rdata, offset + 4)?;
                    params.push(HttpsSvcParam::Port(port));
                }
            }
            offset += 4 + svc_param_len;
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
                    let mut res1 = String::new();
                    for val in values {
                        res1.push_str(&format!("{val},"));
                    }
                    res1.pop();
                    write!(f, " mandatory={res1}")?;
                }

                HttpsSvcParam::Alpn(values) => {
                    let mut res1 = String::new();
                    for val in values {
                        res1.push_str(&format!("{val},"));
                    }
                    res1.pop();
                    write!(f, " alpn={res1}")?;
                }
                HttpsSvcParam::DohPath(values) => {
                    write!(f, " dohpath={values}")?;
                }
                HttpsSvcParam::Ohttp => {
                    write!(f, "ohttp")?;
                }
                HttpsSvcParam::NoDefaultAlpn => {
                    write!(f, "no-default-alpn")?;
                }
                HttpsSvcParam::Port(port) => {
                    write!(f, " port={port}")?;
                }
                HttpsSvcParam::Tls_supported_groups(values) => {
                    let mut res1 = String::new();
                    for group in values {
                        res1.push_str(&format!("{group},"));
                    }
                    res1.pop();
                    write!(f, " tls_supported-groups={res1}")?;
                }
                HttpsSvcParam::Ipv4Hint(addrs) => {
                    let mut res1 = String::new();
                    for addr in addrs {
                        res1.push_str(&format!("{addr},"));
                    }
                    res1.pop();
                    write!(f, " ipv4hint={res1}")?;
                }
                HttpsSvcParam::DocPath(addrs) => {
                    let mut res1 = String::new();
                    res1.push_str("/");
                    for addr in addrs {
                        res1.push_str(&format!("{addr}/,"));
                    }
                    res1.pop();
                    write!(f, " ipv6hint={res1}")?;
                }
                HttpsSvcParam::Ipv6Hint(addrs) => {
                    let mut res1 = String::new();
                    for addr in addrs {
                        res1.push_str(&format!("{addr},"));
                    }
                    res1.pop();
                    write!(f, " ipv6hint={res1}")?;
                }
                HttpsSvcParam::ECH(data) => {
                    write!(f, " ech={}", &STANDARD.encode(data))?;
                }
                HttpsSvcParam::KeyValue(key, value) => {
                    write!(f, " key{}={}", key, STANDARD.encode(value))?;
                }
            }
        }
        write!(f, "")
    }
}

impl DNSRecord for RR_HTTPS {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::HTTPS
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.prio.to_be_bytes());

        // Add the target name
        for part in self.target.split('.') {
            if !part.is_empty() {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
        }
        result.push(0); // null terminator

        // Add parameters
        for param in &self.param {
            match param {
                HttpsSvcParam::Mandatory(keys) => {
                    result.extend_from_slice(&(SVC_Param_Keys::mandatory as u16).to_be_bytes());
                    let param_len = keys.len() * 2;
                    result.extend_from_slice(&(param_len as u16).to_be_bytes());
                    for key in keys {
                        result.extend_from_slice(&(*key as u16).to_be_bytes());
                    }
                }
                HttpsSvcParam::Tls_supported_groups(values) => {
                    result.extend_from_slice(&(SVC_Param_Keys::tls_supported_groups as u16).to_be_bytes());
                    let param_len = 2 * values.len(); // length byte + string
                    result.extend_from_slice(&(param_len as u16).to_be_bytes());
                    for val in values {
                        result.extend_from_slice(&val.to_be_bytes());
                    }
                }
                HttpsSvcParam::Alpn(values) => {
                    result.extend_from_slice(&(SVC_Param_Keys::alpn as u16).to_be_bytes());
                    let mut param_len = 0;
                    for val in values {
                        param_len += val.len() + 1; // length byte + string
                    }
                    result.extend_from_slice(&(param_len as u16).to_be_bytes());
                    for val in values {
                        result.push(val.len() as u8);
                        result.extend_from_slice(val.as_bytes());
                    }
                }
                HttpsSvcParam::DohPath(values) => {
                    result.extend_from_slice(&(SVC_Param_Keys::doh_path as u16).to_be_bytes());
                    result.extend_from_slice(&(values.len() as u16).to_be_bytes());
                    result.extend_from_slice(values.as_bytes());
                }

                HttpsSvcParam::Ohttp => {
                    result
                        .extend_from_slice(&(SVC_Param_Keys::ohttp as u16).to_be_bytes());
                    result.extend_from_slice(&0u16.to_be_bytes());
                }
                HttpsSvcParam::NoDefaultAlpn => {
                    result
                        .extend_from_slice(&(SVC_Param_Keys::no_default_alpn as u16).to_be_bytes());
                    result.extend_from_slice(&0u16.to_be_bytes());
                }
                HttpsSvcParam::Port(port) => {
                    result.extend_from_slice(&(SVC_Param_Keys::port as u16).to_be_bytes());
                    result.extend_from_slice(&2u16.to_be_bytes());
                    result.extend_from_slice(&port.to_be_bytes());
                }
                HttpsSvcParam::Ipv4Hint(addrs) => {
                    result.extend_from_slice(&(SVC_Param_Keys::ipv4hint as u16).to_be_bytes());
                    result.extend_from_slice(&((addrs.len() * 4) as u16).to_be_bytes());
                    for addr in addrs {
                        result.extend_from_slice(&addr.octets());
                    }
                }
                HttpsSvcParam::DocPath(addrs) => {
                    result.extend_from_slice(&(SVC_Param_Keys::docpath as u16).to_be_bytes());
                    let mut param_len:u16 = 0;
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
                    result.extend_from_slice(&(SVC_Param_Keys::ipv6hint as u16).to_be_bytes());
                    result.extend_from_slice(&((addrs.len() *16) as u16).to_be_bytes());
                    for addr in addrs {
                        result.extend_from_slice(&addr.octets());
                    }
                }
                HttpsSvcParam::ECH(data) => {
                    result.extend_from_slice(&(SVC_Param_Keys::ech as u16).to_be_bytes());
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
