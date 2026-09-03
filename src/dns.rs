use crate::errors::DnsErrorType::InvalidParam;
use crate::errors::ParseErrorType::InvalidParameter;
use crate::errors::{DnsError, ParseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::IntoStaticStr;
use strum_macros::{EnumIter, FromRepr};

pub(crate) fn tlsa_cert_usage(u: u8) -> Result<&'static str, ParseError> {
    match u {
        0 => Ok("PKIX-TA"),
        1 => Ok("PKIX-EE"),
        2 => Ok("DANE-TA"),
        3 => Ok("DANE-EE"),
        _ => Err(ParseError::new(
            InvalidParameter,
            "Unknown certificate usage",
        )),
    }
}

pub(crate) fn tlsa_selector(u: u8) -> Result<&'static str, ParseError> {
    match u {
        0 => Ok("All"),
        1 => Ok("Pubkey"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown TLSA selector")),
    }
}

pub(crate) fn tlsa_algorithm(u: u8) -> Result<&'static str, ParseError> {
    match u {
        0 => Ok("None"),
        1 => Ok("SHA2-256"),
        2 => Ok("SHA2-512"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}
pub(crate) fn key_protocol(u: u8) -> Result<&'static str, ParseError> {
    match u {
        1 => Ok("TLS"),
        2 => Ok("email"),
        3 => Ok("dnssec"),
        4 => Ok("ipsec"),
        255 => Ok("all"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}

pub(crate) fn sshfp_algorithm(u: u8) -> Result<&'static str, ParseError> {
    match u {
        1 => Ok("RSA"),
        2 => Ok("DSS"),
        3 => Ok("ECDSA"),
        4 => Ok("Ed25519"),
        5 => Ok("Ed448"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}

pub(crate) fn sshfp_fp_type(u: u8) -> Result<&'static str, ParseError> {
    match u {
        1 => Ok("SHA-1"),
        2 => Ok("SHA2-256"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}

pub(crate) fn dnssec_algorithm(u: u8) -> Result<&'static str, ParseError> {
    match u {
        0 | 9 | 11 | 123u8..=251u8 => Ok("Reserved"),
        1 => Ok("RSA/MD5"),
        2 => Ok("DH"),
        3 => Ok("DSA/SHA1"),
        5 => Ok("RSA/SHA1"),
        6 => Ok("DSA-NSEC3-SHA1"),
        7 => Ok("RSASHA1-NSEC3-SHA1"),
        8 => Ok("RSA/SHA2-256"),
        10 => Ok("RSA/SHA2-512"),
        12 => Ok("ECC-GOST"),
        13 => Ok("ECDSA/SHA2-256"),
        14 => Ok("ECDSA/SHA2-384"),
        15 => Ok("Ed25519"),
        16 => Ok("Ed448"),
        17 => Ok("SM2SM3"),
        23 => Ok("ECC-GOST12"),
        252 => Ok("Indirect"),
        253 => Ok("PrivateDNS"),
        254 => Ok("PrivateOID"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}

pub(crate) fn dnssec_digest(u: u8) -> Result<&'static str, ParseError> {
    match u {
        0 => Ok("Reserved"),
        1 => Ok("SHA1"),
        2 => Ok("SHA2-256"),
        3 => Ok("GOST R 34.10-2001"),
        4 => Ok("SHA2-384"),
        5 => Ok("GOST R 34.11-2012"),
        6 => Ok("SM3"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown digest")),
    }
}

pub(crate) fn zonemd_digest(u: u8) -> Result<&'static str, ParseError> {
    match u {
        1 => Ok("SHA2-384"),
        2 => Ok("SHA2-512"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown digest")),
    }
}

pub(crate) fn ipsec_alg(alg: u8) -> Result<&'static str, ParseError> {
    match alg {
        1 => Ok("DSA"),
        2 => Ok("RSA"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}

pub(crate) fn dhcid_alg(alg: u8) -> Result<&'static str, ParseError> {
    match alg {
        0 => Ok("Reserved"),
        1 => Ok("SHA-256"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown algorithm")),
    }
}
pub(crate) fn cert_type_str(t: u16) -> Result<&'static str, ParseError> {
    match t {
        1 => Ok("PKIX"),
        2 => Ok("SKPI"),
        3 => Ok("PGP"),
        4 => Ok("IPKIX"),
        5 => Ok("ISPKI"),
        6 => Ok("IPGP"),
        7 => Ok("ACPKIX"),
        8 => Ok("IACPKIX"),
        253 => Ok("URI"),
        254 => Ok("OID"),
        65280..=65534 => Ok("Experimental"),
        _ => Err(ParseError::new(InvalidParameter, "Unknown digest")),
    }
}

#[derive(
    Default,
    Debug,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Hash,
    PartialEq,
    Eq,
    EnumIter,
    IntoStaticStr,
    FromRepr,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
pub enum SvcParamKeys {
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    Ipv4hint = 4,
    Ech = 5,
    Ipv6hint = 6,
    DohPath = 7,
    Ohttp = 8,
    TlsSupportedGroups = 9,
    Docpath = 10,
    Pvd = 11,
    #[default]
    KeyValue = 255,
    Invalid = 65535,
}

impl SvcParamKeys {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DnsError> {
        match SvcParamKeys::from_repr(val) {
            Some(x) => Ok(x),
            None => Err(DnsError::new(InvalidParam, &format!("{val}"))),
        }
    }
}

impl fmt::Display for SvcParamKeys {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}
