use crate::dns::DNS_RR_type::Private;
use crate::errors::{DNS_Error_Type, DNS_error, Parse_error};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr as _;
use strum::IntoEnumIterator as _;
use strum_macros::{EnumIter, FromRepr};
use strum_macros::{EnumString, IntoStaticStr};
use tracing::debug;

#[derive(
    Debug,
    EnumIter,
    Copy,
    Clone,
    PartialEq,
    Eq,
    EnumString,
    IntoStaticStr,
    Hash,
    Serialize,
    Deserialize,
    FromRepr,
    PartialOrd,
    Ord
)]
pub(crate) enum DNS_Opcodes {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DSO = 6,
}

impl DNS_Opcodes {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DNS_Opcodes::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(
                DNS_Error_Type::Invalid_Opcode,
                &format!("{val}"),
            )),
        }
    }
}

impl fmt::Display for DNS_Opcodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_opcodes_tests {
    use crate::dns::DNS_Opcodes;

    #[test]
    fn test_dns_opcodes() {
        assert_eq!(DNS_Opcodes::Query.to_str(), "Query");
        assert_eq!(DNS_Opcodes::Update.to_str(), "Update");
    }
    #[test]
    fn test_dns_opcodes1() {
        assert_eq!(DNS_Opcodes::find(4).unwrap(), DNS_Opcodes::Notify);
    }
}

#[derive(
    Debug,
    Hash,
    EnumIter,
    Copy,
    Clone,
    PartialEq,
    PartialOrd,
    Ord,
    Eq,
    EnumString,
    IntoStaticStr,
    Serialize,
    Deserialize,
    FromRepr,
)]
pub(crate) enum DNS_Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
}

impl DNS_Class {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        if let Some(x) = DNS_Class::from_repr(usize::from(val)) { Ok(x) } else {
            debug!("Error wrong class value {}", val);
            Err(DNS_error::new(
                DNS_Error_Type::Invalid_Class,
                &format!("{val}"),
            ))
        }
        
    }
}

impl fmt::Display for DNS_Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_class_tests {
    use crate::dns::DNS_Class;

    #[test]
    fn test_dns_class2() {
        assert_eq!(DNS_Class::IN.to_str(), "IN");
    }
    #[test]
    fn test_dns_class1() {
        assert_eq!(DNS_Class::find(4).unwrap(), DNS_Class::HS);
    }
    #[test]
    fn test_dns_class3() {
        assert_eq!(DNS_Class::find(255).unwrap(), DNS_Class::ANY);
    }
}

#[derive(
    Hash,
    Debug,
    EnumIter,
    Copy,
    Clone,
    IntoStaticStr,
    EnumString,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    FromRepr,
    PartialOrd,
    Ord
)]
pub(crate) enum DNS_RR_type {
    A = 1,
    A6 = 38,
    AAAA = 28,
    AFSDB = 18,
    AMTRELAY = 260,
    ANY = 255,
    APL = 42,
    ATMA = 34,
    AVC = 258,
    AXFR = 252,
    CAA = 257,
    CDNSKEY = 60,
    CDS = 59,
    CERT = 37,
    CLA = 263,
    CNAME = 5,
    CSYNC = 62,
    DHCID = 49,
    DLV = 32769,
    DNAME = 39,
    DNSKEY = 48,
    DOA = 259,
    DS = 43,
    DSYNC= 66,
    EID = 31,
    EUI48 = 108,
    EUI64 = 109,
    GID = 102,
    GPOS = 27,
    HINFO = 13,
    HIP = 55,
    HTTPS = 65,
    IPSECKEY = 45,
    IPN = 264,
    ISDN = 20,
    IXFR = 251,
    KEY = 25,
    KX = 36,
    L32 = 105,
    L64 = 106,
    LOC = 29,
    LP = 107,
    MAILA = 254,
    MAILB = 253,
    MB = 7,
    MD = 3,
    MF = 4,
    MG = 8,
    MINFO = 14,
    MR = 9,
    MX = 15,
    NAPTR = 35,
    //NB = 32,
    // NBSTAT = 33,
    NID = 104,
    NIMLOC = 32,
    NINF0 = 56,
    NS = 2,
    NSAP = 22,
    NSAP_PTR = 23,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    NSEC = 47,
    NULL = 10,
    NXNAME = 128,
    NXT = 30,
    OPENPGPKEY = 61,
    OPT = 41,
    PTR = 12,
    PX = 26,
    RESINFO = 261,
    RKEY = 57,
    RP = 17,
    RRSIG = 46,
    RT = 21,
    SIG = 24,
    SINK = 40,
    SMIMEA = 53,
    SOA = 6,
    SPF = 99,
    SRV = 33,
    SSHFP = 44,
    SVCB = 64,
    TA = 32768,
    TALINK = 58,
    TKEY = 249,
    TLSA = 52,
    TSIG = 250,
    TXT = 16,
    UID = 101,
    UINFO = 100,
    UNSPEC = 103,
    URI = 256,
    WALLET = 262,
    WKS = 11,
    X25 = 19,
    ZONEMD = 63,
    Private = 65534,
}

impl DNS_RR_type {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DNS_RR_type::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => {
                if val > 65280 {
                    Ok(Private)
                } else {
                    Err(DNS_error::new(
                        DNS_Error_Type::Invalid_RR,
                        &format!("{val}"),
                    ))
                }
            }
        }
    }
   
    pub(crate) fn collect_dns_rr_types() -> Vec<DNS_RR_type> {
        DNS_RR_type::iter().collect::<Vec<_>>()
    }
    #[inline]
    pub(crate) fn from_string(s: &str) -> Result<DNS_RR_type, strum::ParseError> {
        DNS_RR_type::from_str(s)
    }
}

impl fmt::Display for DNS_RR_type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod tests1 {
    use std::str::FromStr;

    use crate::dns::DNS_RR_type;

    #[test]
    fn test_dns_rr() {
        assert_eq!(DNS_RR_type::HTTPS.to_str(), "HTTPS");
        assert_eq!(DNS_RR_type::AAAA.to_str(), "AAAA");
    }
    #[test]
    fn test_dns_rr1() {
        assert_eq!(DNS_RR_type::from_str("HTTPS").unwrap(), DNS_RR_type::HTTPS);
        assert_eq!(DNS_RR_type::from_str("AAAA").unwrap(), DNS_RR_type::AAAA);
    }

    #[test]
    fn test_dns_rr2() {
        assert_eq!(DNS_RR_type::find(1).unwrap(), DNS_RR_type::A);
        assert_eq!(DNS_RR_type::find(28).unwrap(), DNS_RR_type::AAAA);
        assert_eq!(DNS_RR_type::find(65534).unwrap(), DNS_RR_type::Private);
        assert!(DNS_RR_type::find(0).is_err());
    }
}

#[derive(
    Debug,
    EnumIter,
    Copy,
    Clone,
    IntoStaticStr,
    EnumString,
    PartialEq,
    Eq,
    FromRepr,
    Serialize,
    Deserialize,
    Default,
    Hash,
    PartialOrd,
    Ord
)]
pub(crate) enum DnsReplyType {
    #[default]
    NOERROR = 0,
    FORMERROR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
    DSOTYPENI = 11,
    BADVERS = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    BADCOOKIE = 23,
}

impl DnsReplyType {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DnsReplyType::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(
                DNS_Error_Type::Invalid_reply_type,
                &format!("{val}"),
            )),
        }
    }
}

impl fmt::Display for DnsReplyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
#[cfg(test)]
mod tests2 {
    use crate::dns::{DNS_Opcodes, DnsReplyType};
    use std::str::FromStr;

    #[test]
    fn test_dns_rt() {
        assert_eq!(DnsReplyType::NXDOMAIN.to_str(), "NXDOMAIN");
        assert_eq!(DnsReplyType::NOERROR.to_str(), "NOERROR");
    }
    #[test]
    fn test_dns_rt1() {
        assert_eq!(
            DnsReplyType::from_str("NXDOMAIN").unwrap(),
            DnsReplyType::NXDOMAIN
        );
        assert_eq!(
            DnsReplyType::from_str("NOERROR").unwrap(),
            DnsReplyType::NOERROR
        );
    }
    #[test]
    fn test_dns_rt2() {
        assert_eq!(DnsReplyType::find(19).unwrap(), DnsReplyType::BADMODE);
        assert_eq!(DnsReplyType::find(23).unwrap(), DnsReplyType::BADCOOKIE);
        assert!(DNS_Opcodes::find(111).is_err());
    }
}

pub(crate) fn tlsa_cert_usage(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        0 => Ok("PKIX-TA"),
        1 => Ok("PKIX-EE"),
        2 => Ok("DANE-TA"),
        3 => Ok("DANE-EE"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown certificate usage",
        )),
    }
}

pub(crate) fn tlsa_selector(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        0 => Ok("All"),
        1 => Ok("Pubkey"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown TLSA selectory",
        )),
    }
}

pub(crate) fn tlsa_algorithm(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        0 => Ok("None"),
        1 => Ok("SHA2-256"),
        2 => Ok("SHA2-512"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown algorithm",
        )),
    }
}
pub(crate) fn key_protocol(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        1 => Ok("TLS"),
        2 => Ok("email"),
        3 => Ok("dnssec"),
        4 => Ok("ipsec"),
        255 => Ok("all"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown algorithm",
        )),
    }
}

pub(crate) fn sshfp_algorithm(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        1 => Ok("RSA"),
        2 => Ok("DSS"),
        3 => Ok("ECDSA"),
        4 => Ok("Ed25519"),
        5 => Ok("Ed448"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown algorithm",
        )),
    }
}

pub(crate) fn sshfp_fp_type(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        1 => Ok("SHA-1"),
        2 => Ok("SHA2-256"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown algorithm",
        )),
    }
}

pub(crate) fn dnssec_algorithm(u: u8) -> Result<&'static str, Parse_error> {
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

        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown algorithm",
        )),
    }
}

pub(crate) fn dnssec_digest(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        0 => Ok("Reserved"),
        1 => Ok("SHA1"),
        2 => Ok("SHA2-256"),
        3 => Ok("GOST R 34.10-2001"),
        4 => Ok("SHA2-384"),
        5 => Ok("GOST R 34.11-2012"),
        6 => Ok("SM3"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown digest",
        )),
    }
}

pub(crate) fn zonemd_digest(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        1 => Ok("SHA2-384"),
        2 => Ok("SHA2-512"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown digest",
        )),
    }
}

pub(crate) fn ipsec_alg(alg: u8) -> Result<&'static str, Parse_error> {
    match alg {
        1 => Ok("DSA"),
        2 => Ok("RSA"),
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown algorithm",
        )),
    }
}

pub(crate) fn cert_type_str(t: u16) -> Result<&'static str, Parse_error> {
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
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown digest",
        )),
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, IntoStaticStr, FromRepr)]
pub(crate) enum SVC_Param_Keys {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
}

impl SVC_Param_Keys {
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match SVC_Param_Keys::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(
                DNS_Error_Type::Invalid_RR,
                &format!("{val}"),
            )),
        }
    }
    
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
}

impl fmt::Display for SVC_Param_Keys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
