use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumString;
use strum_macros::{AsStaticStr, EnumIter};
use unic_idna::to_unicode;

use crate::errors::{DNS_Error_Type, DNS_error, Parse_error};

#[derive(Debug, EnumIter, Copy, Clone, PartialEq, Eq, EnumString, AsStaticStr)]
pub(crate) enum DNS_Opcodes {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DSO = 6,
}

impl DNS_Opcodes {
    pub(crate) fn to_str(self) -> String {
        String::from(strum::AsStaticRef::as_static(&self))
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        for oc in DNS_Opcodes::iter() {
            if (oc as u16) == val {
                return Ok(oc);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_Opcode,
            &format!("{val}"),
        ))
    }
}


impl std::fmt::Display for DNS_Opcodes {
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

#[derive(Debug, EnumIter, Copy, Clone, PartialEq, Eq, EnumString, AsStaticStr)]
pub(crate) enum DNS_Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
}

impl DNS_Class {
    pub(crate) fn to_str(self) -> String {
        String::from(strum::AsStaticRef::as_static(&self))
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        for cl in DNS_Class::iter() {
            if (cl as u16) == val {
                return Ok(cl);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_Class,
            &format!("{val}"),
        ))
    }
}

impl std::fmt::Display for DNS_Class {
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
}

#[derive(
    Debug, EnumIter, Copy, Clone, AsStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize,
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
    CNAME = 5,
    CSYNC = 62,
    DHCID = 49,
    DLV = 32769,
    DNAME = 39,
    DNSKEY = 48,
    DOA = 259,
    DS = 43,
    EID = 31,
    EUI48 = 108,
    EUI64 = 109,
    GID = 102,
    GPOS = 27,
    HINFO = 13,
    HIP = 55,
    HTTPS = 65,
    IPSECKEY = 45,
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
}

impl DNS_RR_type {
    pub(crate) fn to_str(self) -> String {
        let x = self;
        String::from(strum::AsStaticRef::as_static(&x))
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        for rr in DNS_RR_type::iter() {
            if (rr as u16) == val {
                return Ok(rr);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_RR,
            &format!("{val}"),
        ))
    }
    pub(crate) fn to_vec() -> Vec<DNS_RR_type> {
        DNS_RR_type::iter().collect::<Vec<_>>()
    }
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
}

#[derive( Debug, EnumIter, Copy, Clone, AsStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EDNS0ptionCodes {
    LLQ = 1,
    UpdateLease = 2,
    NSID = 3,
    DAU = 4,
    DHU = 5,
    N3U = 6,
    EdnsClientSubnet = 8,
    EDNSEXPIRE = 9,
    COOKIE = 10,
    EdnsTcpKeepalive = 11,
    Padding = 12,
    CHAIN = 13,
    EdnsKeyTag = 14,
    ExtendedDNSError = 15,
    EDNSClientTag = 16,
    EDNSServerTag = 17,
    ReportChannel = 18,
    UmbrellaIdent = 20292,
    DeviceID = 26946,
}


impl EDNS0ptionCodes {
    pub(crate) fn to_str(self) -> String {
        String::from(strum::AsStaticRef::as_static(&self))
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        for ee in EDNS0ptionCodes::iter() {
            if (ee as u16) == val {
                return Ok(ee);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_Extended_Option_Code,
            &val.to_string(),
        ))
    }
}

impl std::fmt::Display for EDNS0ptionCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive( Debug, EnumIter, Copy, Clone, AsStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DNSExtendedError {
    None = 0xffff,
    Other = 0,
    Unsupported_DNSKEY_Algorithm = 1,
    Unsupported_DS_Digest_Type = 2,
    Stale_Answer = 3,
    Forged_Answer = 4,
    DNSSEC_Indeterminate = 5,
    DNSSEC_Bogus = 6,
    Signature_Expired = 7,
    Signature_Not_Yet_Valid = 8,
    DNSKEY_Missing = 9,
    RRSIGs_Missing = 10,
    No_Zone_Key_Bit_Set = 11,
    NSEC_Missing = 12,
    Cached_Error = 13,
    Not_Ready = 14,
    Blocked = 15,
    Censored = 16,
    Filtered = 17,
    Prohibited = 18,
    Stale_NXDOMAIN_Answer = 19,
    Not_Authoritative = 20,
    Not_Supported = 21,
    No_Reachable_Authority = 22,
    Network_Error = 23,
    Invalid_Data = 24,
    Synthesized = 29,
}

impl DNSExtendedError {
    pub(crate) fn to_str(self) -> String {
        String::from(strum::AsStaticRef::as_static(&self))
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        for ee in DNSExtendedError::iter() {
            if (ee as u16) == val {
                return Ok(ee);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_Extended_Error_Code,
            &val.to_string(),
        ))
    }
}


impl std::fmt::Display for DNSExtendedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
#[derive(Debug, Clone)]

pub(crate) struct DNS_record {
    pub(crate) rr_type: String,
    pub(crate) ttl: u32,
    pub(crate) class: String,
    pub(crate) name: String,
    pub(crate) rdata: String,
    pub(crate) count: u64,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) domain: String,
    pub(crate) asn: String,
    pub(crate) asn_owner: String,
    pub(crate) prefix: String,
    pub(crate) error: DnsReplyType,
    pub(crate) extended_error: DNSExtendedError,
}

impl DNS_record {}

impl std::fmt::Display for DNS_record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let mut s = to_unicode(
                &self.name,
                unic_idna::Flags {
                    transitional_processing: false,
                    verify_dns_length: true,
                    use_std3_ascii_rules: true,
                },
            )
            .0;
            if s == self.name {
                s = String::new();
            } else {
                s = format!("({s}) ");
            }
            writeln!(
                f,
                "  {} {}{} {} {} {} {} {} {} {} ({}) {} {} {}",
                snailquote::escape(&self.name),
                s,
                self.class,
                self.rr_type,
                self.rdata,
                self.ttl,
                self.timestamp,
                self.domain,
                self.prefix,
                self.asn,
                self.asn_owner,
                self.error,
                self.extended_error.to_str(),
                self.count,
            )
        } else {
            writeln!(
                f,
                "Name: {} ({})
            RData: {}  
            RR Type: {}    Class: {}     TTL: {}
            Count: {}      Time: {}
            Domain: {}
            ASN: {}        ASN Owner: {}
            Prefix: {}
            Error: {},
            ExtError: {}",
                snailquote::escape(&self.name),
                to_unicode(
                    &self.name,
                    unic_idna::Flags {
                        transitional_processing: false,
                        verify_dns_length: true,
                        use_std3_ascii_rules: true
                    }
                )
                .0,
                self.rdata,
                self.rr_type,
                self.class,
                self.ttl,
                self.count,
                self.timestamp,
                self.domain,
                self.asn,
                self.asn_owner,
                self.prefix,
                self.error,
                self.extended_error
            )
        }
    }
}

#[derive(
    Debug, EnumIter, Copy, Clone, AsStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize,
)]
pub(crate) enum DnsReplyType {
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
    pub(crate) fn to_str(self) -> String {
        String::from(strum::AsStaticRef::as_static(&self))
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        for rr in DnsReplyType::iter() {
            if (rr as u16) == val {
                return Ok(rr);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_reply_type,
            &val.to_string(),
        ))
    }
}

impl std::fmt::Display for DnsReplyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
#[cfg(test)]
mod tests2 {
    use crate::dns::DnsReplyType;
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
}

pub(crate) fn dns_reply_type(u: u16) -> Result<String, Box<dyn std::error::Error>> {
    Ok(DnsReplyType::find(u)?.to_str())
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

pub(crate) fn key_algorithm(u: u8) -> Result<&'static str, Parse_error> {
    match u {
        1 => Ok("RSA/MD5"),
        2 => Ok("DH"),
        3 => Ok("DSA"),
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
        0 => Ok("Reserved"),
        1 => Ok("RSA/MD5"),
        3 => Ok("DSA/SHA1"),
        5 => Ok("RSA/SHA1"),
        6 => Ok("DSA-NSEC3-SHA1"),
        7 => Ok("RSASHA1-NSEC3-SHA1"),
        8 => Ok("RSA/SHA2-256"),
        10 => Ok("RSA/SHA2-512"),
        12 => Ok("GOST"),
        13 => Ok("ECDSA/SHA2-256"),
        14 => Ok("ECDSA/SHA2-384"),
        15 => Ok("Ed25519"),
        16 => Ok("Ed448"),
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
        _ => Err(Parse_error::new(
            crate::errors::ParseErrorType::Invalid_Parameter,
            "Unknown digest",
        )),
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, AsStaticStr)]
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
        for k in SVC_Param_Keys::iter() {
            if (k as u16) == val {
                return Ok(k);
            }
        }
        Err(DNS_error::new(
            DNS_Error_Type::Invalid_RR,
            &format!("{val}"),
        ))
    }
}
