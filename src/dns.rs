use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use strum::IntoEnumIterator;
use strum_macros::EnumString;
use strum_macros::{AsStaticStr, EnumIter};

#[derive(Debug, EnumIter, Copy, Clone, PartialEq, Eq)]
pub enum DNS_Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,
}

impl DNS_Class {
    pub fn to_str(self) -> Result<String, Box<dyn std::error::Error>> {
        if self == DNS_Class::IN {
            return Ok("IN".parse().unwrap());
        } else if self == DNS_Class::CS {
            return Ok(("CS").parse().unwrap());
        } else if self == DNS_Class::CH {
            return Ok(("CH").parse().unwrap());
        } else if self == DNS_Class::HS {
            return Ok(("HS").parse().unwrap());
        } else {
            return Err(format!("Invalid Class {:?}", self).into());
        }
    }
    pub fn find(val: u16) -> Result<Self, Box<dyn std::error::Error>> {
        for cl in DNS_Class::iter() {
            if (cl as u16) == val {
                return Ok(cl);
            }
        }
        return Err(format!("Invalid Class type  {:?}", val).into());
    }
}

#[derive(Debug, EnumIter, Copy, Clone, AsStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize)]
pub enum DNS_RR_type {
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
    WKS = 11,
    X25 = 19,
    ZONEMD = 63,
}

impl DNS_RR_type {
    pub fn to_str(self) -> Result<String, Box<dyn std::error::Error>> {
        let x = self;
        return Ok(String::from(strum::AsStaticRef::as_static(&x)));
    }

    pub fn find(val: u16) -> Result<Self, Box<dyn std::error::Error>> {
        for rr in DNS_RR_type::iter() {
            if (rr as u16) == val {
                return Ok(rr);
            }
        }
        return Err(format!("Invalid RR type  {:?}", val).into());
    }
}

impl fmt::Display for DNS_RR_type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "{}", self.to_str().expect("RRtype Not found"));
    }
}

#[derive(Debug, Clone)]
pub struct DNS_record {
    pub(crate) rr_type: String,
    pub(crate) ttl: u32,
    pub(crate) class: String,
    pub(crate) name: String,
    pub(crate) rdata: String,
    pub(crate) count: u64,
    pub(crate) timestamp: DateTime<Utc>,
}

impl DNS_record {
    pub fn to_str(&self) -> Result<String, Box<dyn std::error::Error>> {
        return Ok(format!(
            "{} {} {} {} {}",
            self.name, self.rr_type, self.class, self.ttl, self.rdata
        ));
    }
}

impl std::fmt::Display for DNS_record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(
            f,
            "Name: {} 
            RData: {}  
            RR Type: {}
            Class:{}
            Count: {}
            Time: {}",
            self.name, self.rdata, self.rr_type, self.class, self.count, self.timestamp
        );
    }
}

impl Default for DNS_record {
    fn default() -> Self {
        DNS_record {
            rr_type: String::new(),
            ttl: 0,
            class: String::new(),
            name: String::new(),
            rdata: String::new(),
            count: 0,
            timestamp: Utc::now(),
        }
    }
}

pub fn dns_reply_type(u: u16) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("NOERROR");
        }
        1 => {
            return Ok("FORMERROR");
        }
        2 => {
            return Ok("SERVFAIL");
        }
        3 => {
            return Ok("NXDOMAIN");
        }
        4 => {
            return Ok("NOTIMP");
        }
        5 => {
            return Ok("REFUSED");
        }
        6 => {
            return Ok("YXDOMAIN");
        }
        7 => {
            return Ok("YXRRSET");
        }
        8 => {
            return Ok("NXRRSET");
        }
        9 => {
            return Ok("NOTAUTH");
        }
        10 => {
            return Ok("NOTZONE");
        }
        11 => {
            return Ok("DSOTYPENI");
        }
        16 => {
            return Ok("BADVERS");
        }
        17 => {
            return Ok("BADKEY");
        }
        18 => {
            return Ok("BADTIME");
        }
        19 => {
            return Ok("BADMODE");
        }
        20 => {
            return Ok("BADNAME");
        }
        21 => {
            return Ok("BADALG");
        }
        22 => {
            return Ok("BADTRUNC");
        }
        23 => {
            return Ok("BADCOOKIE");
        }
        _ => {
            return Err("Unkown error".into());
        }
    }
}

pub fn tlsa_cert_usage(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("PKIX-TA");
        }
        1 => {
            return Ok("PKIX-EE");
        }
        2 => {
            return Ok("DANE-TA");
        }
        3 => {
            return Ok("DANE-EE");
        }
        _ => {
            return Err("Unkown usage".into());
        }
    };
}

pub fn tlsa_selector(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("All");
        }
        1 => {
            return Ok("Pubkey");
        }
        _ => {
            return Err("Unkown selector".into());
        }
    };
}

pub fn tlsa_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("None");
        }
        1 => {
            return Ok("SHA2-256");
        }
        2 => {
            return Ok("SHA2-512");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    };
}
pub fn key_protocol(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("TLS");
        }
        2 => {
            return Ok("email");
        }
        3 => {
            return Ok("dnssec");
        }
        4 => {
            return Ok("ipsec");
        }
        255 => {
            return Ok("all");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    }
}

pub fn key_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("RSA/MD5");
        }
        2 => {
            return Ok("DH");
        }
        3 => {
            return Ok("DSA");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    }
}

pub fn sshfp_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("RSA");
        }
        2 => {
            return Ok("DSS");
        }
        3 => {
            return Ok("ECDSA");
        }
        4 => {
            return Ok("Ed25519");
        }
        5 => {
            return Ok("Ed448");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    }
}

pub fn sshfp_fp_type(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("SHA-1");
        }
        2 => {
            return Ok("SHA2-256");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    }
}

pub fn dnssec_algorithm(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        0 => {
            return Ok("Reserved");
        }
        1 => {
            return Ok("RSA/MD5");
        }
        3 => {
            return Ok("DSA/SHA1");
        }
        5 => {
            return Ok("RSA/SHA1");
        }
        6 => {
            return Ok("DSA-NSEC3-SHA1");
        }
        7 => {
            return Ok("RSASHA1-NSEC3-SHA1");
        }
        8 => {
            return Ok("RSA/SHA2-256");
        }
        10 => {
            return Ok("RSA/SHA2-512");
        }
        12 => {
            return Ok("GOST");
        }
        13 => {
            return Ok("ECDSA/SHA2-256");
        }
        14 => {
            return Ok("ECDSA/SHA2-384");
        }
        15 => {
            return Ok("Ed25519");
        }
        16 => {
            return Ok("Ed448");
        }
        _ => {
            return Err("Unkown algorithm".into());
        }
    };
}

pub fn dnssec_digest(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    print!("Digist {:x}", u);
    match u {
        0 => {
            return Ok("Reserved");
        }
        1 => {
            return Ok("SHA1");
        }
        2 => {
            return Ok("SHA2-256");
        }
        3 => {
            return Ok("GOST R 34.10-2001");
        }
        4 => {
            return Ok("SHA2-384");
        }
        _ => {
            return Err("Unkown digest".into());
        }
    };
}

pub fn zonemd_digest(u: u8) -> Result<&'static str, Box<dyn std::error::Error>> {
    match u {
        1 => {
            return Ok("SHA2-384");
        }
        2 => {
            return Ok("SHA2-512");
        }
        _ => {
            return Err("Unkown digest".into());
        }
    };
}

pub fn cert_type_str(t: u16) -> Result<&'static str, Box<dyn std::error::Error>> {
    match t {
        1 => {
            return Ok("PKIX");
        }
        2 => {
            return Ok("SKPI");
        }
        3 => {
            return Ok("PGP");
        }
        4 => {
            return Ok("IPKIX");
        }
        5 => {
            return Ok("ISPKI");
        }
        6 => {
            return Ok("IPGP");
        }
        7 => {
            return Ok("ACPKIX");
        }
        8 => {
            return Ok("IACPKIX");
        }
        253 => {
            return Ok("URI");
        }
        254 => {
            return Ok("OID");
        }
        _ => {
            return Err("Unkown digest".into());
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, AsStaticStr)]
pub enum SVC_Param_Keys {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
}

impl SVC_Param_Keys {
    pub fn find(val: u16) -> Result<Self, Box<dyn std::error::Error>> {
        for k in SVC_Param_Keys::iter() {
            if (k as u16) == val {
                return Ok(k);
            }
        }
        return Err(format!("Invalid RR type  {:?}", val).into());
    }
}
