use crate::dns_rr_type::DNS_RR_type::Private;
use crate::errors::DNS_Error_Type::Invalid_RR;
use crate::errors::DNS_error;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};

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
    Ord,
    Default,
)]
pub enum DNS_RR_type {
    #[default]
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
    BRID = 68,
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
    DSYNC = 66,
    EID = 31,
    EUI48 = 108,
    EUI64 = 109,
    GID = 102,
    GPOS = 27,
    HINFO = 13,
    HIP = 55,
    HHIT = 67,
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
    NINFO = 56,
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
                    Err(DNS_error::new(Invalid_RR, &format!("{val}")))
                }
            }
        }
    }

    #[inline]
    pub(crate) fn collect_dns_rr_types() -> Vec<DNS_RR_type> {
        DNS_RR_type::iter().collect::<Vec<_>>()
    }
    #[inline]
    pub(crate) fn from_string(s: &str) -> Result<DNS_RR_type, strum::ParseError> {
        DNS_RR_type::from_str(s)
    }
}

impl fmt::Display for DNS_RR_type {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl From<DNS_RR_type> for u16 {
    #[inline]
    fn from(t: DNS_RR_type) -> Self {
        t as u16
    }
}

// (Optional) If you also want ergonomic conversion from references:
impl From<&DNS_RR_type> for u16 {
    #[inline]
    fn from(t: &DNS_RR_type) -> Self {
        (*t) as u16
    }
}
#[cfg(test)]
mod tests1 {
    use std::str::FromStr;

    use crate::dns_rr_type::DNS_RR_type;

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
