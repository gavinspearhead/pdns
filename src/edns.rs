use crate::errors::DNS_Error_Type::{Invalid_Extended_Error_Code, Invalid_Extended_Option_Code};
use crate::errors::DNS_error;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::{EnumIter, FromRepr};
use strum_macros::{EnumString, IntoStaticStr};

#[derive(
    Debug,
    Hash,
    IntoStaticStr,
    EnumIter,
    Copy,
    Clone,
    EnumString,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    FromRepr,
)]

pub(crate) enum EDNSOptionCodes {
    LLQ = 1,
    UpdateLease = 2,
    NSID = 3,
    DAU = 5,
    DHU = 6,
    N3U = 7,
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
    ZoneVersion = 19,
    UmbrellaIdent = 20292,
    DeviceID = 26946,
}

impl EDNSOptionCodes {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match EDNSOptionCodes::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(
                Invalid_Extended_Option_Code,
                &format!("{val}"),
            )),
        }
    }
}

impl fmt::Display for EDNSOptionCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(
    Debug,
    EnumIter,
    Copy,
    Clone,
    FromRepr,
    IntoStaticStr,
    EnumString,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    PartialOrd,
    Ord,
    Hash,
)]
pub(crate) enum DNSExtendedError {
    #[default]
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
    Signature_Expired_Before_Valid = 25,
    Too_Early = 26,
    Unsupported_NSEC3_Iterations_Value = 27,
    Unable_To_Conform_To_Policy = 28,
    Synthesized = 29,
    Invalid_Query_Type = 30,
}

impl DNSExtendedError {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }

    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DNSExtendedError::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(
                Invalid_Extended_Error_Code,
                &format!("{val}"),
            )),
        }
    }
}

impl fmt::Display for DNSExtendedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
