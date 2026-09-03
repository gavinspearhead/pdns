use crate::errors::DnsError;
use crate::errors::DnsErrorType::{InvalidExtendedErrorCode, InvalidExtendedOptionCode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;
use std::net::IpAddr;
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
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    FromRepr,
    Default,
)]
#[repr(u16)]
pub enum EDNSOptionCodes {
    LLQ = 1,
    UpdateLease = 2,
    NSID = 3,
    DAU = 5,
    DHU = 6,
    N3U = 7,
    EdnsClientSubnet = 8,
    EdnsExpire = 9,
    Cookie = 10,
    EdnsTcpKeepalive = 11,
    Padding = 12,
    Chain = 13,
    EdnsKeyTag = 14,
    ExtendedDNSError = 15,
    EDNSClientTag = 16,
    EDNSServerTag = 17,
    ReportChannel = 18,
    ZoneVersion = 19,
    MqtypeQuery = 20,
    MqtypeResponse = 21,
    EdeExtraTextLanguague = 22,
    FilteringContact = 23,
    FilteringOrganization = 24,
    FilteringDb = 25,
    UmbrellaIdent = 20292,
    DeviceID = 26946,
    #[default]
    Reserved = 65535,
}


#[derive(
    Debug,
    Hash,
    IntoStaticStr,
    Clone,
    Serialize,
    Deserialize,

)]


pub enum EDNSOptionData {
    None,
    LLQ((u16, u16,u16, u64,u32)) ,
    UpdateLease ((u32, u32)),
    NSID (String),
    DAU(Vec<u8>) ,
    DHU(Vec<u8>),
    N3U(Vec<u8>),
    EdnsClientSubnet((u16, u8,u8, IpAddr)),
    EdnsExpire,
    Cookie((u64, u128)),
    EdnsTcpKeepalive (u16),
    Padding (u8),
    Chain (String),
    EdnsKeyTag (Vec<u16>),
    ExtendedDNSError (DnsExtendedError),
    EDNSClientTag (u16),
    EDNSServerTag (u16),
    ReportChannel (String),
    ZoneVersion ((u8,u8, Vec<u8>)),
  //  MqtypeQuery = 20,
 //   MqtypeResponse = 21,
  //  EdeExtraTextLanguague = 22,
  //  FilteringContact = 23,
  //  FilteringOrganization = 24,
  //  FilteringDb = 25,
  //  UmbrellaIdent = 20292,
  //  DeviceID = 26946,
    Reserved,
}

impl EDNSOptionData {
    fn get_option_code(&self) -> u16 {
        match self {
            EDNSOptionData::None => 65535,
            EDNSOptionData::LLQ(_) => 1,
            EDNSOptionData::UpdateLease(_) => 2,
            EDNSOptionData::NSID(_) => 3,
            EDNSOptionData::DAU(_) => 5,
            EDNSOptionData::DHU(_) => 6,
            EDNSOptionData::N3U(_) => 7,
            EDNSOptionData::EdnsClientSubnet(_) => 8,
            EDNSOptionData::EdnsExpire => 9,
            EDNSOptionData::Cookie(_) => 10,
            EDNSOptionData::EdnsTcpKeepalive(_) => 11,
            EDNSOptionData::Padding(_) => 12,
            EDNSOptionData::Chain(_) => 13,
            EDNSOptionData::EdnsKeyTag(_) => 14,
            EDNSOptionData::ExtendedDNSError(_) => 15,
            EDNSOptionData::EDNSClientTag(_) => 16,
            EDNSOptionData::EDNSServerTag(_) => 17,
            EDNSOptionData::ReportChannel(_) => 18,
            EDNSOptionData::ZoneVersion(_) => 19,
            EDNSOptionData::Reserved => 65535,
        }
    }
}

impl Display for EDNSOptionData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EDNSOptionData::None => write!(f, "None", ),
            EDNSOptionData::LLQ((version, opcode, error, id, lease)) => {
                write!(f, "LLQ(version={}, opcode={}, error={}, id={}, lease={}) ",
                       version, opcode, error, id, lease, )
            }
            EDNSOptionData::UpdateLease((lease, key_lease)) => {
                write!(f, "UpdateLease(lease={}, key_lease={})", lease, key_lease, )
            }
            EDNSOptionData::NSID(s) => write!(f, "NSID({}) ", s, ),
            EDNSOptionData::DAU(vec) => {
                write!(f, "DAU({:?}) ", vec, )
            }
            EDNSOptionData::DHU(vec) => {
                write!(f, "DHU({:?}) ", vec, )
            }
            EDNSOptionData::N3U(vec) => {
                write!(f, "N3U({:?}) ", vec, )
            }
            EDNSOptionData::EdnsClientSubnet((family, source_prefix, scope_prefix, addr)) => {
                write!(f, "EdnsClientSubnet(family={}, source_prefix={}, scope_prefix={}, addr={})",
                       family, source_prefix, scope_prefix, addr, )
            }
            EDNSOptionData::EdnsExpire => write!(f, "EdnsExpire ", ),
            EDNSOptionData::Cookie((client, server)) => {
                write!(f, "Cookie(client={:#x}, server={:#x}) ", client, server, )
            }
            EDNSOptionData::EdnsTcpKeepalive(timeout) => {
                write!(f, "EdnsTcpKeepalive({}) ", timeout, )
            }
            EDNSOptionData::Padding(len) => write!(f, "Padding({}) ", len, ),
            EDNSOptionData::Chain(s) => write!(f, "Chain({}) ", s, ),
            EDNSOptionData::EdnsKeyTag(tags) => {
                write!(f, "EdnsKeyTag({:?}) ", tags, )
            }
            EDNSOptionData::ExtendedDNSError(err) => {
                write!(f, "EDE ({}) ({})", err, err.to_u16())
            }
            EDNSOptionData::EDNSClientTag(tag) => {
                write!(f, "EDNSClientTag({}) ", tag, )
            }
            EDNSOptionData::EDNSServerTag(tag) => {
                write!(f, "EDNSServerTag({})", tag, )
            }
            EDNSOptionData::ReportChannel(s) => write!(f, "ReportChannel({}) ", s, ),
            EDNSOptionData::ZoneVersion((version, flags, data)) => {
                write!(f, "ZoneVersion(version={}, flags={}, data={:?})", version, flags, data, )
            }
            EDNSOptionData::Reserved => write!(f, "Reserved", ),
        }
    }
}


impl EDNSOptionData {
    pub(crate) fn default() -> Self {
        return EDNSOptionData::None
    }
}

impl EDNSOptionCodes {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }

    pub(crate) fn find(val: u16) -> Result<Self, DnsError> {
        match EDNSOptionCodes::from_repr(val) {
            Some(x) => Ok(x),
            None => Err(DnsError::new(InvalidExtendedOptionCode, &format!("{val}"))),
        }
    }

    #[must_use]
    pub fn to_u16(self) -> u16 {
        self as u16
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
#[repr(u16)]
pub(crate) enum DnsExtendedError {
    #[default]
    None = 0xffff,
    Other = 0,
    UnsupportedDnskeyAlgorithm = 1,
    UnsupportedDsDigestType = 2,
    StaleAnswer = 3,
    ForgedAnswer = 4,
    DnssecIndeterminate = 5,
    DnssecBogus = 6,
    SignatureExpired = 7,
    SignatureNotYetValid = 8,
    DnskeyMissing = 9,
    RrsigsMissing = 10,
    NoZoneKeyBitSet = 11,
    NsecMissing = 12,
    CachedError = 13,
    NotReady = 14,
    Blocked = 15,
    Censored = 16,
    Filtered = 17,
    Prohibited = 18,
    StaleNxdomainAnswer = 19,
    NotAuthoritative = 20,
    NotSupported = 21,
    NoReachableAuthority = 22,
    NetworkError = 23,
    InvalidData = 24,
    SignatureExpiredBeforeValid = 25,
    TooEarly = 26,
    UnsupportedNsec3IterationsValue = 27,
    UnableToConformToPolicy = 28,
    Synthesized = 29,
    InvalidQueryType = 30,
    RateLimited = 31,
    OverQuota = 32,
    Private = 65534,
}

impl DnsExtendedError {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }

    pub(crate) fn to_u16(self) -> u16 {
        self as u16
    }

    pub(crate) fn find(val: u16) -> Result<Self, DnsError> {
        match DnsExtendedError::from_repr(val) {
            Some(x) => Ok(x),
            None => {
                if (49152..65535).contains(&val) {
                    Ok(DnsExtendedError::Private)
                } else {
                    Err(DnsError::new(InvalidExtendedErrorCode, &val.to_string()))
                }
            }
        }
    }
}

impl fmt::Display for DnsExtendedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
