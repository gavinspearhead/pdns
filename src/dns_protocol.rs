use crate::errors::ParseError;
use crate::errors::ParseErrorType::UnknownProtocol;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};

#[derive(
    Debug,
    EnumIter,
    Copy,
    Clone,
    PartialEq,
    Eq,
    EnumString,
    IntoStaticStr,
    Deserialize,
    Serialize,
    FromRepr,
    Default,
    Hash,
    Ord,
    PartialOrd,
)]
#[repr(u8)]
pub enum DnsProtocol {
    #[default]
    Unknown = 0,
    TCP = 6,
    UDP = 17,
    SCTP = 132,

    // dummy protocols as they are not using DNS protocol.
    HTTP_POST = 255,
    HTTPS_POST = 254,
    HTTP_GET = 253,
    HTTPS_GET = 252,
    TLS = 251,
    QUIC = 250,
    HTTPS_JSON = 249,
}

impl DnsProtocol {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u8) -> Result<Self, ParseError> {
        match DnsProtocol::from_repr(val) {
            Some(x) => Ok(x),
            None => Err(ParseError::new(UnknownProtocol, &val.to_string())),
        }
    }
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for DnsProtocol {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
