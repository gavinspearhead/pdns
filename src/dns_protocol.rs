use crate::errors::ParseErrorType::Unknown_Protocol;
use crate::errors::ParseError;
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
    FromRepr,
    Default,
    Hash,
    Ord,
    PartialOrd,
)]

#[repr(u8)]
pub(crate) enum DNSProtocol {
    #[default]
    Unknown = 0,
    TCP = 6,
    UDP = 17,
    SCTP = 132,
}

impl DNSProtocol {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u8) -> Result<Self, ParseError> {
        match DNSProtocol::from_repr(val) {
            Some(x) => Ok(x),
            None => Err(ParseError::new(Unknown_Protocol, &val.to_string())),
        }
    }
    #[inline]
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }

}

impl fmt::Display for DNSProtocol {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
