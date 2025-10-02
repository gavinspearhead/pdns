use crate::errors::ParseErrorType::Unknown_Protocol;
use crate::errors::Parse_error;
use std::fmt;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};

#[derive(
    Debug, EnumIter, Copy, Clone, PartialEq, Eq, EnumString, IntoStaticStr, FromRepr, Default,
)]
pub(crate) enum DNS_Protocol {
    #[default]
    Unknown = 0,
    TCP = 6,
    UDP = 17,
    SCTP = 132,
}

impl DNS_Protocol {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, Parse_error> {
        match DNS_Protocol::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(Parse_error::new(Unknown_Protocol, &val.to_string())),
        }
    }
}

impl fmt::Display for DNS_Protocol {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
