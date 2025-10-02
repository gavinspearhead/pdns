use crate::errors::DNS_Error_Type::Invalid_Class;
use crate::errors::DNS_error;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};
use tracing::debug;

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
    Default,
)]
pub enum DNS_Class {
    #[default]
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
        if let Some(x) = DNS_Class::from_repr(usize::from(val)) {
            Ok(x)
        } else {
            debug!("Error wrong class value {val}");
            Err(DNS_error::new(Invalid_Class, &format!("{val}")))
        }
    }
}

impl fmt::Display for DNS_Class {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_class_tests {
    use crate::dns_class::DNS_Class;

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
