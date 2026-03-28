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
#[repr(u16)]
pub enum DnsClass {
    #[default]
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
}

impl DnsClass {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        if let Some(x) = DnsClass::from_repr(val) {
            Ok(x)
        } else {
            debug!("Error wrong class value {val}");
            Err(DNS_error::new(Invalid_Class, &format!("{val}")))
        }
    }
}

impl fmt::Display for DnsClass {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_class_tests {
    use crate::dns_class::DnsClass;

    #[test]
    fn test_dns_class2() {
        assert_eq!(DnsClass::IN.to_str(), "IN");
        assert_eq!(DnsClass::HS.to_str(), "HS");
        assert_eq!(DnsClass::CS.to_str(), "CS");
        assert_eq!(DnsClass::CH.to_str(), "CH");
    }
    #[test]
    fn test_dns_class1() {
        assert_eq!(DnsClass::find(4).unwrap(), DnsClass::HS);
    }
    #[test]
    fn test_dns_class3() {
        assert_eq!(DnsClass::find(255).unwrap(), DnsClass::ANY);
    }
    #[test]
    fn test_dns_class4() {
        assert!(DnsClass::find(122).is_err());
    }
}
