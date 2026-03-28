use crate::errors::DNS_Error_Type::Invalid_Opcode;
use crate::errors::DNS_error;
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
    Hash,
    Serialize,
    Deserialize,
    FromRepr,
    PartialOrd,
    Ord,
    Default,
)]

#[repr(u16)]
pub(crate) enum DNSOpcodes {
    #[default]
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DSO = 6,
}

impl DNSOpcodes {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DNSOpcodes::from_repr(val) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(Invalid_Opcode, &format!("{val}"))),
        }
    }
}

impl fmt::Display for DNSOpcodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_opcodes_tests {
    use crate::dns_opcodes::DNSOpcodes;

    #[test]
    fn test_dns_opcodes() {
        assert_eq!(DNSOpcodes::Query.to_str(), "Query");
        assert_eq!(DNSOpcodes::Update.to_str(), "Update");
    }
    #[test]
    fn test_dns_opcodes1() {
        assert_eq!(DNSOpcodes::find(4).unwrap(), DNSOpcodes::Notify);
    }
    #[test]
    fn test_dns_opcodes2() {
        assert!(DNSOpcodes::find(114).is_err());
    }
}
