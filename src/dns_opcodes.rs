use crate::errors::DnsError;
use crate::errors::DnsErrorType::Invalid_Opcode;
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
pub(crate) enum DnsOpcodes {
    #[default]
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DSO = 6,
}

impl DnsOpcodes {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DnsError> {
        match DnsOpcodes::from_repr(val) {
            Some(x) => Ok(x),
            None => Err(DnsError::new(Invalid_Opcode, &format!("{val}"))),
        }
    }
}

impl fmt::Display for DnsOpcodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_opcodes_tests {
    use crate::dns_opcodes::DnsOpcodes;

    #[test]
    fn test_dns_opcodes() {
        assert_eq!(DnsOpcodes::Query.to_str(), "Query");
        assert_eq!(DnsOpcodes::Update.to_str(), "Update");
    }
    #[test]
    fn test_dns_opcodes1() {
        assert_eq!(DnsOpcodes::find(4).unwrap(), DnsOpcodes::Notify);
    }
    #[test]
    fn test_dns_opcodes2() {
        assert!(DnsOpcodes::find(114).is_err());
    }
}
