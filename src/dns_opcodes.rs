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
pub(crate) enum DNS_Opcodes {
    #[default]
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DSO = 6,
}

impl DNS_Opcodes {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DNS_Opcodes::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(Invalid_Opcode, &format!("{val}"))),
        }
    }
}

impl fmt::Display for DNS_Opcodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod dns_opcodes_tests {
    use crate::dns_opcodes::DNS_Opcodes;

    #[test]
    fn test_dns_opcodes() {
        assert_eq!(DNS_Opcodes::Query.to_str(), "Query");
        assert_eq!(DNS_Opcodes::Update.to_str(), "Update");
    }
    #[test]
    fn test_dns_opcodes1() {
        assert_eq!(DNS_Opcodes::find(4).unwrap(), DNS_Opcodes::Notify);
    }
}
