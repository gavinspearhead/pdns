use crate::errors::DNS_Error_Type::Invalid_reply_type;
use crate::errors::DNS_error;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};

#[derive(
    Debug,
    EnumIter,
    Copy,
    Clone,
    IntoStaticStr,
    EnumString,
    PartialEq,
    Eq,
    FromRepr,
    Serialize,
    Deserialize,
    Default,
    Hash,
    PartialOrd,
    Ord,
)]
pub enum DnsReplyType {
    #[default]
    NOERROR = 0,
    FORMERROR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
    DSOTYPENI = 11,
    BADVERS = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    BADCOOKIE = 23,
}

impl DnsReplyType {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
    pub(crate) fn find(val: u16) -> Result<Self, DNS_error> {
        match DnsReplyType::from_repr(usize::from(val)) {
            Some(x) => Ok(x),
            None => Err(DNS_error::new(Invalid_reply_type, &format!("{val}"))),
        }
    }
}

impl fmt::Display for DnsReplyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
#[cfg(test)]
mod tests2 {
    use crate::dns_opcodes::DNS_Opcodes;
    use crate::dns_reply_type::DnsReplyType;
    use std::str::FromStr;

    #[test]
    fn test_dns_rt() {
        assert_eq!(DnsReplyType::NXDOMAIN.to_str(), "NXDOMAIN");
        assert_eq!(DnsReplyType::NOERROR.to_str(), "NOERROR");
    }
    #[test]
    fn test_dns_rt1() {
        assert_eq!(
            DnsReplyType::from_str("NXDOMAIN").unwrap(),
            DnsReplyType::NXDOMAIN
        );
        assert_eq!(
            DnsReplyType::from_str("NOERROR").unwrap(),
            DnsReplyType::NOERROR
        );
    }
    #[test]
    fn test_dns_rt2() {
        assert_eq!(DnsReplyType::find(19).unwrap(), DnsReplyType::BADMODE);
        assert_eq!(DnsReplyType::find(23).unwrap(), DnsReplyType::BADCOOKIE);
        assert!(DNS_Opcodes::find(111).is_err());
    }
}
