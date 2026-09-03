use crate::dns_class::DnsClass;
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr_type::DnsRRType;
use crate::edns::DnsExtendedError;
use chrono::{DateTime, Utc};
use idna::domain_to_unicode;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::{Display, EnumString};

#[derive(
    Debug,
    Clone,
    Default,
    PartialOrd,
    Ord,
    Eq,
    PartialEq,
    Hash,
    EnumString,
    Display,
    Serialize,
    Deserialize,
)]
pub enum DnsField {
    Additional,
    Authority,
    #[default]
    Answer,
    Question,
}

#[derive(Debug, Clone, Default, PartialOrd, Ord, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct DnsRecord {
    pub rr_type: DnsRRType,
    pub class: DnsClass,
    pub error: DnsReplyType,
    pub extended_error: DnsExtendedError,
    pub ttl: u32,
    pub count: u32,
    pub asn: u32,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub rdata: String,
    pub domain: String,
    pub asn_owner: String,
    pub prefix: String,
    pub source_field: DnsField,
}

impl DnsRecord {
    pub fn new(
        rr_type: DnsRRType,
        class: DnsClass,
        error: DnsReplyType,
        count: u32,
        timestamp: DateTime<Utc>,
        name: &str,
        ttl: u32,
        rdata: &str,
        source_field: DnsField,
    ) -> DnsRecord {
        DnsRecord {
            rr_type,
            class,
            error,
            extended_error: DnsExtendedError::None,
            ttl,
            count,
            asn: 0,
            timestamp,
            name: name.to_string(),
            rdata: rdata.to_string(),
            domain: String::new(),
            asn_owner: String::new(),
            prefix: String::new(),
            source_field,
        }
    }
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let (name, res) = domain_to_unicode(&self.name);
            let unicode_name = if name == self.name || res.is_err() {
                String::new()
            } else {
                format!("({name}) ")
            };

            write!(
                f,
                "  {} {}{} {} {} {} {} {} {} {}",
                snailquote::escape(&self.name),
                unicode_name,
                self.class,
                self.rr_type,
                self.rdata,
                self.ttl,
                self.timestamp,
                self.domain,
                self.prefix,
                self.source_field,
            )?;

            if self.asn != 0 {
                write!(f, "{} ({}) ", self.asn, self.asn_owner)?;
            }

            writeln!(
                f,
                "{} {} {}",
                self.error,
                self.extended_error.to_str(),
                self.count,
            )
        } else {
            write!(
                f,
                "Name: {} ({})      Domain: {}
            RData: {}
            RR Type: {}    Class: {}     TTL: {}      Error: {}      ExtError: {}    Count: {}
            Time: {}      Prefix: {}",
                snailquote::escape(&self.name),
                domain_to_unicode(&self.name).0,
                self.domain,
                self.rdata,
                self.rr_type,
                self.class,
                self.ttl,
                self.error,
                self.extended_error.to_str(),
                self.count,
                self.timestamp,
                self.prefix,
            )?;

            if self.asn != 0 {
                write!(
                    f,
                    "     ASN: {}        ASN Owner: {}",
                    self.asn, self.asn_owner
                )?;
            }
            writeln!(f)
        }
    }
}
