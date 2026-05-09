use crate::dns_class::DnsClass;
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr_type::DnsRRType;
use crate::edns::DnsExtendedError;
use chrono::{DateTime, Utc};
use idna::domain_to_unicode;
use std::fmt;

#[derive(Debug, Clone, Default, PartialOrd, Ord, Eq, PartialEq, Hash)]
pub(crate) struct DnsRecord {
    pub(crate) rr_type: DnsRRType,
    pub(crate) class: DnsClass,
    pub(crate) error: DnsReplyType,
    pub(crate) extended_error: DnsExtendedError,
    pub(crate) ttl: u32,
    pub(crate) count: u32,
    pub(crate) asn: u32,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) name: String,
    pub(crate) rdata: String,
    pub(crate) domain: String,
    pub(crate) asn_owner: String,
    pub(crate) prefix: String,
}

impl DnsRecord {
    pub(crate) fn new(
        rr_type: DnsRRType,
        class: DnsClass,
        error: DnsReplyType,
        count: u32,
        timestamp: DateTime<Utc>,
        name: &str,
        ttl: u32,
        rdata: &str,
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
                "  {} {}{} {} {} {} {} {} {}",
                snailquote::escape(&self.name),
                unicode_name,
                self.class,
                self.rr_type,
                self.rdata,
                self.ttl,
                self.timestamp,
                self.domain,
                self.prefix,
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
