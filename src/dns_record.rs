use crate::dns_class::DnsClass;
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr_type::DNS_RR_type;
use crate::edns::DNSExtendedError;
use chrono::{DateTime, Utc};
use idna::domain_to_unicode;
use std::fmt;

#[derive(Debug, Clone, Default, PartialOrd, Ord, Eq, PartialEq, Hash)]
pub(crate) struct DNSRecord {
    pub(crate) rr_type: DNS_RR_type,
    pub(crate) class: DnsClass,
    pub(crate) error: DnsReplyType,
    pub(crate) extended_error: DNSExtendedError,
    pub(crate) ttl: u32,
    pub(crate) count: u64,
    pub(crate) asn: u32,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) name: String,
    pub(crate) rdata: String,
    pub(crate) domain: String,
    pub(crate) asn_owner: String,
    pub(crate) prefix: String,
}

impl DNSRecord {}

impl fmt::Display for DNSRecord {
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
