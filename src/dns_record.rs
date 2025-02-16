use crate::dns::{DNS_Class, DNS_RR_type, DnsReplyType};
use crate::edns::DNSExtendedError;
use chrono::{DateTime, Utc};
use std::fmt;
use unic_idna::to_unicode;

#[derive(Debug, Clone)]

pub(crate) struct DNS_record {
    pub(crate) rr_type: DNS_RR_type,
    pub(crate) class: DNS_Class,
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

impl DNS_record {}

impl fmt::Display for DNS_record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let (name, res) = to_unicode(
                &self.name,
                unic_idna::Flags {
                    transitional_processing: false,
                    verify_dns_length: true,
                    use_std3_ascii_rules: true,
                },
            );
            let s = if name == self.name || res != Ok(()) {
                String::new()
            } else {
                format!("({name}) ")
            };

            writeln!(
                f,
                "  {} {s}{} {} {} {} {} {} {} {} ({}) {} {} {}",
                snailquote::escape(&self.name),
                self.class,
                self.rr_type,
                self.rdata,
                self.ttl,
                self.timestamp,
                self.domain,
                self.prefix,
                self.asn,
                self.asn_owner,
                self.error,
                self.extended_error.to_str(),
                self.count,
            )
        } else {
            writeln!(
                f,
                "Name: {} ({})      Domain: {}
        RData: {}
        RR Type: {}    Class: {}     TTL: {}      Error: {}      ExtError: {}    Count: {}
        Time: {}      Prefix: {}   ASN: {}        ASN Owner: {}",
                snailquote::escape(&self.name),
                to_unicode(
                    &self.name,
                    unic_idna::Flags {
                        transitional_processing: false,
                        verify_dns_length: true,
                        use_std3_ascii_rules: true
                    }
                )
                .0,
                self.domain,
                self.rdata,
                self.rr_type,
                self.class,
                self.ttl,
                self.error,
                self.extended_error,
                self.count,
                self.timestamp,
                self.prefix,
                self.asn,
                self.asn_owner,
            )
        }
    }
}
