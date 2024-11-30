use std::fmt;
use chrono::{DateTime, Utc};
use unic_idna::to_unicode;
use crate::dns::{DNS_Class, DNS_RR_type, DnsReplyType};
use crate::edns::DNSExtendedError;

#[derive(Debug, Clone)]

pub(crate) struct DNS_record {
    pub(crate) rr_type: DNS_RR_type,
    pub(crate) class: DNS_Class,
    pub(crate) ttl: u32,
    pub(crate) name: String,
    pub(crate) rdata: String,
    pub(crate) count: u64,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) domain: String,
    pub(crate) asn: u32,
    pub(crate) asn_owner: String,
    pub(crate) prefix: String,
    pub(crate) error: DnsReplyType,
    pub(crate) extended_error: DNSExtendedError,
}

impl DNS_record {}

impl fmt::Display for DNS_record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let mut s = to_unicode(
                &self.name,
                unic_idna::Flags {
                    transitional_processing: false,
                    verify_dns_length: true,
                    use_std3_ascii_rules: true,
                },
            )
                .0;

            s = if s == self.name {
                String::new()
            } else {
                format!("({s}) ")
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
                "Name: {} ({})
            RData: {}  
            RR Type: {}    Class: {}     TTL: {}
            Count: {}      Time: {}
            Domain: {}
            ASN: {}        ASN Owner: {}
            Prefix: {}
            Error: {},
            ExtError: {}",
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
                self.rdata,
                self.rr_type,
                self.class,
                self.ttl,
                self.count,
                self.timestamp,
                self.domain,
                self.asn,
                self.asn_owner,
                self.prefix,
                self.error,
                self.extended_error
            )
        }
    }
}
