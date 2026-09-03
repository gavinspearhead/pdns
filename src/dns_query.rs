use crate::dns_class::DnsClass;
use crate::dns_rr_type::DnsRRType;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone, Copy, Default, Deserialize, Serialize)]
pub enum DnsDir {
    #[default]
    Forward,
    Reverse,
}

#[derive(Debug, PartialEq, Eq, Clone, Default, Deserialize, Serialize)]
pub struct DnsQuery {
    pub query: String,
    pub dir: DnsDir,
    pub dns_rr_type: DnsRRType,
    pub dns_class: DnsClass,
    pub server: String,
    pub dnssec: bool,
    pub validate: bool,
}

impl DnsQuery {
    pub fn new(
        query: &str,
        dir: DnsDir,
        dns_rr_type: DnsRRType,
        dns_class: DnsClass,
        server: &str,
    ) -> Self {
        Self {
            query: query.to_string(),
            dir,
            dns_rr_type,
            dns_class,
            server: server.to_string(),
            dnssec: false,
            validate: false,
        }
    }
}
