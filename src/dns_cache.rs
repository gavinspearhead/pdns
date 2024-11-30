use std::{collections::HashMap, fmt};

use crate::dns::DNS_RR_type;
use crate::dns_record::DNS_record;

#[derive(Debug, Clone)]
pub(crate) struct DNS_Cache {
    items: HashMap<(DNS_RR_type, String, String), DNS_record>,
    timeout: i64,
}

impl DNS_Cache {
    pub(crate) fn new(time_out: i64) -> DNS_Cache {
        DNS_Cache {
            items: HashMap::new(),
            timeout: time_out,
        }
    }
    #[inline]
    pub(crate) fn timeout(&self) -> i64 {
        self.timeout
    }

    pub(crate) fn add(&mut self, record: &DNS_record) {
        self.items
            .entry((record.rr_type, record.name.clone(), record.rdata.clone()))
            .and_modify(|f| f.count += 1)
            .or_insert_with(|| record.clone());
    }
    #[inline]
    pub(crate) fn push_all(&mut self) -> Vec<DNS_record> {
        
            self.items.drain().map(|(_, v)| v).collect()
    }
}

impl fmt::Display for DNS_Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.items.values() {
            write!(f, "{v}").expect("Cannot write output format");
        }
        write!(f, "")
    }
}
