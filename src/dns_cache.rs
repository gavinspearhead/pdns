use std::{collections::HashMap, fmt};

use crate::dns::DNS_record;

#[derive(Debug, Clone)]
pub(crate) struct DNS_Cache {
    items: HashMap<(String, String, String), DNS_record>,
    timeout: u64,
}

impl DNS_Cache {
    pub(crate) fn new(time_out: u64) -> DNS_Cache {
        DNS_Cache {
            items: HashMap::new(),
            timeout: time_out,
        }
    }

    pub(crate) fn timeout(&self) -> u64 {
        self.timeout
    }

    pub(crate) fn add(&mut self, record: &DNS_record) {
        self.items
            .entry((
                record.rr_type.clone(),
                record.name.clone(),
                record.rdata.clone(),
            ))
            .and_modify(|f| f.count += 1)
            .or_insert(record.clone());
    }

    pub(crate) fn push_all(&mut self) -> Vec<DNS_record> {
        let mut res = Vec::new();
        for v in self.items.values() {
            res.push(v.clone());
        }
        self.items.clear();
        res
    }
}

impl fmt::Display for DNS_Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.items.values() {
            write!(f, "{v}").expect("Cannot write output format ");
        }
         write!(f, "")
    }
}
