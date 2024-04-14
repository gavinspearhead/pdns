use std::{collections::HashMap, fmt};

use crate::dns::DNS_record;

#[derive(Debug, Clone)]
pub struct DNS_Cache {
    items: HashMap<(String, String, String), DNS_record>,
    timeout: u64,
}

impl DNS_Cache {
    pub fn new(time_out: u64) -> DNS_Cache {
        return DNS_Cache {
            items: HashMap::new(),
            timeout: time_out,
        };
    }
    pub fn timeout(&self) -> u64 {
        return self.timeout;
    }

    pub fn add(&mut self, record: &DNS_record) {
        self.items
            .entry((
                record.rr_type.clone(),
                record.name.clone(),
                record.rdata.clone(),
            ))
            .and_modify(|f| f.count += 1)
            .or_insert(record.clone());
    }

    pub fn push_all(&mut self) -> Vec<DNS_record> {
        let mut res = Vec::new();
        for (_k, v) in self.items.iter() {
            res.push(v.clone());
        }
        self.items.clear();
        return res;
    }
}

impl fmt::Display for DNS_Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (_k, v) in self.items.iter() {
            write!(f, "{}", v).expect("Cannot write output format ");
        }
        return write!(f, "");
    }
}
