use crate::dns_record::DNS_record;
use crate::dns_rr_type::DNS_RR_type;
use chrono::Utc;
use std::cmp::max;
use std::{collections::HashMap, fmt};
use tracing::debug;

#[derive(Debug, Clone, Default)]
pub(crate) struct DNS_Cache {
    timeout: i64,
    max_size: usize,
    items: HashMap<(DNS_RR_type, String, String), (Option<DNS_record>, i64)>,
}

const MAX_CACHE_SIZE: usize = 1024;
impl DNS_Cache {
    pub fn new(time_out: i64) -> DNS_Cache {
        DNS_Cache {
            items: HashMap::new(),
            timeout: time_out,
            max_size: MAX_CACHE_SIZE,
        }
    }
    #[inline]
    pub fn timeout(&self) -> i64 {
        self.timeout
    }

    #[inline]
    pub fn get_max_size(&self) -> usize {
        self.max_size
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn add(&mut self, record: DNS_record) {
        self.items
            .entry((record.rr_type, record.name.clone(), record.rdata.clone()))
            .and_modify(|f| {
                if let (Some(y), _) = f {
                    y.count += 1;
                }
            })
            .or_insert_with(|| (Some(record), Utc::now().timestamp()));
    }
    #[inline]
    pub(crate) fn push_all(&mut self) -> Vec<DNS_record> {
        self.items.drain().filter_map(|(_, v)| v.0).collect()
    }

    pub fn push_timed(&mut self, force: bool) -> (Vec<DNS_record>, i64) {
        if force {
            return (self.push_all(), 0);
        }
        let mut expired_records = Vec::new();
        let mut first_timeout: i64 = 0;
        let current_time = Utc::now().timestamp();
        let mut cnt = 0;
        self.items.retain(|_, (record, timestamp)| {
            if current_time > *timestamp + self.timeout || cnt >= self.max_size {
                if let Some(x) = record.take() {
                    expired_records.push(x);
                }
                false
            } else {
                cnt += 1;
                first_timeout = max(first_timeout, current_time - *timestamp);
                true
            }
        });

        debug!("expired: {:?} {}", expired_records.len(), self.items.len());
        (expired_records, max(0, self.timeout - first_timeout))
    }
}

impl fmt::Display for DNS_Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.items.values() {
            write!(f, "{v:?}").expect("Cannot write output format");
        }
        write!(f, "")
    }
}
