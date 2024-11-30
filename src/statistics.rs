use crate::rank::Rank;
use crate::time_stats::Time_stats;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::rust::deserialize_ignore_any;
use serde_json;

use std::{collections::HashMap, fs::File, io::BufReader};
use std::cmp::Ordering::Equal;
use serde::ser::SerializeMap;
use crate::dns::{DNS_Class, DNS_Opcodes, DNS_RR_type, DnsReplyType};
use crate::edns::DNSExtendedError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Statistics {
    #[serde(serialize_with = "ordered_map")]
    pub errors: HashMap<DnsReplyType, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub qtypes: HashMap<DNS_RR_type, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub atypes: HashMap<DNS_RR_type, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub qclass: HashMap<DNS_Class, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub aclass: HashMap<DNS_Class, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub opcodes: HashMap<DNS_Opcodes, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub extended_error: HashMap<DNSExtendedError, u128>,
    pub queries: u128,
    pub answers: u128,
    pub additional: u128,
    pub authority: u128,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub sources: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub destinations: Rank<String>,
    pub udp: u128,
    pub tcp: u128,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub topdomain: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub topnx: Rank<String>,
    pub total_time_stats: Time_stats,
    pub blocked_time_stats: Time_stats,
    pub success_time_stats: Time_stats,
}

impl Statistics {
    pub(crate) fn new(toplistsize: usize) -> Statistics {
        Statistics {
            errors: HashMap::new(),
            qtypes: HashMap::new(),
            atypes: HashMap::new(),
            qclass: HashMap::new(),
            aclass: HashMap::new(),
            opcodes: HashMap::new(),
            extended_error: HashMap::new(),
            queries: 0,
            answers: 0,
            additional: 0,
            authority: 0,
            sources: Rank::new(toplistsize),
            destinations: Rank::new(toplistsize),
            udp: 0,
            tcp: 0,
            topdomain: Rank::new(toplistsize),
            topnx: Rank::new(toplistsize),
            total_time_stats: Time_stats::new(),
            success_time_stats: Time_stats::new(),
            blocked_time_stats: Time_stats::new(),
        }
    }

    pub(crate) fn import(
        filename: &str,
        toplistsize: usize,
    ) -> Result<Statistics, Box<dyn std::error::Error>> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut statistics: Statistics = serde_json::from_reader(reader)?;
        statistics.sources = Rank::new(toplistsize);
        statistics.destinations = Rank::new(toplistsize);
        statistics.topdomain = Rank::new(toplistsize);
        statistics.topnx = Rank::new(toplistsize);
        Ok(statistics)
    }
}

/// For use with serde's [serialize_with] attribute
fn ordered_map<S, K: Ord + Serialize + ToString, V: Serialize + PartialOrd >(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut l = Vec::new();
    for (k, v) in value {
        l.push((k, v));
    }
    l.sort_by(|a, b| (a.0.to_string()).partial_cmp(&b.0.to_string()).unwrap_or(Equal));

    let mut map = serializer.serialize_map(Some(l.len()))?;
    for i in l {
        map.serialize_entry(&i.0, i.1)?;
    }
    map.end()

}
