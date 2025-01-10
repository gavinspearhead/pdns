use crate::rank::Rank;
use crate::time_stats::Time_stats;
use serde::{Deserialize, Serialize};
use serde_with::rust::deserialize_ignore_any;
use serde_json;

use std::{collections::HashMap, fs::File, io::BufReader};
use std::net::IpAddr;
use crate::dns::{DNS_Class, DNS_Opcodes, DNS_RR_type, DnsReplyType};
use crate::edns::DNSExtendedError;
use crate::util::ordered_map;

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
    pub sources: Rank<IpAddr>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub destinations: Rank<IpAddr>,
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
