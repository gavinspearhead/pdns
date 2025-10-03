use crate::rank::Rank;
use crate::time_stats::Time_stats;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::rust::deserialize_ignore_any;

use crate::config::Config;
use crate::dns_class::DNS_Class;
use crate::dns_opcodes::DNS_Opcodes;
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr_type::DNS_RR_type;
use crate::edns::DNSExtendedError;
use crate::util::ordered_map;
use chrono::Utc;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;
use std::{collections::HashMap, fs::File, io::BufReader};
use tracing::debug;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub(crate) struct Statistics {
    pub queries: u128,
    pub answers: u128,
    pub additional: u128,
    pub authority: u128,
    pub skipped: u128,
    pub erroneous: u128,
    pub udp: u128,
    pub tcp: u128,
    pub ipv6: u128,
    pub ipv4: u128,
    pub truncated: u128,
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
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub sources: Rank<IpAddr>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub destinations: Rank<IpAddr>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub topdomain: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub topnx: Rank<String>,
    pub total_time_stats: Time_stats,
    pub blocked_time_stats: Time_stats,
    pub success_time_stats: Time_stats,
}

impl Statistics {
    pub fn new(toplistsize: usize) -> Statistics {
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
            truncated: 0,
            additional: 0,
            authority: 0,
            ipv4: 0,
            ipv6: 0,
            sources: Rank::new(toplistsize),
            destinations: Rank::new(toplistsize),
            udp: 0,
            tcp: 0,
            topdomain: Rank::new(toplistsize),
            topnx: Rank::new(toplistsize),
            total_time_stats: Time_stats::new(),
            success_time_stats: Time_stats::new(),
            blocked_time_stats: Time_stats::new(),
            skipped: 0,
            erroneous: 0,
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

    pub fn dump_stats(&self, config: &Config) -> std::io::Result<()> {
        if config.export_stats.is_empty() {
            return Ok(());
        }
        let filename_base = &config.export_stats;
        let mut count: u16 = 0;
        loop {
            let date_as_string = Utc::now().to_rfc3339();
            let filename = Path::new(filename_base).join(format!("stats-{date_as_string}.json"));
            match File::create_new(&filename) {
                Ok(f) => {
                    debug!("Dumping stats to {filename:?}");
                    let mut writer = BufWriter::new(f);
                    serde_json::to_writer_pretty(&mut writer, self)?;
                    writer.flush()?;
                    return Ok(());
                }
                Err(e) => {
                    count += 1;
                    if count > 5 {
                        return Err(e);
                    }
                }
            }
        }
    }
}
