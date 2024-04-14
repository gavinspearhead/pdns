use crate::rank::Rank;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Debug, Clone)]
pub(crate) struct Statistics {
    pub errors: HashMap<String, u128>,
    pub qtypes: HashMap<String, u128>,
    pub atypes: HashMap<String, u128>,
    pub queries: u128,
    pub answers: u128,
    pub additional: u128,
    pub authority: u128,
    pub sources: Rank<String>,
    pub destinations: Rank<String>,
    pub udp: u128,
    pub tcp: u128,
    pub topdomain: Rank<String>,
    pub topnx: Rank<String>,
}

impl Statistics {
    pub fn origin(toplistsize: usize) -> Statistics {
        Statistics {
            errors: HashMap::new(),
            qtypes: HashMap::new(),
            atypes: HashMap::new(),
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
        }
    }

    pub fn to_str(&self) -> String {
        return format!(
            "Statistics:
        Query types: {:#?}
        Answer Types: {:#?}
        Errors: {:?}
        Sources: {:?}
        Destinations: {:?}
        Queries: {}
        Answers: {}
        Additional: {}
        Authority: {}
        UDP: {}
        TCP: {}",
            self.qtypes,
            self.atypes,
            self.errors,
            self.sources,
            self.destinations,
            self.queries,
            self.answers,
            self.additional,
            self.authority,
            self.udp,
            self.tcp
        );
    }
}
