use crate::dns_helper::{dns_read_u16, dns_read_u64, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RR_NID {
    prio: u16,
    node_id: u64,
}

impl RR_NID {
    #[must_use]
    pub fn new() -> RR_NID {
        RR_NID::default()
    }
    pub fn set(&mut self, prio: u16, node_id: u64) {
        self.prio = prio;
        self.node_id = node_id;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_NID, Parse_error> {
        let mut a = RR_NID::new();
        a.prio = dns_read_u16(rdata, 0)?;
        a.node_id = dns_read_u64(rdata, 2)?;
        Ok(a)
    }
}

impl Display for RR_NID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{prio} {node_id1:04x}:{node_id2:04x}:{node_id3:04x}:{node_id4:04x}",
            prio = self.prio,
            node_id1 = self.node_id >> 48,
            node_id2 = self.node_id >> 32 & 0xFFFF,
            node_id3 = self.node_id >> 16 & 0xFFFF,
            node_id4 = self.node_id & 0xFFFF,
        )
    }
}

impl DNSRecord for RR_NID {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::NID
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.prio.to_be_bytes());
        bytes.extend_from_slice(&self.node_id.to_be_bytes());
        bytes
    }
}
