use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_BRID {
    pub uas_type: u8, // 4-bit int (0–15)
    pub uas_ids: Vec<UasIdEntry>,
    pub auth: Option<Vec<AuthEntry>>,
    pub self_id: Option<String>,
    pub area: Option<Area>,
    pub classification: Option<Classification>,
    pub operator_id: Option<Vec<OperatorId>>,
}

#[derive(Debug, Clone, Default)]
pub struct UasIdEntry {
    pub id_type: u8,
    pub uas_id: Vec<u8>, // Binary identifier (e.g., serial number or session ID)
}

#[derive(Debug, Clone, Default)]
pub struct AuthEntry {
    pub auth_type: u8,
    pub auth_data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Area {
    pub radius: u16,  // Radius in meters
    pub ceiling: u16, // Altitude ceiling in meters
    pub floor: u16,   // Altitude floor in meters
}

#[derive(Debug, Clone, Default)]
pub struct Classification {
    pub category: u8,
    pub class_value: u8,
}

#[derive(Debug, Clone, Default)]
pub struct OperatorId {
    pub operator_type: u8,
    pub operator_id: Vec<u8>, // Opaque or UTF-8 encoded
}
impl RR_BRID {
    #[must_use] 
    pub fn new() -> RR_BRID {
        RR_BRID {
            uas_type: 0,
            uas_ids: vec![],
            auth: None,
            self_id: None,
            area: None,
            classification: None,
            operator_id: None,
        }
    }
    pub fn set(&mut self) {}
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_BRID, Parse_error> {
        let mut a = RR_BRID::new();
        Ok(a)
    }
}

impl Display for RR_BRID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DNSRecord for RR_BRID {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::BRID
    }
    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        vec![]
    }
}
