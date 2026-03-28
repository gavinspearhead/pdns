use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8, names_list, parse_dns_str};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::{Invalid_Parameter, Invalid_Resource_Record};
use crate::errors::ParseError;
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
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_BRID, ParseError> {
        if rdata.is_empty() {
            return Err(ParseError::new(Invalid_Resource_Record, "empty BRID RDATA"));
        }

        let mut a = RR_BRID::new();
        a.uas_type = dns_read_u8(rdata, 0)? & 0x0f;

        let mut offset = 1usize;
        while offset < rdata.len() {
            let group_type = dns_read_u8(rdata, offset)?;
            let group_len = usize::from(dns_read_u8(rdata, offset + 1)?);
            let value = dns_parse_slice(rdata, offset + 2..offset + 2 + group_len)?;

            match group_type {
                1 => {
                    if value.is_empty() {
                        return Err(ParseError::new(
                            Invalid_Parameter,
                            "BRID uas-id group too short",
                        ));
                    }
                    a.uas_ids.push(UasIdEntry {
                        id_type: value[0],
                        uas_id: value[1..].to_vec(),
                    });
                }
                2 => {
                    if value.is_empty() {
                        return Err(ParseError::new(
                            Invalid_Parameter,
                            "BRID auth group too short",
                        ));
                    }
                    a.auth.get_or_insert_with(Vec::new).push(AuthEntry {
                        auth_type: value[0],
                        auth_data: value[1..].to_vec(),
                    });
                }
                3 => {
                    a.self_id = Some(parse_dns_str(value)?);
                }
                4 => {
                    if value.len() != 6 {
                        return Err(ParseError::new(
                            Invalid_Parameter,
                            "BRID area group must be 6 bytes",
                        ));
                    }
                    a.area = Some(Area {
                        radius: dns_read_u16(value, 0)?,
                        ceiling: dns_read_u16(value, 2)?,
                        floor: dns_read_u16(value, 4)?,
                    });
                }
                5 => {
                    if value.len() != 2 {
                        return Err(ParseError::new(
                            Invalid_Parameter,
                            "BRID classification group must be 2 bytes",
                        ));
                    }
                    a.classification = Some(Classification {
                        category: value[0],
                        class_value: value[1],
                    });
                }
                6 => {
                    if value.is_empty() {
                        return Err(ParseError::new(
                            Invalid_Parameter,
                            "BRID operator-id group too short",
                        ));
                    }
                    a.operator_id.get_or_insert_with(Vec::new).push(OperatorId {
                        operator_type: value[0],
                        operator_id: value[1..].to_vec(),
                    });
                }
                _ => {
                    return Err(ParseError::new(
                        Invalid_Parameter,
                        &format!("unknown BRID group type {group_type}"),
                    ));
                }
            }

            offset += 2 + group_len;
        }

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
