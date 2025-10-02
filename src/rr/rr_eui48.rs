use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_packet_index;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_EUI48 {
    pub eui48: [u8; 6],
}

impl RR_EUI48 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, eui48: &[u8; 6]) {
        self.eui48.copy_from_slice(eui48);
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_EUI48, Parse_error> {
        let mut a = RR_EUI48::new();

        if rdata.len() != 6 {
            return Err(Parse_error::new(Invalid_packet_index, ""));
        }
        let arr: [u8; 6] = rdata.try_into().unwrap();
        a.set(&arr);
        Ok(a)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.eui48.to_vec()
    }
}

impl Display for RR_EUI48 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.eui48[0],
            self.eui48[1],
            self.eui48[2],
            self.eui48[3],
            self.eui48[4],
            self.eui48[5]
        )
    }
}

impl DNSRecord for RR_EUI48 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::EUI48
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.eui48.to_vec()
    }
}
