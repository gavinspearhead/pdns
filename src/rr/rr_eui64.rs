use crate::dns_helper::names_list;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_EUI64 {
    addr: [u8; 8],
}

impl RR_EUI64 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, addr: &[u8; 8]) {
        self.addr.copy_from_slice(addr);
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_EUI64, Parse_error> {
        if rdata.len() != 8 {
            return Err(Parse_error::new(
                Invalid_Resource_Record,
                "Invalid EUI64 record length",
            ));
        }
        let mut a = RR_EUI64::new();
        a.addr.copy_from_slice(&rdata[0..8]);
        Ok(a)
    }
}

impl Display for RR_EUI64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5],
            self.addr[6],
            self.addr[7]
        )
    }
}

impl DNSRecord for RR_EUI64 {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::EUI64
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        self.addr.to_vec()
    }
}
