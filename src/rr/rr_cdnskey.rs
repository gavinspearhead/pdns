use crate::dns::dnssec_algorithm;
use crate::dns_helper::{dns_read_u16, dns_read_u8, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_packet_index;
use crate::errors::Parse_error;
use base64::engine::general_purpose;
use base64::Engine;
use std::fmt::{Display, Formatter};
#[derive(Debug, Clone, Default)]
pub struct RR_CDNSKEY {
    flag: u16,
    protocol: u8,
    alg: u8,
    pubkey: Vec<u8>,
}

impl RR_CDNSKEY {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, flag: u16, protocol: u8, alg_nr: u8, pubkey: Vec<u8>) {
        self.flag = flag;
        self.protocol = protocol;
        self.alg = alg_nr;
        self.pubkey = pubkey;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_CDNSKEY, Parse_error> {
        if rdata.len() < 5 {
            return Err(Parse_error::new(Invalid_packet_index, ""));
        }
        let mut a = RR_CDNSKEY::new();
        a.flag = dns_read_u16(rdata, 0)?;
        a.protocol = dns_read_u8(rdata, 2)?;
        a.alg = dns_read_u8(rdata, 3)?;
        a.pubkey = rdata[4..].to_vec();
        Ok(a)
    }
}

impl Display for RR_CDNSKEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let alg = dnssec_algorithm(self.alg).unwrap_or_default();
        write!(
            f,
            "{} {} {alg} {:x?}",
            self.flag,
            self.protocol,
            general_purpose::STANDARD.encode(&self.pubkey)
        )
    }
}

impl DNSRecord for RR_CDNSKEY {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::CDNSKEY
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(self.flag.to_be_bytes().as_ref());
        res.extend_from_slice(&[self.protocol]);
        res.extend_from_slice(self.alg.to_be_bytes().as_ref());
        res.extend_from_slice(
            general_purpose::STANDARD
                .decode(&self.pubkey)
                .unwrap_or_default()
                .as_ref(),
        );
        res
    }
}
