use crate::dns::{sshfp_algorithm, sshfp_fp_type};
use crate::dns_helper::{dns_parse_slice, names_list};
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::Parse_error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_SSHFP {
    alg: u8,
    fp_type: u8,
    fingerprint: Vec<u8>,
}

impl RR_SSHFP {
    #[must_use]
    pub fn new() -> RR_SSHFP {
        RR_SSHFP::default()
    }
    pub fn set(&mut self, alg: u8, fp_type: u8, fingeprint: Vec<u8>) {
        self.alg = alg;
        self.fp_type = fp_type;
        self.fingerprint = fingeprint;
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_SSHFP, Parse_error> {
        let mut a = RR_SSHFP::new();

        if rdata.len() < 3 {
            return Err(Parse_error::new(Invalid_Resource_Record, ""));
        }
        a.alg = rdata[0];
        a.fp_type = rdata[1];
        a.fingerprint = dns_parse_slice(rdata, 2..)?.to_vec();
        Ok(a)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.push(self.alg);
        res.push(self.fp_type);
        res.extend_from_slice(&self.fingerprint);
        res
    }
}

impl Display for RR_SSHFP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{alg} {fp_type} {fp}",
            alg = sshfp_algorithm(self.alg).unwrap(),
            fp_type = sshfp_fp_type(self.fp_type).unwrap(),
            fp = hex::encode(&self.fingerprint)
        )
    }
}

impl DNSRecord for RR_SSHFP {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::SSHFP
    }

    fn to_bytes(&self, _names: &mut names_list, _offset: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.push(self.alg);
        res.push(self.fp_type);
        res.extend_from_slice(&self.fingerprint);
        res
    }
}
