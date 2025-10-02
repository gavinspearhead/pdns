use crate::dns::dnssec_algorithm;
use crate::dns_helper::{
    dns_format_name, dns_parse_slice, dns_read_u16, dns_read_u32, dns_read_u8, names_list,
    parse_rrtype, timestamp_to_str,
};
use crate::dns_name::dns_parse_name;
use crate::dns_record_trait::DNSRecord;
use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Parameter;
use crate::errors::Parse_error;
use base64::Engine;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default)]
pub struct RR_RRSIG {
    sig_rrtype: DNS_RR_type,
    alg: u8,
    labels: u8,
    ttl: u32,
    sig_exp: u32,
    sig_inc: u32,
    key_tag: u16,
    signer: String,
    signature: Vec<u8>,
}

impl RR_RRSIG {
    #[must_use]
    pub fn new() -> RR_RRSIG {
        RR_RRSIG::default()
    }
    pub fn set(
        &mut self,
        sig_rrtype: DNS_RR_type,
        alg: u8,
        labels: u8,
        ttl: u32,
        sig_exp: u32,
        sig_inc: u32,
        key_tag: u16,
        signer: &str,
        signature: &[u8],
    ) {
        self.sig_rrtype = sig_rrtype;
        self.alg = alg;
        self.labels = labels;
        self.ttl = ttl;
        self.sig_exp = sig_exp;
        self.sig_inc = sig_inc;
        self.key_tag = key_tag;
        self.signer = signer.to_string();
        self.signature = signature.to_vec();
    }
    pub(crate) fn parse(rdata: &[u8]) -> Result<RR_RRSIG, Parse_error> {
        let mut a = RR_RRSIG::new();
        let sig_rrtype_val = dns_read_u16(rdata, 0)?;
        a.sig_rrtype = parse_rrtype(sig_rrtype_val)
            .map_err(|_| Parse_error::new(Invalid_Parameter, &sig_rrtype_val.to_string()))?;
        a.alg = dns_read_u8(rdata, 2)?;
        a.labels = dns_read_u8(rdata, 3)?;
        a.ttl = dns_read_u32(rdata, 4)?;
        a.sig_exp = dns_read_u32(rdata, 8)?;
        a.sig_inc = dns_read_u32(rdata, 12)?;
        a.key_tag = dns_read_u16(rdata, 16)?;
        let offset_out;
        (a.signer, offset_out) = dns_parse_name(rdata, 18)?;
        a.signature = dns_parse_slice(rdata, offset_out..)?.to_vec();
        Ok(a)
    }
}

impl Display for RR_RRSIG {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let sig_rrtype_str = self.sig_rrtype.to_str();
        let alg = dnssec_algorithm(self.alg).unwrap_or_default();
        let sig_exp = timestamp_to_str(self.sig_exp).unwrap_or_default();
        let sig_inc = timestamp_to_str(self.sig_inc).unwrap_or_default();
        write!(
            f,
            "{sig_rrtype_str} {alg} {labels} {ttl} {sig_exp} {sig_inc} {key_tag} {signer} {sig}",
            labels = self.labels,
            ttl = self.ttl,
            sig_exp = sig_exp,
            sig_inc = sig_inc,
            key_tag = self.key_tag,
            signer = self.signer,
            sig = base64::engine::general_purpose::STANDARD.encode(&self.signature)
        )
    }
}

impl DNSRecord for RR_RRSIG {
    fn get_type(&self) -> DNS_RR_type {
        DNS_RR_type::RRSIG
    }

    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.sig_rrtype as u16).to_be_bytes());
        bytes.push(self.alg);
        bytes.push(self.labels);
        bytes.extend_from_slice(&self.ttl.to_be_bytes());
        bytes.extend_from_slice(&self.sig_exp.to_be_bytes());
        bytes.extend_from_slice(&self.sig_inc.to_be_bytes());
        bytes.extend_from_slice(&self.key_tag.to_be_bytes());
        //        bytes.extend_from_slice(self.signer.as_bytes());
        bytes.extend_from_slice(&dns_format_name(&self.signer, names, offset));
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}
