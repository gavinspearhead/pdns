use crate::dns_class::DNS_Class;
use crate::dns_helper::{dns_format_name, names_list};
use crate::dns_packet::{dns_header, dns_question};
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr_type::DNS_RR_type;
use std::fmt::Display;
use tracing::debug;
use zerocopy::IntoBytes;

#[derive(Debug, Clone, Default)]
pub(crate) struct dns_answer {
    pub header: dns_header,
    pub question: dns_question,
    pub buf: Vec<u8>,
    pub names: names_list,
    pub offset: usize,
}

impl dns_answer {
    const HEADER_LEN: usize = 12;

    #[must_use]
    pub fn new() -> dns_answer {
        dns_answer {
            header: dns_header::new(),
            question: dns_question::new(),
            buf: vec![0; Self::HEADER_LEN],
            names: names_list::new(),
            offset: 0,
        }
    }
    pub(crate) fn set_rcode(&mut self, rcode: DnsReplyType) {
        self.header.rcode = rcode;
    }

    pub fn add_header(
        &mut self,
        dns_header: &dns_header,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.header = *dns_header;
        self.header.qr = 1;
        self.header.ancount = 0;
        self.header.arcount = 0;
        self.header.nscount = 0;
        self.header.qdcount = 1;
        self.header.rcode = DnsReplyType::NOERROR;
        Ok(())
    }

    pub fn add_question(
        &mut self,
        dns_question: &dns_question,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.question = dns_question.clone();
        self.offset = write_question(
            &mut self.buf,
            Self::HEADER_LEN,
            &self.question,
            &mut self.names,
        )?;
        Ok(())
    }

    pub fn get_reply(&mut self) -> &[u8] {
        write_header(&mut self.buf, 0, &mut self.header);
        self.buf.as_slice()
    }
}

impl Display for dns_answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dns_answer {{ header: {:?}, question: {:?}  buf: {:x?} names: {:?} offest: {} }} ",
            self.header, self.question, self.buf, self.names, self.offset
        )
    }
}

fn write_question(
    buf: &mut Vec<u8>,
    offset: usize,
    question: &dns_question,
    names: &mut names_list,
) -> Result<usize, Box<dyn std::error::Error>> {
    let name = dns_format_name(&question.name, names, offset);
    debug!("name: {:?}", name);
    buf.extend_from_slice(&name);
    buf.extend_from_slice((question.dns_rr_type as u16).to_be().as_bytes());
    buf.extend_from_slice((question.dns_class_type as u16).to_be().as_bytes());
    Ok(offset + 4 + name.len())
}

fn write_header(buf: &mut [u8], offset: usize, header: &mut dns_header) -> usize {
    buf[offset..offset + 2].copy_from_slice(header.id.to_be().as_bytes());
    header.flags |= u16::from(header.qr) << 15;
    header.flags |= (header.opcode as u16 & 0b1111) << 11;
    header.flags |= u16::from(header.aa) << 10;
    header.flags |= u16::from(header.tc) << 9;
    header.flags |= u16::from(header.rd) << 8;
    header.flags |= u16::from(header.ra) << 7;
    header.flags |= u16::from(header.z) << 6;
    header.flags |= u16::from(header.ad) << 5;
    header.flags |= u16::from(header.cd) << 4;
    header.flags |= header.rcode as u16 & 0b1111;

    buf[offset + 2..offset + 4].copy_from_slice(header.flags.to_be().as_bytes());
    buf[offset + 4..offset + 6].copy_from_slice(header.qdcount.to_be().as_bytes());
    buf[offset + 6..offset + 8].copy_from_slice(header.ancount.to_be().as_bytes());
    buf[offset + 8..offset + 10].copy_from_slice(header.nscount.to_be().as_bytes());
    buf[offset + 10..offset + 12].copy_from_slice(header.arcount.to_be().as_bytes());
    offset + 12
}

pub fn write_data_record(
    buf: &mut Vec<u8>,
    offset: usize,
    name_in: &str,
    rr_type: DNS_RR_type,
    class_type: DNS_Class,
    ttl: u32,
    answer_slice: &[u8],
    names: &mut names_list,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut name = dns_format_name(name_in, names, offset);
    let name_len = name.len();
    let rdlen = answer_slice.len() as u16;
    debug!("rdlen: {:?} {:?}", rdlen, answer_slice);
    buf.append(&mut name);
    buf.extend_from_slice((rr_type as u16).to_be().as_bytes());
    buf.extend_from_slice((class_type as u16).to_be().as_bytes());
    buf.extend_from_slice(ttl.to_be().as_bytes());
    buf.extend_from_slice(rdlen.to_be().as_bytes());
    buf.extend_from_slice(answer_slice);
    Ok(offset + 10 + name_len + rdlen as usize)
}
