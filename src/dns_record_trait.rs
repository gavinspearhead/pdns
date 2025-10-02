use crate::dns_answers::dns_answer;
use crate::dns_class::DNS_Class;
use crate::dns_packet::dns_question;
use crate::dns_rr_type::DNS_RR_type;
use tracing::debug;

use crate::dns_answers::write_data_record;
use crate::dns_helper::names_list;

pub(crate) trait DNSRecord {
    fn add_to_answer(
        &self,
        answer: &mut dns_answer,
        question: &dns_question,
        ttl: u32,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let bytes = self.to_bytes(&mut answer.names, answer.offset);
        debug!("Answer {:?}", bytes);
        let offset = write_data_record(
            &mut answer.buf,
            answer.offset,
            &question.name,
            self.get_type(),
            DNS_Class::IN,
            ttl,
            &bytes,
            &mut answer.names,
        )?;
        Ok(offset)
    }

    fn get_type(&self) -> DNS_RR_type;
    fn to_bytes(&self, names: &mut names_list, offset: usize) -> Vec<u8>;
}
