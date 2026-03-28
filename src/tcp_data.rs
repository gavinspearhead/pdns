use serde::Serialize;
use tracing::debug;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct TcpData {
    init_seqnr: u32,
    max_tcp_len: usize,
    data: Vec<u8>,
}

impl TcpData {
    const INIT_LEN: usize = 2048;
    pub(crate) fn new(seq_nr: u32, max_size: u32) -> Self {
        TcpData {
            init_seqnr: seq_nr,
            data: Vec::with_capacity(Self::INIT_LEN),
            max_tcp_len: (max_size as usize)
                .checked_mul(1024 * 1024)
                .unwrap_or(10usize * 1024usize * 1024usize ), // convert to megabytes
        }
    }

    pub(crate) fn add_data(&mut self, seqnr: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let pos = seqnr.wrapping_sub(self.init_seqnr) as usize;
        if pos >= self.max_tcp_len {
            debug!("Weird sequence number: {pos} - packet too big");
            return;
        }
        let data_size = pos + data.len();
        if data_size > self.data.len() {
            self.data.resize(data_size, 0);
            //   debug!("resized to {}", self.data.len());
        }
        self.data[pos..data_size].copy_from_slice(data);
        //  debug!("Data added at position: {}, init_seqnr: {} seqnr: {seqnr} ", self.data.len(), self.init_seqnr);
    }

    #[inline]
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}
