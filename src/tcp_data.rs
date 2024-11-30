use tracing::debug;

#[derive(Debug, Clone)]
pub(crate) struct Tcp_data {
    data: Vec<u8>,
    init_seqnr: u32,
}

impl Tcp_data {
    const MAX_TCP_LEN: usize = 20 * 1024 * 1024;  // max  20 MiB
    const INIT_LEN: usize = 2048;
    pub(crate) fn new(seqnr: u32) -> Tcp_data {
        Tcp_data {
            init_seqnr: seqnr,
            data: Vec::with_capacity(Self::INIT_LEN)
        }
    }

    pub(crate) fn add_data(&mut self, seqnr: u32, data: &[u8]) {
        if data.is_empty() { 
            return;
        }
        let pos = (seqnr - self.init_seqnr) as usize;
        if pos > Self::MAX_TCP_LEN {
            debug!("Weird sequence number: {pos} - packet too big");
            return;
        }
        let data_size = pos + data.len();
        if data_size > self.data.len() {
            self.data.resize(data_size, 0);
            debug!("resized to {}", self.data.len());
        }
        self.data[pos..data_size].copy_from_slice(data);
        
        debug!("Data added at position: {}, init_seqnr: {} seqnr: {seqnr} ", self.data.len(), self.init_seqnr);
    }

    #[inline]
    pub(crate) fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}
