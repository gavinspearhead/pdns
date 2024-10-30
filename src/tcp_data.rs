use tracing::debug;

#[derive(Debug, Clone)]
pub(crate) struct Tcp_data {
    data: Vec<u8>,
    init_seqnr: u32,
}

impl Tcp_data {
    const MAX_TCP_LEN: usize = 1024 * 1024;  // max  1MiB

    pub(crate) fn new(seqnr: u32) -> Tcp_data {
        Tcp_data {
            init_seqnr: seqnr,
            data: Vec::new()
        }
    }

    pub(crate) fn add_data(&mut self, seqnr: u32, data: &[u8]) {
        if data.is_empty() { 
            return;
        }
        let pos = (seqnr - self.init_seqnr) as usize;
        if pos > Self::MAX_TCP_LEN {
            debug!("Weird sequence number: {pos}- packet too big");
            return;
        }
        let datasize = pos + data.len();
        if datasize > self.data.len() {
            self.data.resize(datasize, 0);
            debug!("resized to {}", self.data.len());
        }
        self.data[pos..datasize].copy_from_slice(data);
        
        debug!("Data added at position: {}, seqnr: {} ", self.data.len(), self.init_seqnr);
        //debug!("Data added at position: {}, seqnr: {}, data: {:x?}", self.data.len(), self.init_seqnr, self.data);
    }
    #[inline]
    pub(crate) fn check_data_size(&self) -> bool {
        self.data.len() > Tcp_data::MAX_TCP_LEN
    }

    #[inline]
    pub(crate) fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}
