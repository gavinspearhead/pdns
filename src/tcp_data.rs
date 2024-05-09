#[derive(Debug, Clone)]
pub(crate) struct Tcp_data {
    data: Vec<u8>,
    init_seqnr: u32,
}

impl Tcp_data {
    const MAX_TCP_LEN: usize = 1024 * 65; //LEN in the packet is 16 bts, so max 64KiB

    pub(crate) fn add_data(&mut self, seqnr: u32, data: &[u8]) {
        let pos = (seqnr - self.init_seqnr) as usize;
        let datasize = pos + data.len();
        self.data.resize(datasize, 0);
        self.data[pos..(data.len() + pos)].copy_from_slice(data);
    }
    pub(crate) fn check_data_size(&self) -> bool {
        self.data.len() > Tcp_data::MAX_TCP_LEN
    }

    pub(crate) fn new(seqnr: u32) -> Tcp_data {
        Tcp_data {
            init_seqnr: seqnr,
            data: Vec::new(),
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}
