use std::net::IpAddr;

#[derive(Debug, Clone)]
pub(crate) struct Tcp_data {
    sp: u16,
    dp: u16,
    src: IpAddr,
    dst: IpAddr,
    data: Vec<u8>,
    init_seqnr: u32,
}

impl Tcp_data {
    pub fn add_data(&mut self, seqnr: u32, data: &[u8]) {
        let pos = (seqnr - self.init_seqnr) as usize;
        let datasize = pos + data.len();
        self.data.resize(datasize, 0);
        for i in 0..data.len() {
            self.data[pos + i] = data[i];
        }
    }
    const MAX_TCP_LEN: usize = 1024 * 65; //LEN in the packet is 16 bts, so max 64KiB
    pub fn check_data_size(&self) -> bool {
        return self.data.len() > Tcp_data::MAX_TCP_LEN;
    }

    pub fn new(sp: u16, dp: u16, src: IpAddr, dst: IpAddr, seqnr: u32) -> Tcp_data {
        let t = Tcp_data {
            sp: sp,
            dp: dp,
            src: src,
            dst: dst,
            init_seqnr: seqnr,
            data: Vec::new(),
        };
        return t;
    }
    pub fn data(&self) -> &[u8] {
        return self.data.as_ref();
    }
}
