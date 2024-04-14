use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        mpsc::{self, TryRecvError},
        Arc, Mutex,
    },
    thread::sleep,
    time,
};

use crate::tcp_data::Tcp_data;

#[derive(Debug, Clone)]
struct Tcp_connection {
    in_data: Tcp_data,
    ts: DateTime<Utc>,
}

impl Tcp_connection {
    pub fn new(
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
        seqnr: u32,
        timestamp: DateTime<Utc>,
    ) -> Tcp_connection {
        let t = Tcp_connection {
            in_data: Tcp_data::new(sp, dp, src, dst, seqnr),
            ts: timestamp,
        };
        return t;
    }
    pub fn get_data(&self) -> &Tcp_data {
        return &self.in_data;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TCP_Connections {
    connections: HashMap<(IpAddr, IpAddr, u16, u16), Tcp_connection>,
    timelimit: i64,
}

impl TCP_Connections {
    pub fn new() -> TCP_Connections {
        let t = TCP_Connections {
            connections: HashMap::new(),
            timelimit: 20,
        };
        return t;
    }

    pub fn len(&self) -> usize {
        //println!("{}", self.connections.len());
        return self.connections.len();
    }

    pub fn add_data(
        &mut self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
        seqnr: u32,
        data: &[u8],
    ) {
        let timestamp = Utc::now();
        let c = self
            .connections
            .entry((src, dst, sp, dp))
            .or_insert(Tcp_connection::new(sp, dp, src, dst, seqnr, timestamp));
        c.in_data.add_data(seqnr, data);
        if c.in_data.check_data_size() {
            // if it is too big we just throw it away
            self.remove(sp, dp, src, dst);
        }
    }

    pub fn get_data(
        &self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<&Tcp_data, Box<dyn std::error::Error>> {
        let Some(c) = self.connections.get(&(src, dst, sp, dp)) else {
            return Err("connection not found".into());
        };
        return Ok(c.get_data());
    }

    pub fn remove(&mut self, sp: u16, dp: u16, src: IpAddr, dst: IpAddr) {
        //  println!("Removing key {} {} {} {} ", src, dst, sp, dp);
        self.connections.remove(&(src, dst, sp, dp));
    }

    pub fn check_timeout(&mut self) -> u64 {
        let now = Utc::now().timestamp();
        let mut m_ts = 1;
        let mut keys: Vec<(IpAddr, IpAddr, u16, u16)> = Vec::new();
        for (k, v) in &self.connections {
            if v.ts.timestamp() + self.timelimit < now {
                keys.push(*k);
            }
            if now - v.ts.timestamp() > m_ts {
                m_ts = self.timelimit + v.ts.timestamp() - now;
            }
        }
        for k in keys {
            self.connections.remove(&k);
        }
        if m_ts > 0 {
            return m_ts as u64;
        } else {
            return self.timelimit as u64;
        }
    }

    pub fn process_data(
        &mut self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
        seqnr: u32,
        data: &[u8],
        _timestamp: DateTime<Utc>,
        flags: u8,
    ) -> Option<Tcp_data> {
        if (flags & 1 != 0) || (flags & 4 != 0) {
            // FIN flag or reset
            self.add_data(sp, dp, src, dst, seqnr, data);
            match self.get_data(sp, dp, src, dst) {
                Ok(x) => {
                    let y = x.clone();
                    self.remove(sp, dp, src, dst);
                    return Some(y);
                }
                Err(_e) => {
                    self.remove(sp, dp, src, dst);
                    return None;
                }
            }
        } else if (flags & 2 != 0) || (flags & 7 == 0) {
            // SYN flag or no flag
            let mut sn = seqnr;
            if flags & 2 == 2 {
                sn += 1;
            }
            self.add_data(sp, dp, src, dst, sn, data);
            return None;
        }
        return None;
    }
}

pub(crate) fn clean_tcp_list(tcp_list: &Arc<Mutex<TCP_Connections>>, rx: mpsc::Receiver<String>) {
    let timeout = time::Duration::from_secs(1);

    loop {
        let dur = tcp_list.lock().unwrap().check_timeout();
        match rx.try_recv() {
            Ok(_e) => {
                return;
            }
            Err(TryRecvError::Disconnected) => {
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
        sleep(std::cmp::max(timeout, time::Duration::from_secs(dur)));
    }
}
