use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::IpAddr,
    sync::{
        mpsc::{self, TryRecvError},
        Arc, Mutex,
    },
    thread::sleep,
    time,
};
use strum_macros::{EnumIter};
use tracing::debug;

use crate::tcp_data::Tcp_data;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter )]
pub(crate) enum TCP_Connections_Error_Type {
    NotFound,
}

#[derive(Debug, Clone)]
pub(crate) struct TcpConnection_error {
    error_type: TCP_Connections_Error_Type,
    error_str: String,
    value: String,
}

impl TcpConnection_error {
    pub(crate) fn new(err_t: TCP_Connections_Error_Type, val: &str) -> TcpConnection_error {
        let s = match err_t {
            TCP_Connections_Error_Type::NotFound => "TCP Connection not found",
        };

        TcpConnection_error {
            error_type: err_t,
            error_str: s.to_owned(),
            value: val.to_string(),
        }
    }
}

impl fmt::Display for TcpConnection_error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.error_str, self.value)
    }
}

impl Error for TcpConnection_error {
    fn description(&self) -> &str {
        &self.error_str
    }
}

#[derive(Debug, Clone)]
struct Tcp_connection {
    in_data: Tcp_data,
    ts: DateTime<Utc>,
}

impl Tcp_connection {
    pub fn new(seqnr: u32, timestamp: DateTime<Utc>) -> Tcp_connection {
        Tcp_connection {
            in_data: Tcp_data::new(seqnr),
            ts: timestamp,
        }
    }
    pub fn get_data(&self) -> &Tcp_data {
        &self.in_data
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TCP_Connections {
    connections: HashMap<(IpAddr, IpAddr, u16, u16), Tcp_connection>,
    timelimit: i64,
}

impl TCP_Connections {
    pub fn new() -> TCP_Connections {
        TCP_Connections {
            connections: HashMap::new(),
            timelimit: 20,
        }
    }

    pub fn len(&self) -> usize {
        self.connections.len()
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
            .or_insert(Tcp_connection::new(seqnr, timestamp));
        c.in_data.add_data(seqnr, data);
        if c.in_data.check_data_size() {
            // if it is too big we just throw it away
            let _ = self.remove(sp, dp, src, dst);
        }
    }

    pub fn get_data(
        &self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<&Tcp_data, Box<dyn Error>> {
        let Some(c) = self.connections.get(&(src, dst, sp, dp)) else {
            debug!("Connection not found {src}:{sp} => {dst}:{dp}");
            return Err(TcpConnection_error::new(
                TCP_Connections_Error_Type::NotFound,
                &format!("{src}:{dp} => {dst}:{dp}"),
            )
            .into());
        };
        Ok(c.get_data())
    }

    pub fn remove(
        &mut self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<(), Box<dyn Error>> {
        //  println!("Removing key {} {} {} {} ", src, dst, sp, dp);
        match self.connections.remove(&(src, dst, sp, dp)) {
            None => {
                debug!("Connection not found {src}:{sp} => {dst}:{dp}");
                Err(TcpConnection_error::new(
                    TCP_Connections_Error_Type::NotFound,
                    &format!("{src}:{sp} => {dst}:{dp}"),
                )
                .into())
            }
            Some(_) => Ok(())
        }
    }

    pub fn check_timeout(&mut self) -> i64 {
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
            m_ts 
        } else {
            self.timelimit 
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
            return match self.get_data(sp, dp, src, dst) {
                Ok(x) => {
                    let y = x.clone();
                    let _ = self.remove(sp, dp, src, dst);
                    Some(y)
                }
                Err(_e) => {
                    let _ = self.remove(sp, dp, src, dst);
                    None
                }
            }
        } else if (flags & 2 != 0) || (flags.trailing_zeros() >= 3) {
            // SYN flag or no flag
            let mut sn = seqnr;
            if flags & 2 == 2 {
                sn += 1;
            }
            self.add_data(sp, dp, src, dst, sn, data);
            return None;
        }
        None
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
        sleep(std::cmp::max(timeout, time::Duration::from_secs(dur as u64)));
    }
}
