use crate::tcp_connection::TCP_Connections_Error_Type::NotFound;
use crate::tcp_data::Tcp_data;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use serde_with::serde_as;
use std::cmp::max;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::IpAddr,
    sync::{
        mpsc::{self, TryRecvError},
        Arc,
    },
    thread::sleep,
    time,
};
use strum_macros::EnumIter;
use tracing::debug;
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub(crate) enum TCP_Connections_Error_Type {
    NotFound,
}

#[derive(Debug, Clone)]
pub(crate) struct TcpConnection_error {
    //error_type: TCP_Connections_Error_Type,
    error_str: String,
    value: String,
}

impl TcpConnection_error {
    pub(crate) fn new(err_t: TCP_Connections_Error_Type, val: &str) -> TcpConnection_error {
        let s = match err_t {
            NotFound => "TCP Connection not found",
        };

        TcpConnection_error {
            //error_type: err_t,
            error_str: s.to_owned(),
            value: val.to_owned(),
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
#[serde_as]
#[derive(Debug, Clone, Serialize, PartialEq, PartialOrd)]
struct Tcp_connection {
    in_data: Tcp_data,
    #[serde(with = "chrono::serde::ts_seconds")]
    ts: DateTime<Utc>,
}

impl Tcp_connection {
    pub fn new(seq_nr: u32, timestamp: DateTime<Utc>, max_size: u32) -> Tcp_connection {
        Tcp_connection {
            in_data: Tcp_data::new(seq_nr, max_size),
            ts: timestamp,
        }
    }
    #[inline]
    pub fn get_data(&self) -> &Tcp_data {
        &self.in_data
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]

pub(crate) struct TCP_Connections {
    #[serde(with = "vectorize")]
    connections: HashMap<(IpAddr, IpAddr, u16, u16), Tcp_connection>,
    timelimit: u64,
    max_tcp_len: u32,
}

impl TCP_Connections {
    const SYN_FLAG:u8 = 2;
    const FIN_FLAG:u8 = 1;
    const RESET_FLAG:u8 = 4;
    pub fn new(maxsize: u32) -> TCP_Connections {
        TCP_Connections {
            connections: HashMap::new(),
            timelimit: 20,
            max_tcp_len: maxsize,
        }
    }
    /* #[inline]
        pub fn len(&self) -> usize {
            self.connections.len()
        }
    */
    pub fn add_data(
        &mut self,
        sp: u16,
        dp: u16,
        src: &IpAddr,
        dst: &IpAddr,
        seqnr: u32,
        data: &[u8],
        // _timestamp: DateTime<Utc>,
    ) {
        let c = self
            .connections
            .entry((*src, *dst, sp, dp))
            .or_insert_with(|| Tcp_connection::new(seqnr, Utc::now(), self.max_tcp_len));
        c.in_data.add_data(seqnr, data);
    }
    pub fn get_data(
        &self,
        sp: u16,
        dp: u16,
        src: &IpAddr,
        dst: &IpAddr,
    ) -> Result<&Tcp_data, Box<dyn Error>> {
        let Some(c) = self.connections.get(&(*src, *dst, sp, dp)) else {
            debug!("Connection not found {src}:{sp} => {dst}:{dp}");
            return Err(
                TcpConnection_error::new(NotFound, &format!("{src}:{dp} => {dst}:{dp}")).into(),
            );
        };
        Ok(c.get_data())
    }

    pub fn remove(
        &mut self,
        sp: u16,
        dp: u16,
        src: &IpAddr,
        dst: &IpAddr,
    ) -> Result<(), Box<dyn Error>> {
        //debug!("Removing key {src} {dst} {sp} {dp} ");
        match self.connections.remove(&(*src, *dst, sp, dp)) {
            None => {
                debug!("Connection not found {src}:{sp} => {dst}:{dp}");
                Err(TcpConnection_error::new(NotFound, &format!("{src}:{sp} => {dst}:{dp}")).into())
            }
            Some(_) => Ok(()),
        }
    }

    pub fn check_timeout(&mut self) -> u64 {
        let now = Utc::now().timestamp();
        let mut min_idle = 1;
        // debug!("Checking timeout before: Size : {}", self.connections.len());
        self.connections.retain(|_, v| {
            let idle_time = (now - v.ts.timestamp()) as u64;
            min_idle = min_idle.min(self.timelimit - idle_time);
            //  debug!("Check timeout after: {} {}", v.ts, idle_time);
            idle_time < self.timelimit
        });
        if self.connections.is_empty() {
            min_idle = self.timelimit;
        } else {
            min_idle = min_idle.min(self.timelimit);
        }
        //        debug!( "Checking timeout after Size : {} {min_idle}", self.connections.len() );
        min_idle 
    }

    pub fn process_data(
        &mut self,
        sp: u16,
        dp: u16,
        src: IpAddr,
        dst: IpAddr,
        seq_nr: u32,
        data: &[u8],
        flags: u8,
    ) -> Option<Tcp_data> {
        if (flags & Self::FIN_FLAG != 0) || (flags & Self::RESET_FLAG != 0) {
            // FIN flag or reset
            self.add_data(sp, dp, &src, &dst, seq_nr, data);
            return match self.get_data(sp, dp, &src, &dst) {
                Ok(x) => {
                    let y = x.to_owned();
                    let _ = self.remove(sp, dp, &src, &dst);
                    Some(y)
                }
                Err(_e) => {
                    let _ = self.remove(sp, dp, &src, &dst);
                    None
                }
            };
        } else if (flags & Self::SYN_FLAG != 0) || (flags.trailing_zeros() >= 3) {
            // SYN flag or no flag
            let mut sn = seq_nr;
            if flags & Self::SYN_FLAG != 0 {
                // on syn we need to increment the seq nr
                sn += 1;
            }
            self.add_data(sp, dp, &src, &dst, sn, data);
            return None;
        }
        None
    }
}

pub(crate) fn clean_tcp_list(tcp_list: &Arc<Mutex<TCP_Connections>>, rx: mpsc::Receiver<String>) {
    let min_timeout = time::Duration::from_secs(1);

    loop {
        let dur = tcp_list.lock().check_timeout();
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {}
        }
        sleep(max(min_timeout, time::Duration::from_secs(dur)));
    }
}
