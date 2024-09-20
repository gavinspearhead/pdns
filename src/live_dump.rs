use crate::dns::DnsReplyType;
use crate::{http_server::listen, packet_info::Packet_info};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::IpAddr;
use std::{
    io::{self, Write},
    net::{TcpListener, TcpStream},
};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter, EnumString, IntoStaticStr};
use tracing::{debug, error};

#[derive(
    Debug, EnumIter,  Clone, IntoStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize, AsRefStr
)]
pub(crate) enum Filter_fields {
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    REPLY_CODE,
    NAME,
    CLASS,
    RR_TYPE,
    ANSWER,
    DOMAIN,
    ASN,
}

impl Filter_fields {
    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }

    pub(crate) fn find(val: &str) -> Result<Self, Box<dyn std::error::Error>> {
        for field in Filter_fields::iter() {
            if (field.as_ref()) == val.to_ascii_uppercase() {
                let result = field.clone();
                return Ok(result);
            }
        }
        Err("Not found".into())
    }
}

impl fmt::Display for Filter_fields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[derive(
    Debug, EnumIter, Clone, IntoStaticStr, EnumString, PartialEq, Eq, Serialize, Deserialize, AsRefStr
)]
enum Filter_operator {
    EQUAL,
    NOT_EQUAL,
    START_WITH,
    END_WITH,
    CONTAINS,
}
impl fmt::Display for Filter_operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}
type SimpleExpr = (Filter_fields, Filter_operator, String);

#[derive(Debug, Clone)]
pub(crate) struct Filter {
    // FIELD = VALUE OR (FIELD = VALUE AND FIELD = VALUE)
    // operators =, !=, $=, ^=
    expr: SimpleExpr,
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Filter {
    pub(crate) fn new(s: &str) -> Result<Filter, Box<dyn std::error::Error>> {
        let mut spl = s.split_whitespace();
        let field = if let Some(x) = spl.next() {
            match Filter_fields::find(x) {
                Ok(x) => x,
                Err(e) => {
                    debug!("Not found");
                    return Err(e);
                }
            }
        } else {
            debug!("No more parts");
            return Err("not found".into());
        };

        debug!("Field: {:?}", field);
        let oper = match spl.next() {
            Some(x) => match x {
                "=" | "==" => Filter_operator::EQUAL,
                "!=" => Filter_operator::NOT_EQUAL,
                "^=" => Filter_operator::START_WITH,
                "$=" => Filter_operator::END_WITH,
                "*=" => Filter_operator::CONTAINS,
                _ => return Err("unknown operator".into()),
            },
            None => return Err("not found".into()),
        };
        debug!("Oper: {:?}", oper);
        let Some(value) = spl.next() else {
            return Err("not found".into());
        };
        debug!("Value: {:?}", value.to_string());

        Ok(Filter {
            expr: (field, oper, value.to_string()),
        })
    }

    fn matches(&self, packet_info: &Packet_info) -> bool {
        debug!("{}", self.expr.0);
        match self.expr.0 {
            Filter_fields::SRC_IP => {
                let src_addr: IpAddr = match self.expr.2.parse() {
                    Ok(x) => x,
                    Err(_e) => {
                        return false;
                    }
                };
                if self.expr.1 == Filter_operator::EQUAL {
                    return packet_info.s_addr == src_addr;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    return packet_info.s_addr != src_addr;
                }
                false
            }
            Filter_fields::DST_IP => {
                let dst_addr: IpAddr = match self.expr.2.parse() {
                    Ok(x) => x,
                    Err(_e) => {
                        return false;
                    }
                };
                if self.expr.1 == Filter_operator::EQUAL {
                    return packet_info.d_addr == dst_addr;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    return packet_info.d_addr != dst_addr;
                }
                false
            }
            Filter_fields::SRC_PORT => {
                let port: u16 = match self.expr.2.parse::<u16>() {
                    Ok(x) => x,
                    Err(_e) => {
                        return false;
                    }
                };
                if self.expr.1 == Filter_operator::EQUAL {
                    return packet_info.sp == port;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    return packet_info.sp != port;
                }
                false
            }
            Filter_fields::DST_PORT => {
                let port: u16 = match self.expr.2.parse::<u16>() {
                    Ok(x) => x,
                    Err(_e) => {
                        return false;
                    }
                };
                if self.expr.1 == Filter_operator::EQUAL {
                    return packet_info.dp == port;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    return packet_info.dp != port;
                }
                false
            }
            Filter_fields::REPLY_CODE => {
              //  debug!("AA {} {} {}", self.expr.0, self.expr.1, self.expr.2);
                let Ok(rc) = self.expr.2.to_uppercase().parse::<DnsReplyType>() else {
                    debug!("false");
                    return false;
                };
              //  debug!("RC: {}", rc);
                let c = rc;
               // let Ok(c) = DnsReplyType::find(rc) else {
                //    return false;
                //};
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        //debug!("{} {} != {}", i.error, c, i.error == c );
                        //debug!("{}", packet_info);
                        if i.error == c {
                            return true;
                        }
                    }
                    return false;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                //        debug!("{} {} != {}", i.error, c, i.error == c );
                  //      debug!("{}", packet_info);
                        if i.error != c {
                            return true;
                        }
                    }
                    return false;
                }
                false
            }
            Filter_fields::NAME => {
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        if i.name != self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                        if i.name == self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::START_WITH {
                    for i in &packet_info.dns_records {
                        if !i.name.starts_with(&self.expr.2) {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::END_WITH {
                    for i in &packet_info.dns_records {
                        if !i.name.ends_with(&self.expr.2) {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::CONTAINS {
                    for i in &packet_info.dns_records {
                        if !i.name.contains(&self.expr.2) {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }
            Filter_fields::CLASS => {
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        if i.class == self.expr.2 {
                            return true;
                        }
                    }
                    return false;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                        if i.class != self.expr.2 {
                            return true;
                        }
                    }
                    return false;
                }
                false
            }

            Filter_fields::RR_TYPE => {
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        if i.rr_type != self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                        if i.rr_type == self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }

            Filter_fields::ANSWER => {
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        if i.rdata != self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                        if i.rdata == self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }

            Filter_fields::DOMAIN => {
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        if i.domain != self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                        if i.domain == self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::START_WITH {
                    for i in &packet_info.dns_records {
                        if !i.domain.starts_with(&self.expr.2) {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::END_WITH {
                    for i in &packet_info.dns_records {
                        if !i.domain.ends_with(&self.expr.2) {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::CONTAINS {
                    for i in &packet_info.dns_records {
                        if !i.domain.contains(&self.expr.2) {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }

            Filter_fields::ASN => {
                if self.expr.1 == Filter_operator::EQUAL {
                    for i in &packet_info.dns_records {
                        if i.asn != self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                } else if self.expr.1 == Filter_operator::NOT_EQUAL {
                    for i in &packet_info.dns_records {
                        if i.asn == self.expr.2 {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }
        }
    }

    fn to_str(&self) -> String {
        format!("{} {} {}", self.expr.0, self.expr.1, self.expr.2)
    }
}

#[derive(Debug)]
pub(crate) struct Live_dump_session {
    stream: TcpStream,
    filters: Vec<Filter>,
}

impl Live_dump_session {
    pub(crate) fn new(s: TcpStream) -> Live_dump_session {
        Live_dump_session {
            stream: s,
            filters: Vec::new(),
        }
    }

    pub(crate) fn matches(&self, packet_info: &Packet_info) -> bool {
        for filter in &self.filters {
            if !filter.matches(packet_info) {
                return false;
            }
        }
        true
    }

    pub(crate) fn add_filter(&mut self, s: &str) -> Result<(), Box<dyn std::error::Error>> {
        let split_str = s.split_terminator(&['\r', '\n']);

        for t in split_str {
            let x = t.trim();
            debug!("adding filter {x}");
            if x.is_empty() {
                continue;
            }
            let f = match Filter::new(x) {
                Ok(x) => x,
                Err(e) => {
                    return Err(e);
                }
            };

            self.filters.push(f);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Live_dump {
    listener: Option<TcpListener>,
    streams: Vec<Live_dump_session>,
}

impl Live_dump {
    pub(crate) fn new(addr: &str, port: u16) -> Live_dump {
        if addr.is_empty() || port == 0 {
            debug!("Live dump disabled");
            return Live_dump {
                listener: None,
                streams: Vec::new(),
            };
        }

        Live_dump {
            listener: if let Some(x) = listen(addr, port) {
                debug!("Listening on {addr}:{port}");
                let Ok(()) = x.set_nonblocking(true) else {
                    panic!("Cannot set non-blocking on socket");
                };
                Some(x)
            } else {
                panic!("Cannot listen on {addr}:{port}")
            },
            streams: Vec::new(),
        }
    }

    pub(crate) fn accept(&mut self) {
        if let Some(listener) = &self.listener {
            loop {
                match listener.accept() {
                    Ok((socket, addr)) => {
                        debug!("New connection from {addr}");
                        socket
                            .set_nonblocking(true)
                            .expect("set_nonblocking call failed");
                        self.streams.push(Live_dump_session::new(socket));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return;
                    }
                    Err(e) => {
                        error!("couldn't get client: {e:?}");
                        return;
                    }
                }
            }
        }
    }

    pub(crate) fn write_all(&mut self, p1: &Packet_info) {
        let mut x = Vec::new();

        let tmp_str = &format!("{p1:#}");
        for (idx, stream) in self.streams.iter().enumerate() {
            if stream.matches(p1) {
                if let Err(e) =  (&stream.stream).write_all(tmp_str.as_bytes()) {
                    debug!("{e}");
                    x.push(idx);
                }
            }
        }
        for i in x {
            debug!("Removing connection {i}");
            self.streams.remove(i);
        }
    }

    pub(crate) fn read_all(&mut self) {
        let mut buf: [u8; 128] = [0; 128];
        let mut peek_buf: [u8; 128] = [0; 128];
        for stream in &mut self.streams {
            let byte_count = match stream.stream.peek(&mut peek_buf) {
                Ok(x) => {
                    let pos = if let Some(p) = peek_buf.iter().position(|r| r == &0xa) {
                        if p == 0 {
                            let _ = (&stream.stream).read_exact(&mut buf[0..1]);
                            0
                        } else if p <= x {
                            p
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    pos
                }
                Err(_) => 0,
            };
            if byte_count > 0 {
                match (&stream.stream).read_exact(&mut buf[0..byte_count]) {
                    Ok(()) => {
                        let line = &String::from_utf8_lossy(&buf[0..byte_count]).to_lowercase();
                        if line == "show filters" {
                            let _ = stream.stream.write_all(b"Filters\n");
                            for ftr in &stream.filters {
                                let _ = stream.stream.write_all(ftr.to_str().as_bytes());
                                let _ = stream.stream.write_all(b"\n");
                            }
                            let _ = stream.stream.write_all(b"End filters\n");
                        } else if line == "reset filters" {
                            stream.filters = Vec::new();
                        } else {
                            let _ = stream.add_filter(line);
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        debug!("Nothing to read");
                        break;
                    }
                    Err(_) => {
                        debug!("Read error");
                    }
                };
            }
        }
    }
}
