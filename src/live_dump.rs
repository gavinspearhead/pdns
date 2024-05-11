use crate::http_server::listen;
use std::{
    io::{self, Write},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error};

pub(crate) struct Live_dump {
    listener: TcpListener,
    streams: Vec<TcpStream>,
}

impl Live_dump {
    pub(crate) fn new(addr: &str, port: u16) -> Live_dump {
        let l = Live_dump {
            listener: if let Some(x) = listen(addr, port) {
                debug!("Listening on {addr}:{port}");
                x
            } else {
                panic!("Cannot listen on {addr}:{port}")
            },
            streams: Vec::new(),
        };
        let Ok(_) = l.listener.set_nonblocking(true) else {
            panic!("Cannot set non-blocking on socket");
        };
        return l;
    }

    pub(crate) fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((socket, addr)) => {
                    debug!("New connection from {addr}");
                    self.streams.push(socket);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return;
                }
                Err(e) => error!("couldn't get client: {e:?}"),
            }
        }
    }

    pub(crate) fn write_all(&mut self, s: &str) {
        let mut x = Vec::new();
        for (idx, mut stream) in (&self.streams).into_iter().enumerate() {
            match stream.write_all(&s.as_bytes()) {
                Ok(_) => {}
                Err(e) => {
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
}
