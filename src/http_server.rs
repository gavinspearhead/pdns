use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::exit,
    sync::{Arc, Mutex},
};

use tracing::error;

use crate::config::Config;
use crate::statistics::Statistics;
use crate::tcp_connection::TCP_Connections;

pub fn listen(address: &str, port: u16) -> Option<TcpListener> {
    if address.is_empty() {
         return None;
    }
    let addr = format!("{address}:{port}");
    tracing::debug!("Listening on {addr}");
    let x = TcpListener::bind(addr);
    match x {
        Ok(conn) => {
            Some(conn)
        }
        Err(_e) => {
            error!("Cannot listen on {address}:{port}");
            None
        }
    }
}

pub(crate) fn server(
    listener: TcpListener,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_connection(stream, stats, tcp_list, config);
            }
            Err(e) => {
                tracing::error!("Cannot open stream {}", e);
                exit(-1);
            }
        }
    }
}

pub(crate) fn handle_connection(
    mut stream: TcpStream,
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
) {
    let buf_reader = BufReader::new(&mut stream);
    let http_request: Vec<_> = buf_reader
        .lines()
        .map(|result| result.unwrap())
        .take_while(|line| !line.is_empty())
        .collect();

    let req: Vec<&str> = http_request[0].split(' ').collect();
    if req[0] != "GET" {
        return;
    }

    let status_line = "HTTP/1.1 200 OK";
    if req[1] == "/stats" {
        let stats_data = stats.lock().unwrap().clone();
        let stats_str = serde_json::to_string(&stats_data).unwrap();
        let len = stats_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{stats_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == "/topdomains" {
        let top_domains = stats.lock().unwrap().topdomain.clone();
        let td_str = serde_json::to_string(&top_domains).unwrap();
        let len = td_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{td_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == "/topnx" {
        let top_nx = stats.lock().unwrap().topnx.clone();
        let td_str = serde_json::to_string(&top_nx).unwrap();
        let len = td_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{td_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == "/destinations" {
        let destinations = stats.lock().unwrap().destinations.clone();
        let d_str = serde_json::to_string(&destinations).unwrap();
        let len = d_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{d_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == "/sources" {
        let sources = stats.lock().unwrap().sources.clone();
        let s_str = serde_json::to_string(&sources).unwrap();
        let len = s_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{s_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == "/debug" {
        let tcp_len = tcp_list.lock().unwrap().len();
        let debug_str = format!("TCP LEN: {tcp_len}\r\n");
        let len = debug_str.len();
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{debug_str}");
        stream.write_all(response.as_bytes()).unwrap();
    } else if req[1] == "/config" {
        let mut config_copy = config.clone();
        if !config_copy.dbpassword.is_empty() {
            config_copy.dbpassword = "****".to_string();
        }
        let s_str = serde_json::to_string(&config_copy).unwrap();
        let len = s_str.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{s_str}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    } else {
        let status_line = "HTTP/1.1 404 Not found";
        let s = "Page not found";
        let len = s.len() + 2;
        let response = format!("{status_line}\r\nContent-Length: {len}\r\n\r\n{s}\r\n");
        stream.write_all(response.as_bytes()).unwrap();
    }
}
