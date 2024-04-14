use asn_db2::{Database, IpEntry};
use chrono::{DateTime, Utc};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

use crate::{
    dns::{DNS_RR_type, DNS_record},
    DNS_Protocol,
};

#[derive(Debug, Clone)]
pub(crate) struct Packet_info {
    pub timestamp: DateTime<Utc>,
    pub sp: u16, // source port
    pub dp: u16, // destination port
    pub s_addr: IpAddr,
    pub d_addr: IpAddr,
    pub ip_len: u16,
    pub frame_len: u32,
    pub data_len: u32,
    pub protocol: DNS_Protocol,
    pub dns_records: Vec<DNS_record>,
}

impl Default for Packet_info {
    fn default() -> Self {
        Packet_info {
            timestamp: Utc::now(),
            sp: 0,
            dp: 0,
            s_addr: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            d_addr: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_len: 0,
            frame_len: 0,
            data_len: 0,
            protocol: DNS_Protocol::UDP,
            dns_records: Vec::new(),
        }
    }
}

impl Packet_info {
    pub fn set_timestamp(&mut self, timestamp: DateTime<Utc>) {
        self.timestamp = timestamp;
    }
    pub fn set_source_port(&mut self, port: u16) {
        self.sp = port;
    }
    pub fn set_protocol(&mut self, protocol: DNS_Protocol) {
        self.protocol = protocol;
    }
    pub fn set_dest_port(&mut self, port: u16) {
        self.dp = port;
    }
    pub fn set_source_ip(&mut self, s_ip: IpAddr) {
        self.s_addr = s_ip;
    }
    pub fn set_dest_ip(&mut self, d_ip: IpAddr) {
        self.d_addr = d_ip;
    }
    pub fn set_ip_len(&mut self, len: u16) {
        self.ip_len = len;
    }
    pub fn set_data_len(&mut self, len: u32) {
        self.data_len = len;
    }
    pub fn add_dns_record(&mut self, rec: DNS_record) {
        self.dns_records.push(rec);
    }

    pub fn to_str(&self) -> String {
        return format!(
            "{}:{} => {}:{}\n{:?}",
            self.s_addr, self.sp, self.d_addr, self.dp, self.dns_records
        );
    }
    pub fn to_csv(&self) -> String {
        let mut s = String::new();
        for i in &self.dns_records {
            s += &format!(
                "{},{},{},{},{},{},{},{},{}\n",
                self.s_addr,
                self.d_addr,
                self.timestamp,
                i.rr_type,
                i.class,
                i.ttl,
                i.name,
                i.rdata,
                1
            );
        }
        return s;
    }
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        for i in &self.dns_records {
            s += &format!(
                "{{ 
                    \"source_ip\" : {},
                    \"destination_ip\" : {},
                   \"timestamp\": {},
                   \"rr_type\": {},
                   \"class\": {},
                   \"ttl\": {},
                   \"name\": {},
                   \"rdata\": {},
                   \"count\": {}
            }},",
                self.s_addr,
                self.d_addr,
                self.timestamp,
                i.rr_type,
                i.class,
                i.ttl,
                i.name,
                i.rdata,
                1
            );
        }
        return s;
    }

    fn find_asn<'a>(asn_db: &'a Database, ip: &'a str) -> Option<IpEntry<'a>> {
        match ip.parse::<IpAddr>() {
            Ok(ip) => {
                return asn_db.lookup(ip);
            }
            Err(_) => return None,
        }
    }

    pub fn update_asn(&mut self, asn_db: &asn_db2::Database) {
        for i in self.dns_records.iter_mut() {
            if let Ok(rr_type) = DNS_RR_type::from_string(&i.rr_type) {
                if rr_type == DNS_RR_type::A || rr_type == DNS_RR_type::AAAA {
                    if let Some(x) = Packet_info::find_asn(asn_db, &i.rdata) {
                        match x {
                            IpEntry::V4(v4) => {
                                i.asn = v4.as_number.to_string();
                                i.asn_owner = v4.owner.clone();
                                i.prefix = v4.subnet.to_string();
                            }
                            IpEntry::V6(v6) => {
                                i.asn = v6.as_number.to_string();
                                i.asn_owner = v6.owner.clone();
                                i.prefix = v6.subnet.to_string();
                            }
                        }
                    }
                }
            }
        }
        //println!("{:?}", self.dns_records);
    }
}

impl fmt::Display for Packet_info {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{}:{} => {}:{}",
            self.s_addr, self.sp, self.d_addr, self.dp
        )
        .expect("Cannot write output format ");
        for i in &self.dns_records {
            writeln!(f, "{}", i).expect("Cannot write output format ");
        }
        return write!(f, "");
    }
}
