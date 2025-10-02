use std::fmt::Write;
use crate::dns_protocol::DNS_Protocol;
use crate::dns_record::DNS_record;
use crate::dns_rr_type::DNS_RR_type;
use asn_db2::{Database, IpEntry};
use chrono::{DateTime, Utc};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Debug, Clone)]
pub(crate) struct Packet_info {
    pub timestamp: DateTime<Utc>,
    pub s_addr: IpAddr,
    pub d_addr: IpAddr,
    pub sp: u16, // source port
    pub dp: u16, // destination port
    pub ip_len: u16,
    pub frame_len: u32,
    pub data_len: u32,
    pub protocol: DNS_Protocol,
    pub dns_records: Vec<DNS_record>,
}

impl Packet_info {
    pub fn new() -> Self {
        Packet_info {
            timestamp: Utc::now(),
            sp: 0,
            dp: 0,
            s_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            d_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_len: 0,
            frame_len: 0,
            data_len: 0,
            protocol: DNS_Protocol::UDP,
            dns_records: Vec::new(),
        }
    }

    #[inline]
    pub fn set_timestamp(&mut self, timestamp: DateTime<Utc>) {
        self.timestamp = timestamp;
    }
    #[inline]
    pub fn set_source_port(&mut self, port: u16) {
        self.sp = port;
    }
    #[inline]
    pub fn set_protocol(&mut self, protocol: DNS_Protocol) {
        self.protocol = protocol;
    }
    #[inline]
    pub fn set_dest_port(&mut self, port: u16) {
        self.dp = port;
    }
    #[inline]
    pub fn set_source_ip(&mut self, s_ip: IpAddr) {
        self.s_addr = s_ip;
    }
    #[inline]
    pub fn set_dest_ip(&mut self, d_ip: IpAddr) {
        self.d_addr = d_ip;
    }
    #[inline]
    pub fn set_ip_len(&mut self, len: u16) {
        self.ip_len = len;
    }
    #[inline]
    pub fn set_data_len(&mut self, len: u32) {
        self.data_len = len;
    }
    #[inline]
    pub fn add_dns_record(&mut self, rec: DNS_record) {
        self.dns_records.push(rec);
    }

    pub fn to_csv(&self) -> String {
        let mut s = String::new();
        for i in &self.dns_records {
            write!(s,
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
            ).unwrap();
        }
        s
    }
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        for i in &self.dns_records {
            write!(s,
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
            ).unwrap();
        }
        s
    }
    #[inline]
    fn find_asn<'a>(asn_db: &'a Database, ip: &'a str) -> Option<IpEntry<'a>> {
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            asn_db.lookup(ip_addr)
        } else {
            None
        }
    }
    pub fn update_asn(&mut self, asn_db: &Database) {
        for record in &mut self.dns_records {
            if matches!(record.rr_type, DNS_RR_type::A | DNS_RR_type::AAAA) {
                if let Some(ip_asn_data) = Packet_info::find_asn(asn_db, &record.rdata) {
                    match ip_asn_data {
                        IpEntry::V4(v4) => {
                            record.asn = v4.as_number;
                            record.asn_owner = v4.owner.clone();
                            record.prefix = v4.subnet.to_string();
                        }
                        IpEntry::V6(v6) => {
                            record.asn = v6.as_number;
                            record.asn_owner = v6.owner.clone();
                            record.prefix = v6.subnet.to_string();
                        }
                    }
                }
            }
        }
    }
    pub fn update_public_suffix(&mut self, publicsuffixlist: &publicsuffix::List) {
        for record in &mut self.dns_records {
            if record.domain.is_empty() {
                record.domain = crate::dns_packet::find_domain(publicsuffixlist, &record.name);
            }
        }
    }
}

impl fmt::Display for Packet_info {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{}:{} => {}:{} ({})",
            self.s_addr, self.sp, self.d_addr, self.dp, self.protocol
        )
        .expect("Cannot write output format ");
        for i in &self.dns_records {
            if f.alternate() {
                write!(f, "{i:#}").expect("Cannot write output format ");
            } else {
                write!(f, "{i}").expect("Cannot write output format ");
            }
        }
        write!(f, "")
    }
}
