#![allow(non_camel_case_types)]
use base64::engine::general_purpose::STANDARD;

use crate::dns_class::DNS_Class;
use crate::dns_packet::{dns_header, dns_question};
use crate::dns_reply_type::DnsReplyType;
use crate::dns_rr_type::DNS_RR_type;
use crate::rr::rr_a::RR_A;
use crate::skiplist::Skip_List;
use base64::Engine;
use log::debug;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::str::FromStr;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, fmt, reload, Layer};
pub mod dns_record_trait;
use crate::dns_record_trait::DNSRecord;

pub mod config;
pub mod dns;
pub mod dns_answers;
pub mod dns_cache;
pub mod dns_class;
pub mod dns_helper;
pub mod dns_name;
pub mod dns_opcodes;
pub mod dns_packet;
pub mod dns_protocol;
pub mod dns_record;
pub mod dns_reply_type;
pub mod dns_rr;
pub mod dns_rr_type;
pub mod edns;
pub mod errors;
pub mod http_server;
pub mod live_dump;
pub mod mysql_connection;
pub mod network_packet;
pub mod packet_info;
pub mod packet_queue;
pub mod rank;
pub mod rr;
pub mod skiplist;
pub mod statistics;
pub mod tcp_connection;
pub mod tcp_data;
pub mod time_stats;
pub mod util;
pub mod version;

use crate::dns_answers::dns_answer;
//use crate::dns_helper::names_list;
use crate::dns_rr::{RR_HTTPS, RR_TXT};
use crate::rr::rr_a6::RR_A6;
use crate::rr::rr_aaaa::RR_AAAA;
use crate::rr::rr_avc::RR_AVC;
use crate::rr::rr_caa::RR_CAA;
use crate::rr::rr_cdnskey::RR_CDNSKEY;
use crate::rr::rr_cds::RR_CDS;
use crate::rr::rr_cert::RR_CERT;
use crate::rr::rr_cla::RR_CLA;
use crate::rr::rr_cname::RR_CNAME;
use crate::rr::rr_csync::RR_CSYNC;
use crate::rr::rr_dhcid::RR_DHCID;
use crate::rr::rr_dname::RR_DNAME;
use crate::rr::rr_doa::RR_DOA;
use crate::rr::rr_eid::RR_EID;
use crate::rr::rr_eui48::RR_EUI48;
use crate::rr::rr_eui64::RR_EUI64;
use crate::rr::rr_gid::RR_GID;
use crate::rr::rr_gpos::RR_GPOS;
use crate::rr::rr_hinfo::RR_HINFO;
use crate::rr::rr_hip::RR_HIP;
use crate::rr::rr_https::HttpsSvcParam;
use crate::rr::rr_ipn::RR_IPN;
use crate::rr::rr_ipseckey::RR_IPSECKEY;
use crate::rr::rr_isdn::RR_ISDN;
use crate::rr::rr_key::RR_KEY;
use crate::rr::rr_kx::RR_KX;
use crate::rr::rr_l32::RR_L32;
use crate::rr::rr_l64::RR_L64;
use crate::rr::rr_loc::RR_LOC;
use crate::rr::rr_lp::RR_LP;
use crate::rr::rr_maila::RR_MAILA;
use crate::rr::rr_mailb::RR_MAILB;
use crate::rr::rr_mb::RR_MB;
use crate::rr::rr_md::RR_MD;
use crate::rr::rr_mf::RR_MF;
use crate::rr::rr_mg::RR_MG;
use crate::rr::rr_minfo::RR_MINFO;
use crate::rr::rr_mx::RR_MX;
use crate::rr::rr_naptr::RR_NAPTR;
use crate::rr::rr_nid::RR_NID;
use crate::rr::rr_ninfo::RR_NINFO;
use crate::rr::rr_ns::RR_NS;
use crate::rr::rr_nsap::RR_NSAP;
use crate::rr::rr_nsap_ptr::RR_NSAP_PTR;
use crate::rr::rr_nsec::RR_NSEC;
use crate::rr::rr_nsec3::RR_NSEC3;
use crate::rr::rr_nsec3param::RR_NSEC3PARAM;
use crate::rr::rr_null::RR_NULL;
use crate::rr::rr_nxt::RR_NXT;
use crate::rr::rr_openpgpkey::RR_OPENPGPKEY;
use crate::rr::rr_ptr::RR_PTR;
use crate::rr::rr_px::RR_PX;
use crate::rr::rr_resinfo::RR_RESINFO;
use crate::rr::rr_rp::RR_RP;
use crate::rr::rr_rt::RR_RT;
use crate::rr::rr_sink::RR_SINK;
use crate::rr::rr_soa::RR_SOA;
use crate::rr::rr_spf::RR_SPF;
use crate::rr::rr_srv::RR_SRV;
use crate::rr::rr_sshfp::RR_SSHFP;
use crate::rr::rr_talink::RR_TALINK;
use crate::rr::rr_tlsa::RR_TLSA;
use crate::rr::rr_uid::RR_UID;
use crate::rr::rr_uri::RR_URI;
use crate::rr::rr_wallet::RR_WALLET;
use crate::rr::rr_wks::RR_WKS;
use crate::rr::rr_x25::RR_X25;

pub(crate) fn make_reply(
    dns_answer: &mut dns_answer,
    dns_query: &dns_question,
    header: &mut dns_header,
) -> Result<(), Box<dyn std::error::Error>> {
    *dns_answer = dns_answer::new();

    if dns_query.dns_class_type != DNS_Class::IN {
        return Err("Wrong class".into());
    }

    dns_answer.add_header(header)?;
    dns_answer.add_question(dns_query)?;
    let mut offset = 0;
    let ttl = 60;
    match dns_query.dns_rr_type {
        DNS_RR_type::A => {
            let mut primary_record = RR_A::new();
            let mut secondary_record = RR_A::new();
            primary_record.set(&Ipv4Addr::new(192, 168, 178, 121));
            secondary_record.set(&Ipv4Addr::new(192, 168, 178, 133));
            offset = add_records_with_log(
                dns_answer,
                dns_query,
                &[&primary_record, &secondary_record],
                0,
                ttl,
            )?;
        }
        DNS_RR_type::MX => {
            let mut primary_record = RR_MX::new();
            primary_record.set(10, "mail_mx.nu.nl");
            let mut sec_record = RR_MX::new();
            sec_record.set(20, "mail_mx2.nu.nl");
            offset = add_records_with_log(
                dns_answer,
                dns_query,
                &[&primary_record, &sec_record],
                0,
                ttl,
            )?;
        }
        DNS_RR_type::NAPTR => {
            let mut primary_record = RR_NAPTR::new();
            primary_record.set(20, 10, "s", "http+N2L+N2C+N2R", "", "www.netmeister.org");
            let mut sec_record = RR_NAPTR::new();
            sec_record.set(
                10,
                20,
                "u",
                "smtp+E2U",
                "!.*([^.]+[^.]+)$!mailto:postmaster@$1!i",
                ".",
            );
            offset = add_records_with_log(
                dns_answer,
                dns_query,
                &[&primary_record, &sec_record],
                0,
                ttl,
            )?;
        }
        DNS_RR_type::MINFO => {
            let mut primary_record = RR_MINFO::new();
            primary_record.set("mail.nu.nl", "foomail.nu.nl");
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::MG => {
            let mut primary_record = RR_MG::new();
            primary_record.set("mail.nu.nl");
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::MF => {
            let mut primary_record = RR_MF::new();
            primary_record.set("mail.nu.nl");
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::MD => {
            let mut primary_record = RR_MD::new();
            primary_record.set("mail.nu.nl");
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::MB => {
            let mut primary_record = RR_MB::new();
            primary_record.set("mail.nu.nl");
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::MAILB => {
            let mut primary_record = RR_MAILB::new();
            primary_record.set(Ipv4Addr::new(192, 168, 178, 121));
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::MAILA => {
            let mut primary_record = RR_MAILA::new();
            primary_record.set(Ipv4Addr::new(192, 168, 178, 121));
            offset = add_records_with_log(dns_answer, dns_query, &[&primary_record], 0, ttl)?;
        }
        DNS_RR_type::NULL => {
            let mut null_record = RR_NULL::new();
            null_record.set(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
            add_records_with_log(dns_answer, dns_query, &[&null_record], 0, ttl)?;
        }
        DNS_RR_type::AAAA => {
            let mut aaaa_record = RR_AAAA::new();
            aaaa_record.set(&Ipv6Addr::new(
                0x2a02, 0xa469, 0x4c52, 0x0001, 0x1ac0, 0x4dff, 0xfeaf, 0x8631,
            ));
            add_records_with_log(dns_answer, dns_query, &[&aaaa_record], 0, ttl)?;
        }
        DNS_RR_type::A6 => {
            let mut a6_record = RR_A6::new();
            a6_record.set(
                64,
                Ipv6Addr::from_str("::e276:63ff:fe72:3900")?,
                "a6-prefix.dns.netmeister.org",
            );
            add_records_with_log(dns_answer, dns_query, &[&a6_record], 0, ttl)?;
        }
        DNS_RR_type::NS => {
            let mut ns_record1 = RR_NS::new();
            let mut ns_record2 = RR_NS::new();
            ns_record1.set("ns.nu.nl");
            ns_record2.set("ns.google.com");
            add_records_with_log(dns_answer, dns_query, &[&ns_record1, &ns_record2], 0, ttl)?;
        }
        DNS_RR_type::CNAME => {
            let mut cname_record = RR_CNAME::new();
            cname_record.set("test.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&cname_record], 0, ttl)?;
        }
        DNS_RR_type::DNAME => {
            let mut dname_record = RR_DNAME::new();
            dname_record.set("testdname.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&dname_record], 0, ttl)?;
        }
        DNS_RR_type::PTR => {
            let mut ptr_record = RR_PTR::new();
            ptr_record.set("test.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&ptr_record], 0, ttl)?;
        }
        DNS_RR_type::WALLET => {
            let mut wallet_record = RR_WALLET::new();
            wallet_record.set("WALLET STRING");
            add_records_with_log(dns_answer, dns_query, &[&wallet_record], 0, ttl)?;
        }
        DNS_RR_type::AVC => {
            let mut avc_record = RR_AVC::new();
            avc_record.set("This is a serious test");
            avc_record.set("And a second string");
            add_records_with_log(dns_answer, dns_query, &[&avc_record], 0, ttl)?;
        }
        DNS_RR_type::TALINK => {
            let mut talink_record = RR_TALINK::new();
            talink_record.set(".", "_talink1.dns.netmeister.org.");
            add_records_with_log(dns_answer, dns_query, &[&talink_record], 0, ttl)?;
        }
        DNS_RR_type::SSHFP => {
            let mut sshfp_record = RR_SSHFP::new();
            sshfp_record.set(
                1,
                3,
                hex::decode("53A76D5284C91E140DEC9AD1A757DA123B95B081").unwrap(),
            );
            add_records_with_log(dns_answer, dns_query, &[&sshfp_record], 0, ttl)?;
        }
        DNS_RR_type::SPF => {
            let mut spf_record = RR_SPF::new();
            spf_record.set("v=spf1 a mx -all");
            add_records_with_log(dns_answer, dns_query, &[&spf_record], 0, ttl)?;
        }
        DNS_RR_type::TXT => {
            let mut txt_record = RR_TXT::new();
            txt_record.set("This is a serious test");
            txt_record.set("And a second string");
            add_records_with_log(dns_answer, dns_query, &[&txt_record], 0, ttl)?;
            let mut txt_record = RR_TXT::new();
            txt_record.set("This is a third test");
            txt_record.set("And a fourth string");
            add_records_with_log(dns_answer, dns_query, &[&txt_record], 0, ttl)?;
        }

        DNS_RR_type::GID => {
            let mut gid_record = RR_GID::new();
            gid_record.set(0x1234567);
            add_records_with_log(dns_answer, dns_query, &[&gid_record], 0, ttl)?;
        }
        DNS_RR_type::UID => {
            let mut uid_record = RR_UID::new();
            uid_record.set(1234567);
            add_records_with_log(dns_answer, dns_query, &[&uid_record], 0, ttl)?;
        }
        DNS_RR_type::CAA => {
            let mut caa_record = RR_CAA::new();
            caa_record.set(0, "issue", "letsencrypt.org");
            add_records_with_log(dns_answer, dns_query, &[&caa_record], 0, ttl)?;
        }
        DNS_RR_type::SOA => {
            let mut soa_record = RR_SOA::new();
            soa_record.set(
                "ns1.nu.nl.",
                "dns-admin.nu.nl.",
                773629602,
                900,
                901,
                1800,
                60,
            );
            add_records_with_log(dns_answer, dns_query, &[&soa_record], 0, ttl)?;
        }
        DNS_RR_type::URI => {
            let mut uri_record = RR_URI::new();
            uri_record.set(1, 2, "https://test.nu.nl/foo.html".as_ref());
            add_records_with_log(dns_answer, dns_query, &[&uri_record], 0, ttl)?;
        }
        DNS_RR_type::X25 => {
            let mut x25_record = RR_X25::new();
            x25_record.set("124356890");
            debug!("FFOO {x25_record}");
            add_records_with_log(dns_answer, dns_query, &[&x25_record], 0, ttl)?;
        }
        DNS_RR_type::WKS => {
            let mut wks_record = RR_WKS::new();
            wks_record.set("10.1.2.4".parse().unwrap(), 6, &[25, 80, 443, 23, 22]);
            let mut wks_record1 = RR_WKS::new();
            wks_record1.set("10.1.2.4".parse().unwrap(), 17, &[53, 5353, 5355]);
            add_records_with_log(dns_answer, dns_query, &[&wks_record, &wks_record1], 0, ttl)?;
        }
        DNS_RR_type::TLSA => {
            let mut tlsa_record = RR_TLSA::new();
            tlsa_record.set(3, 1, 1, &*vec![0x12, 0x34, 0x56, 0x78]);
            add_records_with_log(dns_answer, dns_query, &[&tlsa_record], 0, ttl)?;
        }
        DNS_RR_type::CERT => {
            let mut cert_record = RR_CERT::new();
            cert_record.set(6, 0, 0, b"99CE1DC7770AC5A809A60DCD66CE4FE96F6BD3D7");
            add_records_with_log(dns_answer, dns_query, &[&cert_record], 0, ttl)?;
        }
        DNS_RR_type::CSYNC => {
            let mut csync_record = RR_CSYNC::new();
            csync_record.set(
                2021071001,
                3,
                &[
                    DNS_RR_type::A,
                    DNS_RR_type::AAAA,
                    DNS_RR_type::NS,
                    DNS_RR_type::CNAME,
                ],
            );
            add_records_with_log(dns_answer, dns_query, &[&csync_record], 0, ttl)?;
        }
        DNS_RR_type::DHCID => {
            let mut dhcid_record = RR_DHCID::new();
            dhcid_record.set(
                1,
                1,
                &[
                    57, 32, 254, 93, 29, 206, 179, 253, 11, 163, 55, 151, 86, 167, 13, 115, 177,
                    112, 9, 244, 29, 88, 189, 219, 2,
                ],
            );
            add_records_with_log(dns_answer, dns_query, &[&dhcid_record], 0, ttl)?;
        }
        DNS_RR_type::EUI48 => {
            let mut eui48_record = RR_EUI48::new();
            eui48_record.set(&[100, 200, 44, 23, 45, 33]);
            add_records_with_log(dns_answer, dns_query, &[&eui48_record], 0, ttl)?;
        }
        DNS_RR_type::EUI64 => {
            let mut eui64_record = RR_EUI64::new();
            eui64_record.set(&[100, 200, 34, 22, 44, 23, 45, 33]);
            add_records_with_log(dns_answer, dns_query, &[&eui64_record], 0, ttl)?;
        }
        DNS_RR_type::GPOS => {
            let mut gpos_record = RR_GPOS::new();
            gpos_record.set("40.731", "-73.9919", "10.0");
            add_records_with_log(dns_answer, dns_query, &[&gpos_record], 0, ttl)?;
        }
        DNS_RR_type::HINFO => {
            let mut hinfo_record = RR_HINFO::new();
            hinfo_record.set("PDP-11", "UNIX");
            add_records_with_log(dns_answer, dns_query, &[&hinfo_record], 0, ttl)?;
        }
        DNS_RR_type::HIP => {
            let mut hip_record = RR_HIP::new();
            hip_record.set(
                2,
                &[
                    32, 1, 0, 16, 123, 26, 116, 223, 54, 86, 57, 204, 57, 241, 213, 120,
                ],
                &[
                    3u8, 1u8, 0u8, 1u8, 0u8, 109u8, 113u8, 202u8, 19u8, 110u8, 73u8, 180u8, 172u8,
                    228u8, 67u8, 51u8, 135u8, 59u8, 61u8, 44u8, 20u8, 195u8, 208u8, 14u8, 20u8,
                    127u8, 28u8, 34u8, 243u8, 56u8, 167u8, 247u8, 226u8, 187u8, 87u8, 135u8, 181u8,
                    245u8, 214u8, 201u8, 210u8, 195u8, 79u8, 130u8, 35u8, 172u8, 193u8, 9u8, 4u8,
                    221u8, 181u8, 173u8, 46u8, 196u8, 166u8, 214u8, 35u8, 47u8, 59u8, 80u8, 235u8,
                    9u8, 60u8, 41u8, 20u8, 179u8, 185u8, 65u8, 187u8, 229u8, 41u8, 175u8, 88u8,
                    44u8, 54u8, 187u8, 173u8, 222u8, 253u8, 178u8, 173u8, 175u8, 155u8, 73u8, 17u8,
                    144u8, 175u8, 91u8, 37u8, 34u8, 96u8, 60u8, 97u8, 82u8, 114u8, 184u8, 128u8,
                    242u8, 63u8, 114u8, 48u8, 204u8, 110u8, 227u8, 17u8, 19u8, 106u8, 117u8, 177u8,
                    99u8, 143u8, 1u8, 105u8, 44u8, 146u8, 103u8, 71u8, 105u8, 84u8, 211u8, 248u8,
                    5u8, 199u8, 165u8, 180u8, 200u8, 221u8, 188u8, 93u8, 117u8, 223u8,
                ],
                "rvs.example.com.",
            );
            add_records_with_log(dns_answer, dns_query, &[&hip_record], 0, ttl)?;
        }
        DNS_RR_type::LP => {
            let mut lp_record1 = RR_LP::new();
            lp_record1.set(10, "l64.nu.nl");
            let mut lp_record2 = RR_LP::new();
            lp_record2.set(20, "l32.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&lp_record1, &lp_record2], 0, ttl)?;
        }
        DNS_RR_type::LOC => {
            let mut loc_record = RR_LOC::new();
            loc_record.set("34 03 00.000 N 118 14 00.000 W -10.00m 20.00m 5.00m 10.00m");
            add_records_with_log(dns_answer, dns_query, &[&loc_record], 0, ttl)?;
        }
        DNS_RR_type::L64 => {
            let mut l64_record = RR_L64::new();
            l64_record.set(
                10,
                "2001:db8:1140:1000::"
                    .parse()
                    .unwrap_or(Ipv6Addr::UNSPECIFIED),
            );
            add_records_with_log(dns_answer, dns_query, &[&l64_record], 0, ttl)?;
        }
        DNS_RR_type::L32 => {
            let mut l32_record = RR_L32::new();
            l32_record.set(10, "203.0.113.44".parse().unwrap_or(Ipv4Addr::UNSPECIFIED));
            add_records_with_log(dns_answer, dns_query, &[&l32_record], 0, ttl)?;
        }
        DNS_RR_type::SINK => {
            let mut sink_record = RR_SINK::new();
            let val = STANDARD
                .decode("ZG5zLm5ldG1laXN0ZXIub3JnLg==")
                .unwrap_or_default();
            debug!("FOO {val:?}");
            sink_record.set(64, 1, &val);
            add_records_with_log(dns_answer, dns_query, &[&sink_record], 0, ttl)?;
        }
        DNS_RR_type::RT => {
            let mut rt_record = RR_RT::new();
            rt_record.set(10, "rttost.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&rt_record], 0, ttl)?;
        }
        DNS_RR_type::KX => {
            let mut kx_record = RR_KX::new();
            kx_record.set(10, "kxtost.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&kx_record], 0, ttl)?;
        }
        DNS_RR_type::ISDN => {
            let mut isdn_record = RR_ISDN::new();
            isdn_record.set("150862028003217", "004");
            add_records_with_log(dns_answer, dns_query, &[&isdn_record], 0, ttl)?;
        }
        DNS_RR_type::IPSECKEY => {
            let mut ipseckey_record = RR_IPSECKEY::new();
            ipseckey_record.set(
                10,
                0,
                2,
                ".",
                &[
                    1u8, 3u8, 81u8, 83u8, 121u8, 102u8, 11u8, 237u8, 49u8, 81u8, 55u8, 3u8, 237u8,
                    230u8, 246u8, 219u8, 137u8, 241u8, 19u8, 216u8, 232u8, 117u8, 191u8, 114u8,
                    114u8, 233u8, 111u8, 17u8, 104u8, 2u8, 79u8, 78u8, 14u8, 218u8, 111u8, 114u8,
                    222u8, 176u8, 115u8, 1u8, 100u8, 233u8, 169u8, 110u8, 163u8, 13u8, 203u8,
                    150u8, 158u8, 127u8, 2u8, 1u8,
                ],
            );
            add_records_with_log(dns_answer, dns_query, &[&ipseckey_record], 0, ttl)?;
        }
        DNS_RR_type::KEY => {
            let mut key_record = RR_KEY::new();
            key_record.set(512, 255, 2, &STANDARD.decode("ACDtkdVR2HWmc0HPEwkrM+SOrWZd8yPTAytLYZj2u33KgwABAgAg6jav9rTK68C8j+kfLv7+re8KAb1qJXqdSrmL+1l3Js4=").unwrap_or_default());
            add_records_with_log(dns_answer, dns_query, &[&key_record], 0, ttl)?;
        }
        DNS_RR_type::IPN => {
            let mut ipn_record = RR_IPN::new();
            ipn_record.set(0xdeadbeefcafebabeu64);
            add_records_with_log(dns_answer, dns_query, &[&ipn_record], 0, ttl)?;
        }
        DNS_RR_type::RESINFO => {
            let mut res_info_record = RR_RESINFO::new();
            res_info_record.set("qnamemin");
            res_info_record.set("exterr-16.15.17");
            res_info_record.set("resinfourl=https://resolver.example.com/guide");
            add_records_with_log(dns_answer, dns_query, &[&res_info_record], 0, ttl)?;
        }
        DNS_RR_type::RRSIG => {
            let mut px_record = RR_RP::new();
            px_record.set("jschauma.netmeister.org.", "contact.netmeister.org.");
            add_records_with_log(dns_answer, dns_query, &[&px_record], 0, ttl)?;
        }
        DNS_RR_type::RP => {
            let mut px_record = RR_RP::new();
            px_record.set("jschauma.netmeister.org.", "contact.netmeister.org.");
            add_records_with_log(dns_answer, dns_query, &[&px_record], 0, ttl)?;
        }
        DNS_RR_type::PX => {
            let mut px_record = RR_PX::new();
            px_record.set(10, "ab.net2.it.", "O-ab.PRMD-net2.ADMDb.C-it.");
            add_records_with_log(dns_answer, dns_query, &[&px_record], 0, ttl)?;
        }
        DNS_RR_type::NXT => {
            let mut nxt_record = RR_NXT::new();
            nxt_record.set(
                "foo".into(),
                vec![DNS_RR_type::TXT, DNS_RR_type::OPENPGPKEY, DNS_RR_type::CAA],
            );
            add_records_with_log(dns_answer, dns_query, &[&nxt_record], 0, ttl)?;
        }
        DNS_RR_type::OPENPGPKEY => {
            let mut openpgpkey_record = RR_OPENPGPKEY::new();
            openpgpkey_record.set(&[
                0x99, 0x01, 0x0D, 0x04, 0x5C, 0x4D, 0x44, 0x0B, 0x02, 0x03, 0x04, 0x00, 0x02, 0x00,
                0x01, 0x08, 0x00, 0x0B, 0x03, 0xF6, 0x41, 0x45, 0x44, 0x44, 0x02, 0x03, 0x04, 0x00,
                0x07, 0xFE, 0x03, 0x01, 0x02, 0x9B, 0x21, 0x07, 0x02, 0x15, 0x05, 0x09, 0x08, 0x07,
                0x02, 0x03, 0x04, 0x00,
            ]);
            add_records_with_log(dns_answer, dns_query, &[&openpgpkey_record], 0, ttl)?;
        }
        DNS_RR_type::NSEC3PARAM => {
            let mut nsec3param_record = RR_NSEC3PARAM::new();
            nsec3param_record.set(1, 0, 15, &[0xCB, 0x49, 0x10, 0x54, 0x66, 0xD3, 0x6A, 0x0D]);
            add_records_with_log(dns_answer, dns_query, &[&nsec3param_record], 0, ttl)?;
        }
        DNS_RR_type::NSEC3 => {
            let mut nsec3_record = RR_NSEC3::new();
            nsec3_record.set(
                1,
                0,
                0,
                b"",
                b"058AJ9V7U8T8TGT5F9UPL1D5BRDP8JKO",
                vec![DNS_RR_type::A, DNS_RR_type::A6, DNS_RR_type::CAA],
            );
            add_records_with_log(dns_answer, dns_query, &[&nsec3_record], 0, ttl)?;
        }
        DNS_RR_type::NSEC => {
            let mut nsec_record = RR_NSEC::new();
            nsec_record.set(
                "new.test.nu.nl".into(),
                vec![
                    DNS_RR_type::A,
                    DNS_RR_type::AAAA,
                    DNS_RR_type::NS,
                    DNS_RR_type::CNAME,
                    DNS_RR_type::TXT,
                    DNS_RR_type::CAA,
                ],
            );
            add_records_with_log(dns_answer, dns_query, &[&nsec_record], 0, ttl)?;
        }
        DNS_RR_type::NSAP_PTR => {
            let mut nsap_ptr_record = RR_NSAP_PTR::new();
            nsap_ptr_record.set("test_nsap_ptr.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&nsap_ptr_record], 0, ttl)?;
        }
        DNS_RR_type::EID => {
            let mut eid_record = RR_EID::new();
            let nsap_bytes = hex::decode("CAFEFACE1234").unwrap_or_default();
            eid_record.set(&nsap_bytes);
            add_records_with_log(dns_answer, dns_query, &[&eid_record], 0, ttl)?;
        }
        DNS_RR_type::NSAP => {
            let mut nsap_record = RR_NSAP::new();
            let nsap_bytes =
                hex::decode("39840f80005a0000000001e13708002010726e00").unwrap_or_default();
            nsap_record.set(&nsap_bytes);
            add_records_with_log(dns_answer, dns_query, &[&nsap_record], 0, ttl)?;
        }
        DNS_RR_type::DOA => {
            let mut doa_record = RR_DOA::new();
            doa_record.set(0, 1, 2, "test", &[100, 200, 44, 23, 44]);
            add_records_with_log(dns_answer, dns_query, &[&doa_record], 0, ttl)?;
        }
        DNS_RR_type::NINFO => {
            let mut ninifo_record = RR_NINFO::new();
            ninifo_record.set("testing 123");
            ninifo_record.set("testing 345");
            add_records_with_log(dns_answer, dns_query, &[&ninifo_record], 0, ttl)?;
        }
        DNS_RR_type::NID => {
            let mut nid_record = RR_NID::new();
            nid_record.set(0, 0x00144fffff20ee64);
            add_records_with_log(dns_answer, dns_query, &[&nid_record], 0, ttl)?;
        }
        DNS_RR_type::CLA => {
            let mut cla_record = RR_CLA::new();
            cla_record.set("TCP-V4-V6");
            add_records_with_log(dns_answer, dns_query, &[&cla_record], 0, ttl)?;
        }
        DNS_RR_type::CDS => {
            let mut cds_record = RR_CDS::new();
            cds_record.set(
                56039,
                13,
                2,
                "4104805B43928FC573F0704A2C1B5A10BAA2878DE26B8535DDE77517C154CE9F".into(),
            );
            add_records_with_log(dns_answer, dns_query, &[&cds_record], 0, ttl)?;
        }
        DNS_RR_type::CDNSKEY => {
            let mut cdnskey_record = RR_CDNSKEY::new();
            cdnskey_record.set(257, 3, 13, "JErBf5lZ1osSWg7r51+4VfEiWIdONph0L70X0ToT7DkbikKQIp+qvuOOZri7j3qVComv7tgTIBhKxeDQercdKQ==".into());
            add_records_with_log(dns_answer, dns_query, &[&cdnskey_record], 0, ttl)?;
        }
        DNS_RR_type::SRV => {
            let mut srv_record = RR_SRV::new();
            srv_record.set(10, 1, 443, "test.nu.nl");
            add_records_with_log(dns_answer, dns_query, &[&srv_record], 0, ttl)?;
        }
        DNS_RR_type::HTTPS => {
            let mut https_record = RR_HTTPS::new();
            let https_param: HttpsSvcParam =
                HttpsSvcParam::Alpn(vec!["h1".to_string(), "h2".to_string()]);
            let https_param1: HttpsSvcParam = HttpsSvcParam::Ipv4Hint(vec![
                "1.2.3.4".parse().unwrap(),
                "12.23.34.45".parse().unwrap(),
            ]);
            let https_param2: HttpsSvcParam = HttpsSvcParam::Ipv6Hint(vec![
                "2606: 4700::6810: 1f60".parse().unwrap(),
                "2606: 4700: 3030::6815: 1001".parse().unwrap(),
            ]);
            https_record.set(".", 10, &[https_param, https_param1, https_param2]);

            add_records_with_log(dns_answer, dns_query, &[&https_record], 0, ttl)?;
        }
        _ => dns_answer.set_rcode(DnsReplyType::NOERROR),
    }

    Ok(())
}

fn add_records_with_log(
    dns_answer: &mut dns_answer,
    question: &dns_question,
    records: &[&impl DNSRecord],
    offset_in: usize,
    ttl: u32,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut offset = offset_in;
    for record in records {
        dns_answer.header.ancount += 1;
        offset = record.add_to_answer(dns_answer, question, ttl)?;
        println!("writing {} record", record.get_type());
    }
    Ok(offset)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let layers = vec![fmt::Layer::default().boxed()];
    let filter = filter::LevelFilter::DEBUG;
    let (filter, reload_handle) = reload::Layer::new(filter);
    let (tracing_layers, reload_handle1) = reload::Layer::new(layers);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_layers)
        .init();
    // Bind to local address and port
    let host = "127.0.0.1";
    let port = "5355";
    let addr = &format!("{host}:{port}");
    debug!("UDP server listening on {addr}");
    let socket = UdpSocket::bind(addr.as_str())?;
    let mut buf = [0u8; 2048];
    debug!("started socket");

    let mut dns_answer = dns_answer::new();
    let skip_list = Skip_List::new();
    loop {
        // Receive a datagram
        let (amt, src) = socket.recv_from(&mut buf)?;

        debug!("Received {amt} bytes from {src}");
        debug!("{}", hex::encode(&buf[..amt]));

        let mut dns_header = dns_header::new();
        let mut offset = dns_header
            .parse(buf.as_ref())
            .expect("Error parsing DNS header");
        debug!("{dns_header:?}");
        let mut dns_question = dns_question::new();
        offset += dns_question
            .parse(buf.as_ref(), offset, &skip_list)
            .expect("Error parsing DNS question");
        debug!("{dns_question:?}");
        buf.fill(0);
        make_reply(&mut dns_answer, &dns_question, &mut dns_header)?;
        socket.send_to(dns_answer.get_reply(), src)?;
        debug!("{dns_answer}");
    }
}
