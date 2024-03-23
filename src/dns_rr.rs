use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use base64::engine::general_purpose;
use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
use strum::AsStaticRef;

use crate::dns::{cert_type_str, dnssec_algorithm, dnssec_digest, key_algorithm, key_protocol, sshfp_algorithm, sshfp_fp_type, tlsa_algorithm, tlsa_cert_usage, tlsa_selector, zonemd_digest, DNS_RR_type, SVC_Param_Keys};
use crate::dns_helper::{base32hex_encode, dns_read_u16, dns_read_u32, dns_read_u8, parse_protocol, parse_rrtype, timestame_to_str};


pub fn dns_parse_name(
    packet: &[u8],
    offset: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let (mut name, offset_out) = dns_parse_name_internal(packet, offset)?;
    if name.len() == 0 {
        name = String::from(".");
    } else  {
        name = name.trim_end_matches('.').to_string();
    }
    return Ok((name, offset_out));
}

fn dns_parse_name_internal(
    packet: &[u8],
    offset_in: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let mut idx = offset_in;
    let mut name = String::new();
    //    println!("{} {:x?}", offset_in, &packet[offset_in.. offset_in+20]);
    while packet[idx] != 0 {
        let Some(val) = packet.get(idx) else {
            return Err("Invalid index".into());
        };
        if *val > 63 {
            let pos = (dns_read_u16(packet, idx)? & 0x3fff) as usize;
            let (name1, _len) = dns_parse_name(&packet, pos)?;
            return Ok((name + &name1, idx + 2));
        } else {
            let label_len: usize = *packet.get(idx).unwrap() as usize;
            idx += 1;
            let Some(label) = packet.get(idx..(idx + (label_len))) else {
                return Err("Invalid index !!".into());
            };
            name.push_str(std::str::from_utf8(&label)?);
            name.push('.');
            idx += label_len;
        }
    }
    return Ok((name, idx + 1));
}

fn parse_dns_https(rdata: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let svc_prio = dns_read_u16(rdata, 0)?;
    let (target, mut offset) = dns_parse_name(rdata, 2)?;
    let mut res = String::new();
    res += &format!("{} {} ", svc_prio, target);
    while offset < rdata.len() {
        let svc_param_key = SVC_Param_Keys::find(dns_read_u16(rdata, offset)?)?;
        let svc_param_len = dns_read_u16(rdata, offset + 2)? as usize;
        match svc_param_key {
            SVC_Param_Keys::mandatory => {
                let mut pos: usize = 0;
                res += "mandatory=";
                while pos < svc_param_len {
                    let man_val = dns_read_u16(rdata, offset + pos + 4)?;
                    res += &format!("{},", SVC_Param_Keys::find(man_val)?.as_static());
                    pos += 2;
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::alpn => {
                let mut pos: usize = 0;
                res += "alpn=";
                while pos < svc_param_len {
                    let alpn_len = rdata[offset + pos + 4] as usize;
                    let alpn = String::from_utf8_lossy(
                        &rdata[offset + pos + 4 + 1..offset + pos + 4 + 1 + alpn_len],
                    );
                    pos += 1 + alpn_len;
                    res += &format!("{},", alpn);
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::ech => {
                res += "ech=";
                let data = general_purpose::STANDARD
                    .encode(&rdata[offset + 4..offset + 4 + svc_param_len]);
                res += &data;
                res += " ";
            }
            SVC_Param_Keys::ipv4hint => {
                res += "ipv4hint=";
                let mut pos: usize = 0;
                while pos + 4 <= svc_param_len {
                    let loc = offset + 4 + pos;
                    res += &format!(
                        "{}.{}.{}.{},",
                        rdata[loc],
                        rdata[loc + 1],
                        rdata[loc + 2],
                        rdata[loc + 3]
                    );
                    pos += 4;
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::ipv6hint => {
                res += "ipv6hint=";
                let mut pos: usize = 0;
                while pos + 16 <= svc_param_len {
                    let r: [u8; 16] = rdata[offset + 4 + pos..offset + 4 + pos + 16].try_into()?;
                    let addr = Ipv6Addr::from(r);
                    res += &format!("{},", addr);
                    pos += 16;
                }
                res = String::from_str(res.trim_end_matches(','))?;
                res += " ";
            }
            SVC_Param_Keys::no_default_alpn => {
                res += "no-default-alpn";
            }
            SVC_Param_Keys::port => {
                let port = dns_read_u16(rdata, offset + 4)?;
                res += &format!("port={}", port);
            }
        }
        offset += 4 + svc_param_len as usize;
    }
    return Ok(res);
}

fn decode_gpos_size(val: u8) -> String {
    let mut base = ((val & 0xf0) >> 4) as u64;
    let exp = (val & 0x0f) as u64;
    if exp < 2 {
        if exp == 1 {
            base *= 10;
        }
        return format!("0.{}", base);
    }
    return format!("{}{}", base, "0".repeat(exp as usize - 2));
}

pub fn dns_parse_rdata(
    rdata: &[u8],
    rrtype: DNS_RR_type,
    packet: &[u8],
    offset_in: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut outdata = String::new();
    if rrtype == DNS_RR_type::A {
        if rdata.len() != 4 {
            return Err("Invalid record".into());
        }
        outdata.push_str(&format!(
            "{}.{}.{}.{}",
            rdata[0], rdata[1], rdata[2], rdata[3]
        ));
        return Ok(outdata);
    } else if rrtype == DNS_RR_type::AAAA {
        if rdata.len() != 16 {
            return Err("Invalid record".into());
        }
        let r: [u8; 16] = rdata.try_into()?;
        let addr = Ipv6Addr::from(r);
        return Ok(addr.to_string());
    } else if rrtype == DNS_RR_type::CNAME || rrtype == DNS_RR_type::DNAME {
        let (s, _offset) = dns_parse_name(packet, offset_in)?;
        return Ok(s);
    } else if rrtype == DNS_RR_type::CAA {
        let flag = rdata[0];
        let tag_len = rdata[1];
        let Some(r) = rdata.get(2..2 + tag_len as usize) else {
            return Err("Index error".into());
        };
        let tag = std::str::from_utf8(r)?;
        let Some(r) = rdata.get(2 + tag_len as usize..) else {
            return Err("Index error".into());
        };
        let value = std::str::from_utf8(r)?;
        return Ok(format!("{} {} ({})", tag, value, flag));
    } else if rrtype == DNS_RR_type::SOA {
        let mut offset: usize = offset_in;
        let ns: String;
        let mb: String;
        (ns, offset) = dns_parse_name(packet, offset)?;
        (mb, offset) = dns_parse_name(packet, offset)?;
        let sn = dns_read_u32(packet, offset)?;
        let refr = dns_read_u32(packet, offset + 4)?;
        let ret = dns_read_u32(packet, offset + 8)?;
        let exp = dns_read_u32(packet, offset + 16)?;
        let ttl = dns_read_u32(packet, offset + 16)?;
        return Ok(format!(
            "{} {} {} {} {} {} {}",
            ns, mb, sn, refr, ret, exp, ttl
        ));
    } else if rrtype == DNS_RR_type::NS {
        let (ns, _offset_out) = dns_parse_name(packet, offset_in)?;
        return Ok(ns);
    } else if rrtype == DNS_RR_type::TXT
        || rrtype == DNS_RR_type::NINF0
        || rrtype == DNS_RR_type::AVC
        || rrtype == DNS_RR_type::SPF
    {
        let mut pos = 0;
        let mut res = String::new();
        while pos < rdata.len() {
            let tlen: usize = rdata[pos].into();
            let Some(r) = rdata.get(1 + pos..pos + tlen + 1) else {
                return Err("Index error".into());
            };
            res += &format!("{} ", std::str::from_utf8(r)?);
            pos += 1 + tlen;
        }
        return Ok(String::from(res));
    } else if rrtype == DNS_RR_type::PTR {
        let (ptr, _offset_out) = dns_parse_name(packet, offset_in)?;
        return Ok(ptr);
    } else if rrtype == DNS_RR_type::MX || rrtype == DNS_RR_type::RT {
        let _pref = BigEndian::read_u16(&rdata[0..2]);
        let (mx, _offset_out) = dns_parse_name(packet, offset_in + 2)?;
        return Ok(mx);
    } else if rrtype == DNS_RR_type::HINFO {
        let cpu_len1 = dns_read_u8(rdata, 0)?;
        let cpu_len: usize = cpu_len1 as usize;
        let mut offset: usize = 1;
        let Some(r) = rdata.get(offset..offset + cpu_len as usize) else {
            return Err("Index error".into());
        };
        let mut s = String::from(std::str::from_utf8(r)?);
        offset += cpu_len as usize;
        let os_len = rdata[offset] as usize;
        offset += 1;
        s.push(' ');
        let Some(r) = rdata.get(offset..offset + os_len) else {
            return Err("Index error".into());
        };
        s += &String::from(std::str::from_utf8(r)?);
        return Ok(s);
    } else if rrtype == DNS_RR_type::SRV {
        let prio = dns_read_u16(rdata, 0)?;
        let weight = dns_read_u16(rdata, 2)?;
        let port = dns_read_u16(rdata, 4)?;
        let (target, _offset_out) = dns_parse_name(rdata, 6)?;
        return Ok(format!("{} {} {} {}", prio, weight, port, target));
    } else if rrtype == DNS_RR_type::TLSA || rrtype == DNS_RR_type::SMIMEA {
        if rdata.len() < 4 {
            return Err("Rdata too small".into());
        }
        let cert_usage = tlsa_cert_usage(rdata[0])?;
        let selector = tlsa_selector(rdata[1])?;
        let alg_type = tlsa_algorithm(rdata[2])?;
        let cad = &rdata[3..];
        return Ok(format!(
            "{} {} {} {}",
            cert_usage,
            selector,
            alg_type,
            hex::encode(cad)
        ));
    } else if rrtype == DNS_RR_type::AFSDB {
        let subtype = dns_read_u16(rdata, 0)?;
        let (hostname, _offset_out) = dns_parse_name(rdata, 2)?;
        return Ok(format!("{} {}", subtype, hostname));
    } else if rrtype == DNS_RR_type::CDS || rrtype == DNS_RR_type::DS || rrtype == DNS_RR_type::TA {
        if rdata.len() < 5 {
            return Err("Index error".into());
        }
        let keyid = dns_read_u16(rdata, 0)?;
        let alg = dnssec_algorithm(rdata[2])?;
        let dig_t = dnssec_digest(rdata[3])?;
        let dig = &rdata[4..];
        return Ok(format!("{} {} {} {}", keyid, alg, dig_t, hex::encode(dig)));
    } else if rrtype == DNS_RR_type::DNSKEY || rrtype == DNS_RR_type::CDNSKEY {
        if rdata.len() < 5 {
            return Err("Index error".into());
        }
        let flag = dns_read_u16(rdata, 0)?;
        let protocol = dnssec_algorithm(rdata[2])?;
        let alg = dnssec_algorithm(rdata[3])?;
        let pubkey = &rdata[4..];
        return Ok(format!(
            "{} {} {} {}",
            flag,
            protocol,
            alg,
            hex::encode(pubkey)
        ));
    } else if rrtype == DNS_RR_type::LOC {
        let version = dns_read_u8(rdata, 0)?;
        if version != 0 {
            return Err("Unknown GPOS version".into());
        }
        let size = dns_read_u8(rdata, 1)?;
        let hor_prec = dns_read_u8(rdata, 2)?;
        let ver_prec = dns_read_u8(rdata, 3)?;
        let mut lat = dns_read_u32(rdata, 4)? as i64;
        let mut lon = dns_read_u32(rdata, 8)? as i64;
        let alt = dns_read_u32(rdata, 12)? as i64;
        let north: char;
        let east: char;
        let equator: i64 = 1 << 31;
        if lat > equator {
            north = 'N';
            lat -= equator;
        } else {
            north = 'S';
            lat = equator - lon;
        }
        if lon > equator {
            east = 'E';
            lon -= equator;
        } else {
            east = 'W';
            lon = equator - lon;
        }
        let ho = lon / (1000 * 60 * 60);
        lon %= 1000 * 60 * 60;
        let mo = lon / (1000 * 60);
        lon %= 1000 * 60;
        let so = lon as f64 / 1000.0;
        let ha = lat / (1000 * 60 * 60);
        lat %= 1000 * 60 * 60;
        let ma = lat / (1000 * 60);
        lat %= 1000 * 60;
        let sa = lat as f64 / 1000.0;

        let a = (alt as f64 / 100.0) - 100000.0;

        return Ok(format!(
            "{} {} {} {} {} {} {} {} {}m {}m {}m {}m ",
            ha,
            ma,
            sa,
            north,
            ho,
            mo,
            so,
            east,
            a,
            decode_gpos_size(size),
            decode_gpos_size(hor_prec),
            decode_gpos_size(ver_prec)
        ));
    } else if rrtype == DNS_RR_type::NAPTR {
        let order = dns_read_u16(rdata, 0)?;
        let pref = dns_read_u16(rdata, 2)?;
        let flag_len = dns_read_u8(rdata, 4)?;
        let mut offset: usize = 5;
        let flags = std::str::from_utf8(&rdata[offset..offset + flag_len as usize])?;
        offset += flag_len as usize;
        let srv_len = rdata[offset as usize];
        offset += 1;
        let srv = std::str::from_utf8(&rdata[offset..offset + srv_len as usize])?;
        offset += srv_len as usize;
        let re_len = dns_read_u8(rdata, offset)?;
        offset += 1;
        let mut re = "";
        if re_len > 0 {
            re = std::str::from_utf8(&rdata[offset..offset + re_len as usize])?;
        }
        offset += re_len as usize;
        let (repl, _) = dns_parse_name(rdata, offset)?;
        return Ok(format!(
            "{} {} {} {} {} {}",
            order, pref, flags, srv, re, repl
        ));
    } else if rrtype == DNS_RR_type::RRSIG {
        let sig_rrtype = parse_rrtype(dns_read_u16(rdata, 0)?)?;
        let sig_rrtype_str = sig_rrtype.to_str()?;
        let alg = dnssec_algorithm(dns_read_u8(rdata, 2)?)?;
        let labels = dns_read_u8(rdata, 3)?;
        let ttl = dns_read_u32(rdata, 4)?;
        let sig_exp = timestame_to_str(dns_read_u32(rdata, 8)?)?;
        let sig_inc = timestame_to_str(dns_read_u32(rdata, 12)?)?;
        let key_tag = dns_read_u16(rdata, 16)?;
        let (signer, offset_out) = dns_parse_name(rdata, 18)?;
        let signature = &rdata[offset_out..];
        return Ok(format!(
            "{} {} {} {} {} {} {} {} {}",
            sig_rrtype_str,
            alg,
            labels,
            ttl,
            sig_exp,
            sig_inc,
            key_tag,
            signer,
            hex::encode(&signature)
        ));
    } else if rrtype == DNS_RR_type::SSHFP {
        if rdata.len() < 3 {
            return Err("Invalid packet".into());
        }
        let alg = sshfp_algorithm(rdata[0])?;
        let fp_type = sshfp_fp_type(rdata[1])?;
        let fingerprint = &rdata[2..];
        return Ok(format!("{} {} {}", alg, fp_type, hex::encode(&fingerprint)));
    } else if rrtype == DNS_RR_type::OPENPGPKEY {
        let pubkey = general_purpose::STANDARD_NO_PAD.encode(&rdata);
        return Ok(pubkey);
    } else if rrtype == DNS_RR_type::RP {
        let (mailbox, offset) = dns_parse_name(rdata, 0)?;
        let (txt, _) = dns_parse_name(rdata, offset)?;
        return Ok(format!("{} {}", mailbox, txt));
    } else if rrtype == DNS_RR_type::MB {
        let (mb, _offset) = dns_parse_name(packet, offset_in)?;
        return Ok(mb);
    } else if rrtype == DNS_RR_type::A6 {
        let prefix_len = rdata[0];
        let len: usize = (128 - prefix_len as usize) / 8;
        let mut r: [u8; 16] = [0; 16];
        for i in 0..len {
            r[15 - i] = rdata[len - i]
        }
        let addr_suffix = Ipv6Addr::from(r);
        let mut prefix_name = String::new();
        if prefix_len != 0 {
            (prefix_name, _) = dns_parse_name(packet, offset_in + 1 + len)?;
        }
        return Ok(format!("{} {} {}", prefix_len, addr_suffix, prefix_name));
    } else if rrtype == DNS_RR_type::AMTRELAY {
        let precedence = rdata[0];
        let mut rtype = rdata[1];
        let dbit = rtype >> 7;
        rtype = rtype & 0x7f;
        let mut relay: String = String::new();
        if rtype == 3 {
            (relay, _) = dns_parse_name(packet, offset_in + 2)?;
        } else if rtype == 2 {
            let r: [u8; 16] = rdata[2..18].try_into()?;
            let addr = Ipv6Addr::from(r);
            relay = format!("{}", addr);
        } else if rtype == 1 {
            let r: [u8; 4] = rdata[2..6].try_into()?;
            let addr = Ipv4Addr::from(r);
            relay = format!("{}", addr);
        }
        return Ok(format!("{} {} {} {}", precedence, dbit, rtype, relay));
    } else if rrtype == DNS_RR_type::X25 {
        let len: usize = rdata[0] as usize;
        if len + 1 != rdata.len() {
            return Err("Ivalid X25 format".into());
        }
        let Some(addr) = rdata.get(1..1 + len) else {
            return Err("Parse Error".into());
        };
        let addr1 = std::str::from_utf8(addr)?;
        return Ok(String::from_str(addr1)?);
    } else if rrtype == DNS_RR_type::NSEC3PARAM {
        let hash = rdata[0];
        let flags = rdata[1];
        let iterations = dns_read_u16(rdata, 2)?;
        let salt_len = rdata[4] as usize;
        if salt_len + 5 > rdata.len() {
            return Err("Invalid NSEC3PARAM format".into());
        }
        let Some(salt) = rdata.get(5..5 + salt_len) else {
            return Err("Parse Error".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            hash,
            flags,
            iterations,
            hex::encode(salt)
        ));
    } else if rrtype == DNS_RR_type::GPOS {
        let mut idx = 0;
        let lon_len = rdata[idx] as usize;
        idx += 1;
        let Some(lon) = rdata.get(idx..idx + lon_len) else {
            return Err("Parse Error".into());
        };
        idx += lon_len;
        let lat_len = rdata[idx] as usize;
        idx += 1;
        let Some(lat) = rdata.get(idx..idx + lat_len) else {
            return Err("Parse Error".into());
        };
        idx += lat_len;
        let alt_len = rdata[idx] as usize;
        idx += 1;
        let Some(alt) = rdata.get(idx..idx + alt_len) else {
            return Err("Parse Error".into());
        };
        return Ok(format!(
            "{} {} {}",
            std::str::from_utf8(lon)?,
            std::str::from_utf8(lat)?,
            std::str::from_utf8(alt)?
        ));
    } else if rrtype == DNS_RR_type::EUI48 {
        if rdata.len() != 6 {
            return Err("Parse Error".into());
        }
        return Ok(format!(
            "{:x}-{:x}-{:x}-{:x}-{:x}-{:x}",
            rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5]
        ));
    } else if rrtype == DNS_RR_type::EUI64 {
        if rdata.len() != 8 {
            return Err("Parse Error".into());
        }
        return Ok(format!(
            "{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}",
            rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5], rdata[6], rdata[7]
        ));
    } else if rrtype == DNS_RR_type::CERT {
        let cert_type = dns_read_u16(rdata, 0)?;
        let key_tag = dns_read_u16(rdata, 2)?;
        let alg = dns_read_u8(rdata, 4)?;
        let Some(cert) = rdata.get(5..) else {
            return Err("Packet too small".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            cert_type_str(cert_type)?,
            (key_tag),
            dnssec_algorithm(alg)?,
            hex::encode(cert)
        ));
    } else if rrtype == DNS_RR_type::HTTPS || rrtype == DNS_RR_type::SVCB {
        return parse_dns_https(rdata);
    } else if rrtype == DNS_RR_type::WKS {
        let protocol = dns_read_u8(rdata, 4)?;
        let Some(bitmap) = rdata.get(5..) else {
            return Err("Parse error".into());
        };

        return Ok(format!(
            "{}.{}.{}.{} {} {}",
            rdata[0],
            rdata[1],
            rdata[2],
            rdata[3],
            parse_protocol(protocol)?,
            parse_bitmap_str(bitmap)?
        ));
    } else if rrtype == DNS_RR_type::TSIG {
        // todo
    } else if rrtype == DNS_RR_type::APL {
        let mut pos = 0;
        let mut res = String::new();
        while pos < rdata.len() {
            let af = dns_read_u16(rdata, pos)?;
            let pref_len = dns_read_u8(rdata, pos + 2)?;
            let addr_len_ = dns_read_u8(rdata, pos + 3)?;
            let flags = addr_len_ >> 7;
            let mut neg_str = "";
            if flags > 0 {
                neg_str = "!";
            }
            let addr_len = (addr_len_ & 0x7f) as usize;
            let Some(addr) = rdata.get(pos + 4..pos + 4 + addr_len) else {
                return Err("Parse error".into());
            };
            //println!("{:?} {}", addr, addr_len);
            let mut ip_addr = std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            if af == 1 {
                // ipv4
                let mut ip: [u8; 4] = [0; 4];
                for i in 0..addr_len {
                    ip[i] = addr[i];
                }
                ip_addr = std::net::IpAddr::V4(Ipv4Addr::from(ip));
            }
            if af == 2 {
                // Ipv6
                let mut ip: [u8; 16] = [0; 16];
                for i in 0..addr_len {
                    ip[i] = addr[i];
                }
                ip_addr = std::net::IpAddr::V6(Ipv6Addr::from(ip));
            }
            res += &format!("{}{}/{} ", neg_str, ip_addr, pref_len);
            pos += 4 + addr_len;
        }
        return Ok(res);
    } else if rrtype == DNS_RR_type::ATMA {
        let format = rdata[0];
        let address = &rdata[1..];
        return Ok(format!("{} {}", format, hex::encode(address)));
    } else if rrtype == DNS_RR_type::DLV {
        let Some(key_id) = rdata.get(0..2) else {
            return Err("Packet too small".into());
        };

        let alg = dns_read_u8(rdata, 2)?;
        let digest_type = dns_read_u8(rdata, 3)?;
        let Some(digest) = rdata.get(4..) else {
            return Err("Packet too small".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            hex::encode(key_id),
            dnssec_algorithm(alg)?,
            dnssec_digest(digest_type)?,
            hex::encode(digest)
        ));
    } else if rrtype == DNS_RR_type::TALINK {
        let (name1, offset_out) = dns_parse_name(packet, offset_in)?;
        let (name2, _) = dns_parse_name(packet, offset_out)?;
        return Ok(format!("{} {}", name1, name2));
    } else if rrtype == DNS_RR_type::DHCID {
        return Ok(format!("{}", hex::encode(rdata)));
    } else if rrtype == DNS_RR_type::ZONEMD {
        let serial = dns_read_u32(rdata, 0)?;
        let scheme = dns_read_u8(rdata, 4)?;
        let alg = dns_read_u8(rdata, 5)?;
        let Some(digest) = rdata.get(6..) else {
            return Err("Packet too small".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            serial,
            scheme,
            zonemd_digest(alg)?,
            hex::encode(digest)
        ));
    } else if rrtype == DNS_RR_type::URI {
        let prio = dns_read_u16(rdata, 0)?;
        let weight = dns_read_u16(rdata, 2)?;
        let Some(target_data) = rdata.get(4..) else {
            return Err("Packet too small".into());
        };
        let target = std::str::from_utf8(target_data)?;
        return Ok(format!("{} {} {}", prio, weight, target));
    } else if rrtype == DNS_RR_type::CSYNC {
        let soa = dns_read_u32(rdata, 0)?;
        let flags = dns_read_u16(rdata, 4)?;
        let bitmap = parse_nsec_bitmap_vec(&rdata[6..])?;
        let mut bitmap_str = String::new();
        for i in bitmap {
            bitmap_str += &format!("{} ", DNS_RR_type::find(i)?);
        }
        return Ok(format!("{} {} {}", soa, flags, bitmap_str));
    } else if rrtype == DNS_RR_type::DOA {
        let doa_ent = dns_read_u32(rdata, 0)?;
        let doa_type = dns_read_u32(rdata, 4)?;
        let doa_loc = dns_read_u8(rdata, 8)?;
        let doa_media_type_len = dns_read_u8(rdata, 9)? as usize;
        let Some(doa_media_type) = rdata.get(10..10 + doa_media_type_len) else {
            return Err("parse error".into());
        };
        let Some(doa_data) = rdata.get(10 + doa_media_type_len..) else {
            return Err("parse error".into());
        };

        let doa_data_str = general_purpose::STANDARD.encode(doa_data);
        return Ok(format!(
            "{} {} {} {:?} {} ",
            doa_ent,
            doa_type,
            doa_loc,
            String::from_utf8_lossy(doa_media_type),
            doa_data_str
        ));
    } else if rrtype == DNS_RR_type::HIP {
        let hit_len = dns_read_u8(rdata, 0)? as usize;
        let hit_alg = dns_read_u8(rdata, 1)?;
        let pk_len = dns_read_u16(rdata, 2)? as usize;
        let Some(hit) = rdata.get(4..4 + hit_len as usize) else {
            return Err("parse error".into());
        };
        let Some(hip_pk) = rdata.get(4 + hit_len..4 + hit_len + pk_len) else {
            return Err("parse error".into());
        };
        let (rendezvous, _) = dns_parse_name(rdata, 4 + hit_len + pk_len)?;
        return Ok(format!(
            "{} {:x?} {:x?} {}",
            hit_alg,
            hex::encode(hit),
            general_purpose::STANDARD_NO_PAD.encode(hip_pk),
            rendezvous
        ));
    } else if rrtype == DNS_RR_type::MD {
        let (res_md, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_md));
    } else if rrtype == DNS_RR_type::MF {
        let (res_mf, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_mf));
    } else if rrtype == DNS_RR_type::MG {
        let (res_mg, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_mg));
    } else if rrtype == DNS_RR_type::MR {
        let (res_mr, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", res_mr));
    } else if rrtype == DNS_RR_type::NXT {
        let (next, _) = dns_parse_name(packet, offset_in)?;
        let bm = parse_bitmap_vec(&rdata[next.len() + 1..])?;
        return Ok(format!("{} {}", next, map_bitmap_to_rr(&bm)?));
    } else if rrtype == DNS_RR_type::NSAP {
        return Ok(format!("0x{}", hex::encode(rdata)));
    } else if rrtype == DNS_RR_type::NSAP_PTR {
        let (nsap_ptr, _) = dns_parse_name(packet, offset_in)?;
        return Ok(format!("{}", nsap_ptr));
    } else if rrtype == DNS_RR_type::MINFO {
        let (res_mb, offset) = dns_parse_name(packet, offset_in)?;
        let (err_mb, _) = dns_parse_name(packet, offset)?;
        return Ok(format!("{} {}", res_mb, err_mb));
    //} else if rrtype == DNS_RR_type::MAILA { // not an rr _type
    // todo
    //} else if rrtype == DNS_RR_type::MAILB {
    // todo
    } else if rrtype == DNS_RR_type::IPSECKEY {
        let precedence = dns_read_u8(rdata, 0)?;
        let gw_type = dns_read_u8(rdata, 1)?;
        let alg = dns_read_u8(rdata, 2)?;
        let mut pk_offset = 3;
        let mut name = String::new();
        match gw_type {
            0 => {
                name.push('.');
            } // No Gateway
            1 => {
                pk_offset += 4;
                let r: [u8; 4] = rdata[3..8].try_into()?;
                let addr = IpAddr::V4(Ipv4Addr::from(r));
                name = addr.to_string();
            } // IPv4 address
            2 => {
                pk_offset += 16;
                let r: [u8; 16] = rdata[3..20].try_into()?;
                let addr = IpAddr::V6(Ipv6Addr::from(r));
                name = addr.to_string();
            } // IPv6 Address
            3 => {
                (name, pk_offset) = dns_parse_name(rdata, 3)?;
            } // a FQDN
            _ => {
                return Err("Parse Error".into());
            }
        }
        let alg_name;
        if alg == 1 {
            alg_name = "DSA"
        } else if alg == 2 {
            alg_name = "RSA"
        } else {
            return Err("Unknown algorithm".into());
        }
        let Some(pk) = rdata.get(pk_offset..) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {} {} {} {}",
            precedence,
            gw_type,
            alg_name,
            name,
            hex::encode(pk)
        ));
    } else if rrtype == DNS_RR_type::ISDN {
        let addr_len = dns_read_u8(rdata, 0)?;
        let Some(addr) = rdata.get(1..1 + addr_len as usize) else {
            return Err("Parse error".into());
        };
        let subaddr_len = dns_read_u8(rdata, 1 + addr_len as usize)?;
        let Some(sub_addr) = rdata.get(1..1 + addr_len as usize + 1 + subaddr_len as usize) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {}",
            String::from_utf8_lossy(&addr),
            String::from_utf8_lossy(&sub_addr)
        ));
    } else if rrtype == DNS_RR_type::NID {
        let prio = dns_read_u16(rdata, 0)?;
        let node_id1 = dns_read_u16(rdata, 2)?;
        let node_id2 = dns_read_u16(rdata, 4)?;
        let node_id3 = dns_read_u16(rdata, 6)?;
        let node_id4 = dns_read_u16(rdata, 7)?;
        return Ok(format!(
            "{} {:x}:{:x}:{:x}:{:x}",
            prio, node_id1, node_id2, node_id3, node_id4
        ));
    } else if rrtype == DNS_RR_type::L32 {
        let prio = dns_read_u16(rdata, 0)?;
        let r: [u8; 4] = rdata[2..].try_into()?;
        let addr = Ipv4Addr::from(r);
        return Ok(format!("{} {}", prio, addr));
    } else if rrtype == DNS_RR_type::L64 {
        let prio = dns_read_u16(rdata, 0)?;
        let mut r: [u8; 16] = [0; 16];
        for i in 0..rdata[2..].len() {
            r[i] = rdata[2 + i];
        }
        let addr = Ipv6Addr::from(r).to_string();
        return Ok(format!("{} {}", prio, addr.trim_end_matches(':')));
    } else if rrtype == DNS_RR_type::LP {
        let prio = dns_read_u16(rdata, 0)?;
        let (fqdn, _) = dns_parse_name(rdata, 2)?;
        return Ok(format!("{} {}", prio, fqdn));
    } else if rrtype == DNS_RR_type::KX {
        let pref = dns_read_u16(rdata, 0)?;
        let (kx, _) = dns_parse_name(packet, offset_in + 2)?;
        return Ok(format!("{} {}", pref, kx));
    } else if rrtype == DNS_RR_type::TKEY { // meta RR?
         // todo /
    } else if rrtype == DNS_RR_type::KEY {
        let flags = dns_read_u16(rdata, 0)?;
        let protocol = dns_read_u8(rdata, 2)?;
        let alg = dns_read_u8(rdata, 3)?;
        let Some(key) = rdata.get(4..) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {} {} {}",
            flags,
            key_protocol(protocol)?,
            key_algorithm(alg)?,
            general_purpose::STANDARD.encode(key)
        ));
    } else if rrtype == DNS_RR_type::PX {
        let pref = dns_read_u16(rdata, 0)?;
        let (map822, offset) = dns_parse_name(rdata, 2)?;
        let (mapx400, _) = dns_parse_name(rdata, offset)?;
        return Ok(format!("{} {} {}", pref, map822, mapx400));
    } else if rrtype == DNS_RR_type::SIG {
        // todo
    } else if rrtype == DNS_RR_type::SINK {
        let mut coding = dns_read_u8(rdata, 0)?;
        let mut offset = 1;
        if coding == 0 {
            // weird bind thing
            coding = dns_read_u8(rdata, 1)?;
            offset = 2;
        }
        let subcoding = dns_read_u8(rdata, offset)?;
        let Some(data) = rdata.get(offset + 1..) else {
            return Err("Parse error".into());
        };
        return Ok(format!(
            "{} {} {}",
            coding,
            subcoding,
            general_purpose::STANDARD.encode(data)
        ));
    } else if rrtype == DNS_RR_type::EID || rrtype == DNS_RR_type::NIMLOC {
        return Ok(hex::encode(rdata));
    } else if rrtype == DNS_RR_type::NSEC {
        let (next_dom, offset) = dns_parse_name(rdata, 0)?;
        let mut bitmap_str = String::new();
        let bitmap = parse_nsec_bitmap_vec(&rdata[offset..])?;
        for i in bitmap {
            bitmap_str += &format!("{} ", DNS_RR_type::find(i)?);
        }
        return Ok(format!("{} {}", next_dom, bitmap_str));
    } else if rrtype == DNS_RR_type::NSEC3 {
        let hash_alg = dns_read_u8(rdata, 0)?;
        let flags = dns_read_u8(rdata, 1)?;
        let iterations = dns_read_u16(rdata, 2)?;
        let salt_len = dns_read_u8(rdata, 4)? as usize;
        let Some(salt) = rdata.get(5..5 + salt_len) else {
            return Err("parse error".into());
        };
        let hash_len = dns_read_u8(rdata, 5 + salt_len)? as usize;
        let Some(next_owner) = rdata.get(6 + salt_len..6 + salt_len + hash_len) else {
            return Err("parse error".into());
        };
        let bitmap = parse_nsec_bitmap_vec(&rdata[6 + salt_len + hash_len..])?;
        let mut bitmap_str = String::new();
        for i in bitmap {
            bitmap_str += &format!("{} ", DNS_RR_type::find(i)?);
        }
        return Ok(format!(
            "{} {} {} {} {} {}",
            dnssec_digest(hash_alg)?,
            flags,
            iterations,
            hex::encode(salt),
            base32hex_encode(next_owner),
            bitmap_str
        ));
    } else {
        return Err(format!("RR type not supported {:?}", rrtype).into());
    }
    return Ok("".to_string());
}

fn parse_nsec_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let len = bitmap.len();
    let mut res: Vec<u16> = Vec::new();
    let mut offset = 0;
    while offset < len {
        let high_byte = (bitmap[offset] as u16) << 8;
        let size = bitmap[offset + 1] as usize;
        for i in 0..size {
            let mut pos: u8 = 0x80;
            for j in 0..8 {
                if bitmap[offset + 2 + i] & pos != 0 {
                    res.push((high_byte as usize | ((8 * i) + j)).try_into()?);
                }
                pos >>= 1;
            }
        }
        //        println!("iDDD {} {} {:x?} {:?}", offset, len, &bitmap[offset..], res);
        offset += size + 2;
    }
    return Ok(res);
}
fn parse_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let len = bitmap.len();
    let mut res: Vec<u16> = Vec::new();
    for i in 0..len {
        let mut pos: u8 = 0x80;
        for j in 0..8 {
            if bitmap[i] & pos != 0 {
                res.push(((8 * i) + j).try_into()?);
            }
            pos >>= 1;
        }
    }
    return Ok(res);
}

fn map_bitmap_to_rr(bitmap: &[u16]) -> Result<String, Box<dyn std::error::Error>> {
    let mut res = String::new();
    for i in bitmap {
        res += &format!("{} ", DNS_RR_type::find(*i)?);
    }
    return Ok(res);
}

fn parse_bitmap_str(bitmap: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let bitmap = parse_bitmap_vec(bitmap)?;
    return map_bitmap_to_rr(&bitmap);
}
