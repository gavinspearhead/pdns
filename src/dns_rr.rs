use crate::dns::{
    cert_type_str, dnssec_algorithm, dnssec_digest, ipsec_alg, key_algorithm, key_protocol,
    sshfp_algorithm, sshfp_fp_type, tlsa_algorithm, tlsa_cert_usage, tlsa_selector, zonemd_digest,
    DNS_RR_type, SVC_Param_Keys,
};
use crate::dns_helper::{
    base32hex_encode, dns_parse_slice, dns_read_u16, dns_read_u32, dns_read_u64, dns_read_u8,
    parse_dns_str, parse_ipv4, parse_ipv6, parse_rrtype, timestame_to_str,
};
use crate::dns_packet::DNS_Protocol;
use crate::errors::{ParseErrorType, Parse_error};
use base64::engine::general_purpose;
use base64::Engine;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

const MAX_DOMAIN_NAME_LENGTH: usize = 253;
const MAX_RECURSION_DEPTH: usize = 63;

pub(crate) fn dns_parse_name(packet: &[u8], offset: usize) -> Result<(String, usize), Parse_error> {
    let (mut name, offset_out) = dns_parse_name_internal(packet, offset, 0)?;
    name = if name.is_empty() {
        String::from('.')
    } else {
        name = name.trim_end_matches('.').to_string();
        if name.len() > MAX_DOMAIN_NAME_LENGTH {
            return Err(Parse_error::new(ParseErrorType::Invalid_Domain_name, &name));
        }
        name
    };
    Ok((name, offset_out))
}
const POINTER_FLAG: u8 = 0xc0;
const POINTER_MASK: u16 = 0x3fff;

fn dns_parse_name_internal(
    packet: &[u8],
    offset_in: usize,
    recursion_depth: usize,
) -> Result<(String, usize), Parse_error> {
    if recursion_depth > MAX_RECURSION_DEPTH {
        debug!("Recursion depth exceeded");
        return Err(Parse_error::new(ParseErrorType::Invalid_packet_index, ""));
    }
    let mut idx = offset_in;
    let mut name = String::new();
    while dns_read_u8(packet, idx)? != 0 {
        let val = dns_read_u8(packet, idx)?; // read the first byte of the pointer
        if (val & POINTER_FLAG) == POINTER_FLAG {
            // it is actually a pointer
            let pos = usize::from(dns_read_u16(packet, idx)? & POINTER_MASK); // slice the of the 2 MSbs
            let (name1, _) = dns_parse_name_internal(packet, pos, recursion_depth + 1)?;
            return Ok((name + &name1, idx + 2));
        } else if (val & POINTER_FLAG) == 0 {
            // it is just a length value.
            let label_len = usize::from(val);
            idx += 1;
            let label = dns_parse_slice(packet, idx..idx + label_len)?;
            name.push_str(match std::str::from_utf8(label) {
                Ok(t) => t,
                Err(_) => {
                    return Err(Parse_error::new(ParseErrorType::Invalid_packet_index, ""));
                }
            });
            name.push('.');
            idx += label_len;
        } else {
            return Err(Parse_error::new(ParseErrorType::Invalid_packet_index, ""));
        }
    }
    Ok((name, idx + 1))
}

fn parse_rr_https(rdata: &[u8]) -> Result<String, Parse_error> {
    //todo fix array size checks
    let svc_prio = dns_read_u16(rdata, 0)?;
    let (target, mut offset) = dns_parse_name(rdata, 2)?;
    let mut res = format!("{svc_prio} {target} ");
    while offset < rdata.len() {
        let Ok(svc_param_key) = SVC_Param_Keys::find(dns_read_u16(rdata, offset)?) else {
            return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
        };

        let svc_param_len = dns_read_u16(rdata, offset + 2)? as usize;
        match svc_param_key {
            SVC_Param_Keys::mandatory => {
                let mut pos: usize = 0;
                res += "mandatory=";
                while pos < svc_param_len {
                    let man_val = dns_read_u16(rdata, offset + pos + 4)?;
                    let Ok(x) = SVC_Param_Keys::find(man_val) else {
                        return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
                    };
                    res += &format!("{x},");
                    pos += 2;
                }
                let mut res1 = res.trim_end_matches(',').to_string();
                /*let Ok(mut res1) = String::from_str(res.trim_end_matches(',')) else {
                    return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
                };*/
                res1 += " ";
                res += &res1;
            }
            SVC_Param_Keys::alpn => {
                let mut pos: usize = 0;
                res += "alpn=";
                while pos < svc_param_len {
                    let alpn_len = usize::from(dns_read_u8(rdata, offset + pos + 4)?);
                    let alpn = String::from_utf8_lossy(dns_parse_slice(
                        rdata,
                        offset + pos + 4 + 1..offset + pos + 4 + 1 + alpn_len,
                    )?);
                    pos += 1 + alpn_len;
                    res += &format!("{alpn},");
                }
                res = res.trim_end_matches(',').to_string() + " ";
            }
            SVC_Param_Keys::ech => {
                res += "ech=";
                let data_str: String = general_purpose::STANDARD.encode(dns_parse_slice(
                    rdata,
                    offset + 4..offset + 4 + svc_param_len,
                )?);
                res += &data_str;
                res += " ";
            }
            SVC_Param_Keys::ipv4hint => {
                res += "ipv4hint=";
                let mut pos: usize = 0;
                while pos + 4 <= svc_param_len {
                    let loc = offset + 4 + pos;
                    let addr = parse_ipv4(dns_parse_slice(rdata, loc..loc+4)?)?;
                    res += &format!("{addr},");
                    pos += 4;
                }
                res = res.trim_end_matches(',').to_string();
                res += " ";
            }
            SVC_Param_Keys::ipv6hint => {
                res += "ipv6hint=";
                let mut pos: usize = 0;
                while pos + 16 <= svc_param_len {
                    let loc = offset + 4 + pos;
                    let addr = parse_ipv6(dns_parse_slice(rdata, loc..loc+16)?)?;
                    res += &format!("{addr},");
                    pos += 16;
                }
                res = res.trim_end_matches(',').to_string();
                res += " ";
            }
            SVC_Param_Keys::no_default_alpn => {
                res += "no-default-alpn";
            }
            SVC_Param_Keys::port => {
                let port = dns_read_u16(rdata, offset + 4)?;
                res += &format!("port={port}");
            }
        }
        offset += 4 + svc_param_len;
    }
    Ok(res)
}

fn decode_gpos_size(val: u8) -> String {
    let mut base = u64::from((val & 0xf0) >> 4);
    let exp = u64::from(val & 0x0f);
    if exp < 2 {
        if exp == 1 {
            base *= 10;
        }
        return format!("0.{base}");
    }
    format!("{base}{}", "0".repeat((exp - 2) as usize))
}

fn parse_rr_a(rdata: &[u8]) -> Result<String, Parse_error> {
    if rdata.len() != 4 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Resource_Record,
            &format!("{rdata:?}"),
        ));
    }
    let addr = parse_ipv4(rdata)?.to_string();
    Ok(addr)
}

fn parse_rr_aaaa(rdata: &[u8]) -> Result<String, Parse_error> {
    if rdata.len() != 16 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Resource_Record,
            &format!("{rdata:?}"),
        ));
    }
    let addr = parse_ipv6(rdata)?.to_string();
    Ok(addr)
}

fn parse_rr_caa(rdata: &[u8]) -> Result<String, Parse_error> {
    let flag = dns_read_u8(rdata, 0)?;
    let tag_len = dns_read_u8(rdata, 1)?;
    let r = dns_parse_slice(rdata, 2..2 + tag_len as usize)?;
    let Ok(tag) = std::str::from_utf8(r) else {
        return Err(Parse_error::new(ParseErrorType::Invalid_DNS_Packet, ""));
    };
    let r = dns_parse_slice(rdata, 2 + tag_len as usize..)?;
    let value = parse_dns_str(r)?;
    Ok(format!("{tag} {value} ({flag})"))
}

fn parse_rr_soa(packet: &[u8], offset_in: usize) -> Result<String, Parse_error> {
    let mut offset: usize = offset_in;
    let ns: String;
    let mb: String;
    (ns, offset) = dns_parse_name(packet, offset)?;
    (mb, offset) = dns_parse_name(packet, offset)?;
    let sn = dns_read_u32(packet, offset)?;
    let refr = dns_read_u32(packet, offset + 4)?;
    let ret = dns_read_u32(packet, offset + 8)?;
    let exp = dns_read_u32(packet, offset + 12)?;
    let ttl = dns_read_u32(packet, offset + 16)?;
    Ok(format!("{ns} {mb} {sn} {refr} {ret} {exp} {ttl}"))
}

fn parse_rr_txt(rdata: &[u8]) -> Result<String, Parse_error> {
    let mut pos = 0;
    let mut res = String::new();
    while pos < rdata.len() {
        let tlen: usize = rdata[pos].into();
        let r = dns_parse_slice(rdata, 1 + pos..pos + tlen + 1)?;
        let _ = write!(res, "{} ", parse_dns_str(r)?);
        pos += 1 + tlen;
    }
    Ok(res)
}

fn parse_rr_hinfo(rdata: &[u8]) -> Result<String, Parse_error> {
    let cpu_len1 = dns_read_u8(rdata, 0)?;
    let cpu_len: usize = cpu_len1 as usize;
    let mut offset: usize = 1;
    let r = dns_parse_slice(rdata, offset..offset + cpu_len)?;
    let mut s = parse_dns_str(r)?;
    offset += cpu_len;
    let os_len = dns_read_u8(rdata, offset)? as usize;
    offset += 1;
    s.push(' ');
    let r = dns_parse_slice(rdata, offset..offset + os_len)?;
    s += &parse_dns_str(r)?;
    Ok(s)
}

fn parse_rr_loc(rdata: &[u8]) -> Result<String, Parse_error> {
    let version = dns_read_u8(rdata, 0)?;
    if version != 0 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Parameter,
            "Unknown GPOS version",
        ));
    }
    let size = dns_read_u8(rdata, 1)?;
    let hor_prec = dns_read_u8(rdata, 2)?;
    let ver_prec = dns_read_u8(rdata, 3)?;
    let mut lat = i64::from(dns_read_u32(rdata, 4)?);
    let mut lon = i64::from(dns_read_u32(rdata, 8)?);
    let alt = i64::from(dns_read_u32(rdata, 12)?);
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
    let a = (alt as f64 / 100.0) - 100_000.0;

    Ok(format!(
        "{ha} {ma} {sa} {north} {ho} {mo} {so} {east} {a}m {}m {}m {}m ",
        decode_gpos_size(size),
        decode_gpos_size(hor_prec),
        decode_gpos_size(ver_prec)
    ))
}

fn parse_rr_nsec3(rdata: &[u8]) -> Result<String, Parse_error> {
    let hash_alg = dns_read_u8(rdata, 0)?;
    let flags = dns_read_u8(rdata, 1)?;
    let iterations = dns_read_u16(rdata, 2)?;
    let salt_len = dns_read_u8(rdata, 4)? as usize;
    let salt = dns_parse_slice(rdata, 5..5 + salt_len)?;
    let hash_len = dns_read_u8(rdata, 5 + salt_len)? as usize;
    let next_owner = dns_parse_slice(rdata, 6 + salt_len..6 + salt_len + hash_len)?;
    let bitmap = parse_nsec_bitmap_vec(&rdata[6 + salt_len + hash_len..])?;
    let mut bitmap_str = String::new();
    for i in bitmap {
        let Ok(x) = DNS_RR_type::find(i) else {
            return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
        };
        bitmap_str += &format!("{x} ");
    }
    Ok(format!(
        "{} {flags} {iterations} {} {} {bitmap_str}",
        dnssec_digest(hash_alg)?,
        hex::encode(salt),
        base32hex_encode(next_owner),
    ))
}
fn parse_rr_dnskey(rdata: &[u8]) -> Result<String, Parse_error> {
    if rdata.len() < 5 {
        return Err(Parse_error::new(ParseErrorType::Invalid_packet_index, ""));
    }
    let flag = dns_read_u16(rdata, 0)?;
    let protocol = dnssec_algorithm(rdata[2])?;
    let alg = dnssec_algorithm(rdata[3])?;
    let pubkey = &rdata[4..];
    Ok(format!("{flag} {protocol} {alg} {}", hex::encode(pubkey)))
}

fn parse_rr_tlsa(rdata: &[u8]) -> Result<String, Parse_error> {
    if rdata.len() < 4 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Resource_Record,
            "",
        ));
    }
    let cert_usage = tlsa_cert_usage(rdata[0])?;
    let selector = tlsa_selector(rdata[1])?;
    let alg_type = tlsa_algorithm(rdata[2])?;
    let cad = &rdata[3..];
    Ok(format!(
        "{cert_usage} {selector} {alg_type} {}",
        hex::encode(cad)
    ))
}

fn parse_rr_cds(rdata: &[u8]) -> Result<String, Parse_error> {
    if rdata.len() < 5 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Resource_Record,
            "",
        ));
    }
    let keyid = dns_read_u16(rdata, 0)?;
    let alg = dnssec_algorithm(rdata[2])?;
    let dig_t = dnssec_digest(rdata[3])?;
    let dig = &rdata[4..];
    Ok(format!("{keyid} {alg} {dig_t} {}", hex::encode(dig)))
}

fn parse_rr_ipseckey(rdata: &[u8]) -> Result<String, Parse_error> {
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
            name = parse_ipv4(dns_parse_slice(rdata, 3..7)?)?.to_string();
        } // IPv4 address
        2 => {
            pk_offset += 16;
            name = parse_ipv6(dns_parse_slice(rdata, 3..19)?)?.to_string();
        } // IPv6 Address
        3 => {
            (name, pk_offset) = dns_parse_name(rdata, 3)?;
        } // a FQDN
        e => {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_Resource_Record,
                &e.to_string(),
            ));
        }
    }
    let alg_name = ipsec_alg(alg)?;
    let pk = dns_parse_slice(rdata, pk_offset..)?;
    Ok(format!(
        "{precedence} {gw_type} {alg_name} {name} {}",
//       base64::encode(pk)
        general_purpose::STANDARD.encode(pk)
    ))
}

fn parse_rr_apl(rdata: &[u8]) -> Result<String, Parse_error> {
    let mut pos = 0;
    let mut res = String::new();
    while pos < rdata.len() {
        let af = dns_read_u16(rdata, pos)?;
        let pref_len = dns_read_u8(rdata, pos + 2)?;
        let addr_len_ = dns_read_u8(rdata, pos + 3)?;
        let flags = addr_len_ >> 7;
        let neg_str = if flags > 0 { "!" } else { "" };

        let addr_len = (addr_len_ & 0x7f) as usize;
        let addr = dns_parse_slice(rdata, pos + 4..pos + 4 + addr_len)?;
        let ip_addr: IpAddr;
        if af == 1 {
            // ipv4
            let mut ip: [u8; 4] = [0; 4];
            ip[..addr_len].copy_from_slice(&addr[..addr_len]);
            ip_addr = IpAddr::V4(Ipv4Addr::from(ip));
        } else if af == 2 {
            // Ipv6
            let mut ip: [u8; 16] = [0; 16];
            ip[..addr_len].copy_from_slice(&addr[..addr_len]);
            ip_addr = IpAddr::V6(Ipv6Addr::from(ip));
        } else {
            return Err(Parse_error::new(
                ParseErrorType::Unknown_Address_Family,
                &af.to_string(),
            ));
        }
        res += &format!("{neg_str}{ip_addr}/{pref_len} ");
        pos += 4 + addr_len;
    }
    Ok(res)
}

fn parse_rr_gpos(rdata: &[u8]) -> Result<String, Parse_error> {
    let mut idx = 0;
    let lon_len = dns_read_u8(rdata, idx)? as usize;
    idx += 1;
    let lon = dns_parse_slice(rdata, idx..idx + lon_len)?;
    idx += lon_len;
    let lat_len = dns_read_u8(rdata, idx)? as usize;
    idx += 1;
    let lat = dns_parse_slice(rdata, idx..idx + lat_len)?;
    idx += lat_len;
    let alt_len = dns_read_u8(rdata, idx)? as usize;
    idx += 1;
    let alt = dns_parse_slice(rdata, idx..idx + alt_len)?;
    Ok(format!(
        "{} {} {}",
        parse_dns_str(lon)?,
        parse_dns_str(lat)?,
        parse_dns_str(alt)?
    ))
}

fn parse_rr_nsec3param(rdata: &[u8]) -> Result<String, Parse_error> {
    let hash = dns_read_u8(rdata, 0)?;
    let flags = dns_read_u8(rdata, 1)?;
    let iterations = dns_read_u16(rdata, 2)?;
    let salt_len = dns_read_u8(rdata, 4)? as usize;
    if salt_len + 5 > rdata.len() {
        return Err(Parse_error::new(ParseErrorType::Invalid_NSEC3PARAM, ""));
    }
    let salt = dns_parse_slice(rdata, 5..5 + salt_len)?;
    Ok(format!("{hash} {flags} {iterations} {}", hex::encode(salt)))
}

fn parse_rr_x25(rdata: &[u8]) -> Result<String, Parse_error> {
    let len = dns_read_u8(rdata, 0)? as usize;
    if len + 1 != rdata.len() {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Parameter,
            "Invalid X25 format",
        ));
    }
    let addr = dns_parse_slice(rdata, 1..=len)?;
    let addr1 = parse_dns_str(addr)?;
    Ok(addr1)
}

fn parse_rr_naptr(rdata: &[u8]) -> Result<String, Parse_error> {
    let order = dns_read_u16(rdata, 0)?;
    let pref = dns_read_u16(rdata, 2)?;
    let flag_len = usize::from(dns_read_u8(rdata, 4)?);
    let mut offset: usize = 5;
    let flags = parse_dns_str(dns_parse_slice(rdata, offset..offset + flag_len)?)?;
    offset += flag_len;
    let srv_len = usize::from(dns_read_u8(rdata, offset)?);
    offset += 1;
    let srv = parse_dns_str(dns_parse_slice(rdata, offset..offset + srv_len)?)?;
    offset += srv_len;
    let re_len = usize::from(dns_read_u8(rdata, offset)?);
    offset += 1;
    let mut re = String::new();
    if re_len > 0 {
        re.clone_from(&(parse_dns_str(dns_parse_slice(rdata, offset..offset + re_len)?)?));
    }
    offset += re_len;
    let (repl, _) = dns_parse_name(rdata, offset)?;
    Ok(format!("{order} {pref} {flags} {srv} {re} {repl}"))
}

fn parse_rr_srv(rdata: &[u8]) -> Result<String, Parse_error> {
    let prio = dns_read_u16(rdata, 0)?;
    let weight = dns_read_u16(rdata, 2)?;
    let port = dns_read_u16(rdata, 4)?;
    let (target, _offset_out) = dns_parse_name(rdata, 6)?;
    Ok(format!("{prio} {weight} {port} {target}"))
}

fn parse_rr_sshfp(rdata: &[u8]) -> Result<String, Parse_error> {
    if rdata.len() < 3 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Resource_Record,
            "",
        ));
    }
    let alg = sshfp_algorithm(rdata[0])?;
    let fp_type = sshfp_fp_type(rdata[1])?;
    let fingerprint = dns_parse_slice(rdata, 2..)?;
    Ok(format!("{alg} {fp_type} {}", hex::encode(fingerprint)))
}

fn parse_rr_cert(rdata: &[u8]) -> Result<String, Parse_error> {
    let cert_type = dns_read_u16(rdata, 0)?;
    let key_tag = dns_read_u16(rdata, 2)?;
    let alg = dns_read_u8(rdata, 4)?;
    let cert = dns_parse_slice(rdata, 5..)?;
    Ok(format!(
        "{} {key_tag} {} {}",
        cert_type_str(cert_type)?,
        dnssec_algorithm(alg)?,
        hex::encode(cert)
    ))
}

fn parse_rr_wks(rdata: &[u8]) -> Result<String, Parse_error> {
    let address = dns_parse_slice(rdata, 0..4)?;
    let protocol = dns_read_u8(rdata, 4)?;
    let bitmap = dns_parse_slice(rdata, 5..)?;
    let addr_str = parse_ipv4(address)?;
    Ok(format!(
        "{addr_str} {} {}",
        DNS_Protocol::find(protocol.into())?.to_str(),
        parse_bitmap_vec(bitmap)?
            .iter()
            .fold(String::new(), |a, &n| a + &n.to_string() + " ")
    ))
}

fn parse_rr_dlv(rdata: &[u8]) -> Result<String, Parse_error> {
    let key_id = dns_parse_slice(rdata, 0..2)?;
    let alg = dns_read_u8(rdata, 2)?;
    let digest_type = dns_read_u8(rdata, 3)?;
    let digest = dns_parse_slice(rdata, 4..)?;
    Ok(format!(
        "{} {} {} {}",
        hex::encode(key_id),
        dnssec_algorithm(alg)?,
        dnssec_digest(digest_type)?,
        hex::encode(digest)
    ))
}

fn parse_rr_zonemd(rdata: &[u8]) -> Result<String, Parse_error> {
    let serial = dns_read_u32(rdata, 0)?;
    let scheme = dns_read_u8(rdata, 4)?;
    let alg = dns_read_u8(rdata, 5)?;
    let digest = dns_parse_slice(rdata, 6..)?;
    Ok(format!(
        "{serial} {scheme} {} {}",
        zonemd_digest(alg)?,
        hex::encode(digest)
    ))
}

fn parse_rr_uri(rdata: &[u8]) -> Result<String, Parse_error> {
    let prio = dns_read_u16(rdata, 0)?;
    let weight = dns_read_u16(rdata, 2)?;
    let target_data = dns_parse_slice(rdata, 4..)?;
    let target = parse_dns_str(target_data)?;
    Ok(format!("{prio} {weight} {target}"))
}

fn parse_rr_csync(rdata: &[u8]) -> Result<String, Parse_error> {
    let soa = dns_read_u32(rdata, 0)?;
    let flags = dns_read_u16(rdata, 4)?;
    let bitmap = parse_nsec_bitmap_vec(dns_parse_slice(rdata, 6..)?)?;
    let mut bitmap_str = String::new();
    for i in bitmap {
        let Ok(x) = DNS_RR_type::find(i) else {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_Resource_Record,
                "",
            ));
        };
        bitmap_str += &format!("{x} ");
    }
    Ok(format!("{soa} {flags} {bitmap_str}"))
}

fn parse_rr_doa(rdata: &[u8]) -> Result<String, Parse_error> {
    let doa_ent = dns_read_u32(rdata, 0)?;
    let doa_type = dns_read_u32(rdata, 4)?;
    let doa_loc = dns_read_u8(rdata, 8)?;
    let doa_media_type_len = dns_read_u8(rdata, 9)? as usize;
    let doa_media_type = dns_parse_slice(rdata, 10..10 + doa_media_type_len)?;
    let doa_data = dns_parse_slice(rdata, 10 + doa_media_type_len..)?;
    let doa_data_str = general_purpose::STANDARD.encode(doa_data);
    Ok(format!(
        "{doa_ent} {doa_type} {doa_loc} {:?} {doa_data_str} ",
        String::from_utf8_lossy(doa_media_type),
    ))
}

fn parse_rr_nsec(rdata: &[u8]) -> Result<String, Parse_error> {
    let (next_dom, offset) = dns_parse_name(rdata, 0)?;
    let mut bitmap_str = String::new();
    let bitmap = parse_nsec_bitmap_vec(dns_parse_slice(rdata, offset..)?)?;
    for i in bitmap {
        let Ok(x) = DNS_RR_type::find(i) else {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_Resource_Record,
                "",
            ));
        };
        bitmap_str += &format!("{x} ");
    }
    Ok(format!("{next_dom} {bitmap_str}"))
}
fn parse_rr_sink(rdata: &[u8]) -> Result<String, Parse_error> {
    let mut coding = dns_read_u8(rdata, 0)?;
    let mut offset = 1;
    if coding == 0 {
        // weird bind thing
        coding = dns_read_u8(rdata, 1)?;
        offset = 2;
    }
    let subcoding = dns_read_u8(rdata, offset)?;
    let val = dns_parse_slice(rdata, offset + 1..)?;
    Ok(format!(
        "{coding} {subcoding} {}",
        general_purpose::STANDARD.encode(val)
    ))
}
fn parse_rr_key(rdata: &[u8]) -> Result<String, Parse_error> {
    let flags = dns_read_u16(rdata, 0)?;
    let protocol = dns_read_u8(rdata, 2)?;
    let alg = dns_read_u8(rdata, 3)?;
    let key = dns_parse_slice(rdata, 4..)?;
    Ok(format!(
        "{flags} {} {} {}",
        key_protocol(protocol)?,
        dnssec_algorithm(alg)?,
        general_purpose::STANDARD.encode(key)
    ))
}

fn parse_rr_hip(rdata: &[u8]) -> Result<String, Parse_error> {
    let hit_len = dns_read_u8(rdata, 0)? as usize;
    let hit_alg = dns_read_u8(rdata, 1)?;
    let pk_len = dns_read_u16(rdata, 2)? as usize;
    let hit = dns_parse_slice(rdata, 4..4 + hit_len)?;
    let hip_pk = dns_parse_slice(rdata, 4 + hit_len..4 + hit_len + pk_len)?;
    let (rendezvous, _) = dns_parse_name(rdata, 4 + hit_len + pk_len)?;
    Ok(format!(
        "{hit_alg} {:x?} {:x?} {rendezvous}",
        hex::encode(hit),
        general_purpose::STANDARD_NO_PAD.encode(hip_pk),
    ))
}

fn parse_rr_l32(rdata: &[u8]) -> Result<String, Parse_error> {
    let prio = dns_read_u16(rdata, 0)?;
    let addr = parse_ipv4(&rdata[2..])?;
    Ok(format!("{prio} {addr}"))
}

fn parse_rr_l64(rdata: &[u8]) -> Result<String, Parse_error> {
    let prio = dns_read_u16(rdata, 0)?;
    let mut r: [u8; 16] = [0; 16];
    r[..8].copy_from_slice(dns_parse_slice(rdata, 2..(8 + 2))?);
    let addr = Ipv6Addr::from(r).to_string();
    Ok(format!("{prio} {}", addr.trim_end_matches(':')))
}

fn parse_rr_nid(rdata: &[u8]) -> Result<String, Parse_error> {
    let prio = dns_read_u16(rdata, 0)?;
    let node_id1 = dns_read_u16(rdata, 2)?;
    let node_id2 = dns_read_u16(rdata, 4)?;
    let node_id3 = dns_read_u16(rdata, 6)?;
    let node_id4 = dns_read_u16(rdata, 7)?;
    Ok(format!(
        "{prio} {node_id1:x}:{node_id2:x}:{node_id3:x}:{node_id4:x}"
    ))
}

fn parse_rr_isdn(rdata: &[u8]) -> Result<String, Parse_error> {
    let addr_len = usize::from(dns_read_u8(rdata, 0)?);
    let addr = dns_parse_slice(rdata, 1..=addr_len)?;
    let mut sub_addr_str = String::new();
    if rdata.len() > 1+addr_len {
        let subaddr_len = usize::from(dns_read_u8(rdata, 1 + addr_len)?);
        
        let sub_addr = dns_parse_slice(rdata, 2 + addr_len..1 + addr_len + 1 + subaddr_len)?;
        sub_addr_str = String::from_utf8_lossy(sub_addr).into();
    }
    Ok(format!(
        "'{}' '{}'",
        String::from_utf8_lossy(addr),
        sub_addr_str
    ))
}

fn parse_rr_amtrelay(packet: &[u8], rdata: &[u8], offset_in: usize) -> Result<String, Parse_error> {
    let precedence = dns_read_u8(rdata, 0)?;
    let mut rtype = dns_read_u8(rdata, 1)?;
    let dbit = rtype >> 7;
    rtype &= 0x7f;
    let relay: String;
    if rtype == 3 {
        (relay, _) = dns_parse_name(packet, offset_in + 2)?;
    } else if rtype == 2 {
        let addr = parse_ipv6(&rdata[2..18])?;
        relay = format!("{addr}");
    } else if rtype == 1 {
        let addr = parse_ipv4(&rdata[2..6])?;
        relay = format!("{addr}");
    } else {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_Parameter,
            &rtype.to_string(),
        ));
    }
    Ok(format!("{precedence} {dbit} {rtype} {relay}"))
}

fn parse_rr_a6(packet: &[u8], rdata: &[u8], offset_in: usize) -> Result<String, Parse_error> {
    let prefix_len = dns_read_u8(rdata, 0)? as usize;
    let len: usize = (128 - prefix_len) / 8;
    let mut r: [u8; 16] = [0; 16];
    for i in 0..len {
        r[15 - i] = dns_read_u8(rdata, len - i)?;
    }
    let addr_suffix = Ipv6Addr::from(r);
    let mut prefix_name = String::new();
    if prefix_len != 0 {
        (prefix_name, _) = dns_parse_name(packet, offset_in + 1 + len)?;
    }
    Ok(format!("{prefix_len} {addr_suffix} {prefix_name}"))
}

fn parse_rr_rrsig(rdata: &[u8]) -> Result<String, Parse_error> {
    let Ok(sig_rrtype) = parse_rrtype(dns_read_u16(rdata, 0)?) else {
        return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
    };
    let sig_rrtype_str = sig_rrtype.to_str();
    let alg = dnssec_algorithm(dns_read_u8(rdata, 2)?)?;
    let labels = dns_read_u8(rdata, 3)?;
    let ttl = dns_read_u32(rdata, 4)?;
    let sig_exp = timestame_to_str(dns_read_u32(rdata, 8)?)?;
    let sig_inc = timestame_to_str(dns_read_u32(rdata, 12)?)?;
    let key_tag = dns_read_u16(rdata, 16)?;
    let (signer, offset_out) = dns_parse_name(rdata, 18)?;
    let signature = dns_parse_slice(rdata, offset_out..)?;
    Ok(format!(
        "{sig_rrtype_str} {alg} {labels} {ttl} {sig_exp} {sig_inc} {key_tag} {signer} {}",
        hex::encode(signature)
    ))
}

pub(crate) fn dns_parse_rdata(
    rdata: &[u8],
    rrtype: DNS_RR_type,
    packet: &[u8],
    offset_in: usize,
) -> Result<String, Parse_error> {
    if rrtype == DNS_RR_type::A {
        parse_rr_a(rdata)
    } else if rrtype == DNS_RR_type::AAAA {
        parse_rr_aaaa(rdata)
    } else if rrtype == DNS_RR_type::CNAME
        || rrtype == DNS_RR_type::DNAME
        || rrtype == DNS_RR_type::NS
    {
        let (s, _offset) = dns_parse_name(packet, offset_in)?;
        Ok(s)
    } else if rrtype == DNS_RR_type::CAA {
        parse_rr_caa(rdata)
    } else if rrtype == DNS_RR_type::SOA {
        parse_rr_soa(packet, offset_in)
    } else if rrtype == DNS_RR_type::TXT
        || rrtype == DNS_RR_type::NINF0
        || rrtype == DNS_RR_type::AVC
        || rrtype == DNS_RR_type::SPF
        || rrtype == DNS_RR_type::CLA
        || rrtype == DNS_RR_type::WALLET
        || rrtype == DNS_RR_type::RESINFO
    {
        parse_rr_txt(rdata)
    } else if rrtype == DNS_RR_type::IPN {
        let ipn = dns_read_u64(packet, offset_in)?;
        Ok(format!("{ipn}"))
    } else if rrtype == DNS_RR_type::PTR {
        let (ptr, _offset_out) = dns_parse_name(packet, offset_in)?;
        Ok(ptr)
    } else if rrtype == DNS_RR_type::MX || rrtype == DNS_RR_type::RT {
        let _pref = dns_read_u16(rdata, 0)?;
        let (mx, _offset_out) = dns_parse_name(packet, offset_in + 2)?;
        Ok(mx)
    } else if rrtype == DNS_RR_type::HINFO {
        parse_rr_hinfo(rdata)
    } else if rrtype == DNS_RR_type::SRV {
        parse_rr_srv(rdata)
    } else if rrtype == DNS_RR_type::TLSA || rrtype == DNS_RR_type::SMIMEA {
        parse_rr_tlsa(rdata)
    } else if rrtype == DNS_RR_type::AFSDB {
        let subtype = dns_read_u16(rdata, 0)?;
        let (hostname, _offset_out) = dns_parse_name(rdata, 2)?;
        Ok(format!("{subtype} {hostname}"))
    } else if rrtype == DNS_RR_type::CDS || rrtype == DNS_RR_type::DS || rrtype == DNS_RR_type::TA {
        parse_rr_cds(rdata)
    } else if rrtype == DNS_RR_type::DNSKEY || rrtype == DNS_RR_type::CDNSKEY {
        parse_rr_dnskey(rdata)
    } else if rrtype == DNS_RR_type::LOC {
        parse_rr_loc(rdata)
    } else if rrtype == DNS_RR_type::NAPTR {
        parse_rr_naptr(rdata)
    } else if rrtype == DNS_RR_type::RRSIG {
        parse_rr_rrsig(rdata)
    } else if rrtype == DNS_RR_type::SSHFP {
        parse_rr_sshfp(rdata)
    } else if rrtype == DNS_RR_type::OPENPGPKEY {
        let pubkey = general_purpose::STANDARD_NO_PAD.encode(rdata);
        Ok(pubkey)
    } else if rrtype == DNS_RR_type::RP {
        let (mailbox, offset) = dns_parse_name(rdata, 0)?;
        let (txt, _) = dns_parse_name(rdata, offset)?;
        Ok(format!("{mailbox} {txt}"))
    } else if rrtype == DNS_RR_type::MB {
        let (mb, _offset) = dns_parse_name(packet, offset_in)?;
        Ok(mb)
    } else if rrtype == DNS_RR_type::A6 {
        parse_rr_a6(packet, rdata, offset_in)
    } else if rrtype == DNS_RR_type::AMTRELAY {
        parse_rr_amtrelay(packet, rdata, offset_in)
    } else if rrtype == DNS_RR_type::X25 {
        parse_rr_x25(rdata)
    } else if rrtype == DNS_RR_type::NSEC3PARAM {
        parse_rr_nsec3param(rdata)
    } else if rrtype == DNS_RR_type::GPOS {
        parse_rr_gpos(rdata)
    } else if rrtype == DNS_RR_type::EUI48 {
        if rdata.len() != 6 {
            return Err(Parse_error::new(ParseErrorType::Invalid_packet_index, ""));
        }
        Ok(format!(
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5]
        ))
    } else if rrtype == DNS_RR_type::EUI64 {
        if rdata.len() != 8 {
            return Err(Parse_error::new(ParseErrorType::Invalid_packet_index, ""));
        }
        Ok(format!(
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5], rdata[6], rdata[7]
        ))
    } else if rrtype == DNS_RR_type::CERT {
        parse_rr_cert(rdata)
    } else if rrtype == DNS_RR_type::HTTPS || rrtype == DNS_RR_type::SVCB {
        parse_rr_https(rdata)
    } else if rrtype == DNS_RR_type::WKS {
        parse_rr_wks(rdata)
        /*    } else if rrtype == DNS_RR_type::TSIG {
        // todo*/
    } else if rrtype == DNS_RR_type::APL {
        parse_rr_apl(rdata)
    } else if rrtype == DNS_RR_type::ATMA {
        let format = dns_read_u8(rdata, 0)?;
        let address = &rdata[1..];
        Ok(format!("{format} {}", hex::encode(address)))
    } else if rrtype == DNS_RR_type::DLV {
        parse_rr_dlv(rdata)
    } else if rrtype == DNS_RR_type::TALINK {
        let (name1, offset_out) = dns_parse_name(packet, offset_in)?;
        let (name2, _) = dns_parse_name(packet, offset_out)?;
        Ok(format!("{name1} {name2}"))
    } else if rrtype == DNS_RR_type::DHCID {
        Ok(hex::encode(rdata).to_string())
    } else if rrtype == DNS_RR_type::ZONEMD {
        parse_rr_zonemd(rdata)
    } else if rrtype == DNS_RR_type::URI {
        parse_rr_uri(rdata)
    } else if rrtype == DNS_RR_type::CSYNC {
        parse_rr_csync(rdata)
    } else if rrtype == DNS_RR_type::DOA {
        parse_rr_doa(rdata)
    } else if rrtype == DNS_RR_type::HIP {
        parse_rr_hip(rdata)
    } else if rrtype == DNS_RR_type::MD
        || rrtype == DNS_RR_type::MF
        || rrtype == DNS_RR_type::MG
        || rrtype == DNS_RR_type::MR
    {
        let (res, _) = dns_parse_name(packet, offset_in)?;
        Ok(res)
    } else if rrtype == DNS_RR_type::NXT {
        let (next, _) = dns_parse_name(packet, offset_in)?;
        let bm = parse_bitmap_vec(&rdata[next.len() + 2..])?;
        Ok(format!("{} {}", next, map_bitmap_to_rr(&bm)?))
    } else if rrtype == DNS_RR_type::NSAP {
        Ok(format!("0x{}", hex::encode(rdata)))
    } else if rrtype == DNS_RR_type::NSAP_PTR {
        let (nsap_ptr, _) = dns_parse_name(packet, offset_in)?;
        Ok(nsap_ptr)
    } else if rrtype == DNS_RR_type::MINFO {
        let (res_mb, offset) = dns_parse_name(packet, offset_in)?;
        let (err_mb, _) = dns_parse_name(packet, offset)?;
        Ok(format!("{res_mb} {err_mb}"))
    //} else if rrtype == DNS_RR_type::MAILA { // not an rr _type
    // todo
    //} else if rrtype == DNS_RR_type::MAILB {
    // todo
    } else if rrtype == DNS_RR_type::IPSECKEY {
        parse_rr_ipseckey(rdata)
    } else if rrtype == DNS_RR_type::ISDN {
        parse_rr_isdn(rdata)
    } else if rrtype == DNS_RR_type::NID {
        parse_rr_nid(rdata)
    } else if rrtype == DNS_RR_type::L32 {
        parse_rr_l32(rdata)
    } else if rrtype == DNS_RR_type::L64 {
        parse_rr_l64(rdata)
    } else if rrtype == DNS_RR_type::LP {
        let prio = dns_read_u16(rdata, 0)?;
        let (fqdn, _) = dns_parse_name(rdata, 2)?;
        Ok(format!("{prio} {fqdn}"))
    } else if rrtype == DNS_RR_type::KX {
        let pref = dns_read_u16(rdata, 0)?;
        let (kx, _) = dns_parse_name(packet, offset_in + 2)?;
        Ok(format!("{pref} {kx}"))
    //} else if rrtype == DNS_RR_type::TKEY { // meta RR?
    // todo /
    } else if rrtype == DNS_RR_type::RKEY {
        parse_rr_key(rdata)
    } else if rrtype == DNS_RR_type::KEY {
        parse_rr_key(rdata)
    } else if rrtype == DNS_RR_type::PX {
        let pref = dns_read_u16(rdata, 0)?;
        let (map822, offset) = dns_parse_name(rdata, 2)?;
        let (mapx400, _) = dns_parse_name(rdata, offset)?;
        Ok(format!("{pref} {map822} {mapx400}"))
    //} else if rrtype == DNS_RR_type::SIG {
    // todo
    } else if rrtype == DNS_RR_type::SINK {
        parse_rr_sink(rdata)
    } else if rrtype == DNS_RR_type::EID || rrtype == DNS_RR_type::NIMLOC {
        Ok(hex::encode(rdata))
    } else if rrtype == DNS_RR_type::NSEC {
        parse_rr_nsec(rdata)
    } else if rrtype == DNS_RR_type::NSEC3 {
        parse_rr_nsec3(rdata)
    } else if rrtype == DNS_RR_type::Private {
        Ok(String::new().into())
        // just ignore
    } else {
        debug!("Unknown RR type");
        Err(Parse_error::new(
            ParseErrorType::Invalid_Resource_Record,
            rrtype.to_str(),
        ))
    }
}

fn parse_nsec_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Parse_error> {
    let len = bitmap.len();
    let mut res: Vec<u16> = Vec::new();
    let mut offset = 0;
    while offset < len {
        let high_byte = (u16::from(dns_read_u8(bitmap, offset)?)) << 8;
        let size = usize::from(dns_read_u8(bitmap,offset + 1)?);
        for i in 0..size {
            let mut pos: u8 = 0x80;
            for j in 0..8 {
                if dns_read_u8(bitmap,offset + 2 + i)? & pos != 0 {
                    let Ok(x) = (high_byte as usize | ((8 * i) + j)).try_into() else {
                        return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
                    };
                    res.push(x);
                }
                pos >>= 1;
            }
        }
        offset += size + 2;
    }
    Ok(res)
}

fn parse_bitmap_vec(bitmap: &[u8]) -> Result<Vec<u16>, Parse_error> {
    let mut res: Vec<u16> = Vec::new();
    for (i, item) in bitmap.iter().enumerate() {
        let mut pos: u8 = 0x80;
        for j in 0..8 {
            if item & pos != 0 {
                let Ok(x) = ((8 * i) + j).try_into() else {
                    return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
                };
                res.push(x);
            }
            pos >>= 1;
        }
    }
    Ok(res)
}

fn map_bitmap_to_rr(bitmap: &[u16]) -> Result<String, Parse_error> {
    let mut res = String::new();
    for i in bitmap {
        let Ok(x) = DNS_RR_type::find(*i) else {
            return Err(Parse_error::new(ParseErrorType::Invalid_Parameter, ""));
        };
        res += &format!("{x} ");
    }
    Ok(res)
}
