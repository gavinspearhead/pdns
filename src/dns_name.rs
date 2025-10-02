use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8};
use crate::errors::ParseErrorType::{Invalid_Domain_name, Invalid_packet_index};
use crate::errors::Parse_error;
use std::borrow::Cow;
use tracing::debug;

const MAX_DOMAIN_NAME_LENGTH: usize = 253;
const MAX_RECURSION_DEPTH: usize = 63;

pub(crate) fn dns_parse_name(packet: &[u8], offset: usize) -> Result<(String, usize), Parse_error> {
    let (name, offset_out) = dns_parse_name_internal(packet, offset, 0)?;
    let name = if name.is_empty() {
        Cow::Borrowed(".")
    } else {
        let trimmed = name.strip_suffix('.').unwrap_or(&name);
        if trimmed.len() > MAX_DOMAIN_NAME_LENGTH {
            return Err(Parse_error::new(Invalid_Domain_name, &name));
        }
        Cow::Owned(trimmed.to_string())
    };
    Ok((name.into_owned(), offset_out))
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
        return Err(Parse_error::new(Invalid_packet_index, ""));
    }
    let mut idx = offset_in;
    let mut name = String::with_capacity(MAX_DOMAIN_NAME_LENGTH);
    loop {
        let val = dns_read_u8(packet, idx)?; // read the first byte of the pointer
        if val == 0 {
            break;
        }
        if (val & POINTER_FLAG) == POINTER_FLAG {
            // it is actually a pointer
            let pos = usize::from(dns_read_u16(packet, idx)? & POINTER_MASK); // slice the of the 2 MSbs
            let (pointer_name, _) = dns_parse_name_internal(packet, pos, recursion_depth + 1)?;
            name.push_str(pointer_name.as_str());
            return Ok((name, idx + 2));
        } else if (val & POINTER_FLAG) == 0 {
            // it is just a length value.
            let label_len = usize::from(val & 0x3f);
            idx += 1;
            let label = dns_parse_slice(packet, idx..idx + label_len)?;
            match std::str::from_utf8(label) {
                Ok(t) => name.push_str(t),
                Err(_) => {
                    return Err(Parse_error::new(Invalid_packet_index, &format!("{idx}")));
                }
            }
            name.push('.');
            idx += label_len;
        } else {
            return Err(Parse_error::new(Invalid_packet_index, &format!("{idx}")));
        }
    }
    Ok((name, idx + 1))
}
