use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8};
use crate::errors::ParseErrorType::{Invalid_Domain_name, Invalid_packet_index};
use crate::errors::Parse_error;
use std::borrow::Cow;
use tracing::debug;
use once_cell::sync::Lazy;

const MAX_DOMAIN_NAME_LENGTH: usize = 253;
const MAX_DOMAIN_NAME_LENGTH_WITH_DOT: usize = 254;
const MAX_RECURSION_DEPTH: usize = 63;
const MAX_LABEL_LENGTH: usize = 63;
static DNS_NAME_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"^\.?$|^(?:(?:[a-zA-Z0-9]|_)(?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*(?:[a-zA-Z0-9]|_)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.(?:[a-zA-Z0-9]|_)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.?$").unwrap()
});
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_dns_name() {
        // Valid names
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("sub.example.com"));
        assert!(is_valid_dns_name("_test.example.com"));
        assert!(is_valid_dns_name("test-domain.example.com"));
        assert!(is_valid_dns_name("_domain.sub.example.com"));
        assert!(is_valid_dns_name("_domain._sub.example.com"));
        assert!(is_valid_dns_name("domaine-xample.com."));
        assert!(is_valid_dns_name("domain.example.com."));
        assert!(is_valid_dns_name("."));

        // Invalid names
        assert!(!is_valid_dns_name("")); // Empty
        assert!(!is_valid_dns_name(".domain.com")); // Leading dot
        assert!(!is_valid_dns_name("domain..com")); // Consecutive dots
        assert!(!is_valid_dns_name("domain.com..")); // Multiple trailing dots
        assert!(!is_valid_dns_name("-domain.com")); // Leading hyphen
        assert!(!is_valid_dns_name("domain-.com")); // Trailing hyphen
        assert!(!is_valid_dns_name("domain_with_underscore.com")); // Underscore not at start
        assert!(!is_valid_dns_name("test.do_main.com")); // Underscore not at start
        assert!(!is_valid_dns_name("domain.c")); // TLD too short
        assert!(!is_valid_dns_name("d.com")); // Second-level domain too short

        // Invalid characters
        assert!(!is_valid_dns_name("domain$.com"));
        assert!(!is_valid_dns_name("domain space.com"));
        assert!(!is_valid_dns_name("domain@.com"));
        assert!(!is_valid_dns_name("\0domain@.com"));

        // Length restrictions
        assert!(!is_valid_dns_name(&"a".repeat(MAX_DOMAIN_NAME_LENGTH + 1))); // Domain name too long
        assert!(!is_valid_dns_name(&format!("{}.com", "a".repeat(MAX_LABEL_LENGTH + 1)))); // Label too long
        let max_domain = format!("{}.{}.{}.com",
                                 "a".repeat(MAX_LABEL_LENGTH),
                                 "b".repeat(MAX_LABEL_LENGTH),
                                 "c".repeat(MAX_LABEL_LENGTH - 10));
        assert!(is_valid_dns_name(&max_domain)); // Maximum valid length with max length labels
        assert!(is_valid_dns_name(&format!("{}.com", "a".repeat(MAX_LABEL_LENGTH)))); // Maximum valid label length
        let over_max_domain = format!("{}.{}.{}.{}.{}.com",
                                      "a".repeat(MAX_LABEL_LENGTH),
                                      "b".repeat(MAX_LABEL_LENGTH),
                                      "c".repeat(MAX_LABEL_LENGTH),
                                      "e".repeat(MAX_LABEL_LENGTH),
                                      "d".repeat(MAX_LABEL_LENGTH));
        assert!(!is_valid_dns_name(&over_max_domain)); // Exceeds max length with max length labels
        assert!(is_valid_dns_name(&format!("{}.{}.com", "a".repeat(MAX_LABEL_LENGTH), "b".repeat(MAX_LABEL_LENGTH)))); // Combined labels too long
    }

    #[test]
    fn test_dns_name_max_values() {
        // Maximum label length (63 chars)
        let max_label = "a".repeat(MAX_LABEL_LENGTH);
        assert!(is_valid_dns_name(&format!("{}.example.com", max_label)));

        // Maximum total length (253 chars)
        let max_labels = (0..4).map(|i| format!("{}{}", "a".repeat(61), i))
            .collect::<Vec<_>>()
            .join(".");
        assert!(is_valid_dns_name(&max_labels));

        // Maximum number of labels
        let max_label_count = (0..63).map(|i| format!("a{}", i))
            .collect::<Vec<_>>()
            .join(".");
        assert!(is_valid_dns_name(&max_label_count));
    }

    #[test]
    fn test_dns_parse_name_max_values() {
        // Test maximum length domain name parsing
        let mut packet = vec![0u8; 512];
        let mut offset = 0;

        // Create maximum length labels
        for i in 0..4 {
            packet[offset] = 61; // Label length
            offset += 1;
            packet[offset..offset + 61].fill(b'a');
            packet[offset + 60] = i + b'0'; // Make labels unique
            offset += 61;
        }
        packet[offset] = 0; // Terminating zero

        let (name, new_offset) = dns_parse_name(&packet, 0).unwrap();
        assert_eq!(new_offset, offset + 1);
        assert!(name.len() <= MAX_DOMAIN_NAME_LENGTH);
        assert!(is_valid_dns_name(&name));
    }
}

fn is_valid_dns_name(name: &str) -> bool
{
    if name.is_empty() || name.len() > MAX_DOMAIN_NAME_LENGTH_WITH_DOT ||
        (name.len() > MAX_DOMAIN_NAME_LENGTH && !name.ends_with('.')) {
        return false;
    }

    if name == "." {
        return true;
    }

    if !DNS_NAME_REGEX.is_match(name) {
        return false;
    }

    for label in name.split('.') {
        if label.len() > MAX_LABEL_LENGTH {
            return false;
        }
    }

    true
}

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
    if !is_valid_dns_name(name.as_ref()) {
        debug!("Invalid DNS name: {}", name);
    }
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
                Ok(t) => {
                    if name.len() + t.len() + 1 > MAX_DOMAIN_NAME_LENGTH_WITH_DOT {
                        return Err(Parse_error::new(Invalid_Domain_name, &name));
                    }
                    name.push_str(t)
                },
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
