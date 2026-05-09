use crate::dns_helper::{dns_parse_slice, dns_read_u16, dns_read_u8};
use crate::errors::{ParseError, ParseErrorType};
use byteorder::{BigEndian, ByteOrder};
use std::fmt::Display;

#[derive(Clone, Default)]
pub struct ECHConfig {
    version: u16,
    length: u16,
    contents: ECHConfigContents,
}

#[derive( Clone, Default)]
pub struct ECHConfigContents {
    config_id: u8,
    kem_id: u16,
    hpke_public_key: Vec<u8>,
    cipher_suites: Vec<ECHCipherSuite>,
    maximum_name_length: u8,
    public_name: String,
    extensions: Vec<ECHExtension>,
}

#[derive(Debug, Clone, Default)]
pub struct ECHCipherSuite {
    kdf_id: u16,
    aead_id: u16,
}

#[derive(Clone, Default)]
pub struct ECHExtension {
    extension_type: u16,
    extension_data: Vec<u8>,
}

impl ECHConfig {
    pub fn parse(data: &[u8]) -> Result<Vec<Self>, ParseError> {
        if data.len() < 4 {
            return Err(ParseError::new(
                ParseErrorType::Invalid_DNS_Packet,
                "Insufficient length",
            ));
        }
        let mut configs = Vec::new();
        let mut offset = 0;

        // Parse the outer ECHConfigList
        let total_length = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;

        if data.len() < (offset + total_length as usize) {
            return Err(ParseError::new(
                ParseErrorType::Invalid_DNS_Packet,
                "Insufficient length",
            ));
        }

        while offset < total_length as usize {
            let config = Self::parse_config(&data[offset..])?;
            offset += config.length as usize + 4; // 4 = version(2) + length(2)
            configs.push(config);
        }

        Ok(configs)
    }

    fn parse_config(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 4 {
            return Err(ParseError::new(
                ParseErrorType::Invalid_DNS_Packet,
                "Insufficient length",
            ));
        }

        let version = dns_read_u16(data, 0)?;
        let length = dns_read_u16(data, 2)?;

        if data.len() < (4 + length as usize) {
            return Err(ParseError::new(
                ParseErrorType::Invalid_DNS_Packet,
                "Insufficient length",
            ));
        }

        let contents = ECHConfigContents::parse(&data[4..4 + length as usize])?;

        Ok(Self {
            version,
            length,
            contents,
        })
    }
}

impl ECHConfigContents {
    fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 6 {
            return Err(ParseError::new(
                ParseErrorType::Invalid_DNS_Packet,
                "Insufficient length",
            ));
        }
        let mut offset = 0;

        let config_id = dns_read_u8(data, offset)?;
        offset += 1;
        // Parse cipher suite

        let kem_id = dns_read_u16(&data, offset)?;
        offset += 2;
        let key_length = dns_read_u16(data, offset)? as usize;
        offset += 2;
        let pub_key = dns_parse_slice(data, offset..offset + key_length)?;
        offset += key_length;
        let cipher_suites_length = dns_read_u16(data, offset)? as usize;
        offset += 2;
        let mut cipher_suites = Vec::new();
        for i in (0..cipher_suites_length).step_by(4) {
            let kdf = dns_read_u16(data, offset + i)?;
            let aead = dns_read_u16(data, offset + i + 2)?;
            cipher_suites.push(ECHCipherSuite {
                kdf_id: kdf,
                aead_id: aead,
            });
            offset += 4;
        }
        let maximum_name_length = dns_read_u8(data, offset)?;
        offset += 1;
        let public_name_length = dns_read_u8(data, offset)?;
        offset += 1;
        let public_name1 = dns_parse_slice(data, offset..offset + public_name_length as usize)?;

        let _extensions_length = dns_read_u16(data, offset)?;
        let mut extensions = Vec::new();
        while offset < data.len() {
            let ext_data_type = dns_read_u16(data, offset)? ;
            offset += 2;
            let data = dns_parse_slice(data, offset..)?;
            extensions.push(ECHExtension { extension_type : ext_data_type, extension_data: Vec::from(data) });

        }

        Ok(Self {
            config_id,
            kem_id,
            hpke_public_key: Vec::from(pub_key),
            cipher_suites,
            maximum_name_length,
            public_name: String::from_utf8_lossy(public_name1).parse().unwrap(),
            extensions,
        })
    }
}

impl Display for ECHConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ver:{:x},len:{},contents:{}",
            self.version, self.length, self.contents
        )
    }
}

impl Display for ECHConfigContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,
               "config_id:{}, kem_id:{}, pub_key:{}, cipher:[{}], max_name_len:{}, pub_name:{}, exts:{}",
               self.config_id,
               self.kem_id,
               hex::encode(&self.hpke_public_key),
               self.cipher_suites.iter()
                   .map(|cs| format!("{cs}"))
                   .collect::<Vec<_>>()
                   .join(","),
               self.maximum_name_length,
               self.public_name,
               self.extensions.len())
    }
}

impl Display for ECHCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kdf:{},aead:{}", self.kdf_id, self.aead_id)
    }
}


impl Display for ECHExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ext_type:{}, ext_data:{}", self.extension_type, hex::encode(&self.extension_data))
    }
}

#[derive(Debug)]
pub enum EchParseError {
    InsufficientLength,
    InvalidPublicName,
}
