use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Clone, Default)]
pub struct ECHConfig {
    version: u16,
    length: u16,
    contents: ECHConfigContents,
}

#[derive(Debug, Clone, Default)]
pub struct ECHConfigContents {
    cipher_suite: ECHCipherSuite,
    config_id: u8,
    hpke_public_key: Vec<u8>,
    maximum_name_length: u8,
    public_name: String,
    extensions: Vec<ECHExtension>,
}

#[derive(Debug, Clone, Default)]
pub struct ECHCipherSuite {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
}

#[derive(Debug, Clone, Default)]
pub struct ECHExtension {
    extension_type: u16,
    extension_data: Vec<u8>,
}

impl ECHConfig {
    pub fn parse(data: &[u8]) -> Result<Vec<Self>, ParseError> {
        if data.len() < 4 {
            return Err(ParseError::InsufficientLength);
        }
        let mut configs = Vec::new();
        let mut offset = 0;

        // Parse the outer ECHConfigList
        let total_length = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;

        if data.len() < (offset + total_length as usize) {
            return Err(ParseError::InsufficientLength);
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
            return Err(ParseError::InsufficientLength);
        }

        let version = BigEndian::read_u16(&data[0..2]);
        let length = BigEndian::read_u16(&data[2..4]);

        if data.len() < (4 + length as usize) {
            return Err(ParseError::InsufficientLength);
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
        let mut offset = 1;

        // Parse cipher suite
        if data.len() < 6 {
            return Err(ParseError::InsufficientLength);
        }

        let cipher_suite = ECHCipherSuite {
            kem_id: BigEndian::read_u16(&data[offset..offset + 2]),
            kdf_id: BigEndian::read_u16(&data[offset + 2..offset + 4]),
            aead_id: BigEndian::read_u16(&data[offset + 4..offset + 6]),
        };
        offset += 6;

        // Parse config_id
        if data.len() < offset + 1 {
            return Err(ParseError::InsufficientLength);
        }
        let config_id = data[offset];
        offset += 1;

        // Parse HPKE public key
        if data.len() < offset + 2 {
            return Err(ParseError::InsufficientLength);
        }
        let key_length = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;

        if data.len() < offset + key_length as usize {
            return Err(ParseError::InsufficientLength);
        }
        let hpke_public_key = data[offset..offset + key_length as usize].to_vec();
        offset += key_length as usize;

        // Parse maximum_name_length
        if data.len() < offset + 1 {
            return Err(ParseError::InsufficientLength);
        }
        let maximum_name_length = data[offset];
        offset += 1;

        // Parse public_name
        if data.len() < offset + 2 {
            return Err(ParseError::InsufficientLength);
        }
        let name_length = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;

        if data.len() < offset + name_length as usize {
            return Err(ParseError::InsufficientLength);
        }
        let public_name = String::from_utf8(data[offset..offset + name_length as usize].to_vec())
            .map_err(|_| ParseError::InvalidPublicName)?;
        offset += name_length as usize;

        // Parse extensions
        if data.len() < offset + 2 {
            return Err(ParseError::InsufficientLength);
        }
        let extensions_size = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;

        if data.len() < offset + extensions_size as usize {
            return Err(ParseError::InsufficientLength);
        }

        let mut extensions = Vec::new();
        let mut extensions_offset = 0;
        while extensions_offset < extensions_size as usize {
            if data.len() < offset + extensions_offset + 4 {
                return Err(ParseError::InsufficientLength);
            }

            let extension_type = BigEndian::read_u16(&data[offset + extensions_offset..]);
            extensions_offset += 2;

            let extension_length = BigEndian::read_u16(&data[offset + extensions_offset..]);
            extensions_offset += 2;

            if data.len() < offset + extensions_offset + extension_length as usize {
                return Err(ParseError::InsufficientLength);
            }

            let extension_data = data[offset + extensions_offset
                ..offset + extensions_offset + extension_length as usize]
                .to_vec();
            extensions_offset += extension_length as usize;

            extensions.push(ECHExtension {
                extension_type,
                extension_data,
            });
        }

        Ok(Self {
            cipher_suite,
            config_id,
            hpke_public_key,
            maximum_name_length,
            public_name,
            extensions,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    InsufficientLength,
    InvalidPublicName,
}
