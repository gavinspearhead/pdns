use std::{error::Error, fmt};
use strum_macros::EnumIter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub(crate) enum ParseErrorType {
    Invalid_UDP_Header,
    Invalid_TCP_Header,
    Invalid_IPv6_Header,
    Invalid_IPv4_Header,
    Invalid_DNS_Packet,
    Invalid_TCP_Packet,
    Invalid_UDP_Packet,
    Invalid_IP_Version,
    Packet_Too_Small,
    Unknown_Packet_Type,
    Unknown_Link_Type,
    Unknown_Frame_Type,
    Invalid_packet_index,
    Invalid_timestamp,
    Unknown_Protocol,
    Unknown_Address_Family,
    Invalid_Resource_Record,
    Invalid_NSEC3PARAM,
    Invalid_Parameter,
    Invalid_Domain_name,
    Invalid_Data,
    Invalid_IPAddress,
    Skipped_Message,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub(crate) error_type: ParseErrorType,
    error_str: String,
    value: String,
}

impl ParseError {
    pub(crate) fn new(err_t: ParseErrorType, val: &str) -> ParseError {
        let s = match err_t {
            ParseErrorType::Invalid_UDP_Header => "Invalid UDP Header",
            ParseErrorType::Invalid_TCP_Header => "Invalid TCP Header",
            ParseErrorType::Invalid_TCP_Packet => "Invalid TCP Packet",
            ParseErrorType::Invalid_UDP_Packet => "Invalid UDP Packet",
            ParseErrorType::Invalid_IPv6_Header => "Invalid IPv6 Header",
            ParseErrorType::Invalid_IPv4_Header => "Invalid IPv4 Header",
            ParseErrorType::Invalid_DNS_Packet => "Invalid DNS Packet",
            ParseErrorType::Invalid_IP_Version => "Invalid IP Version",
            ParseErrorType::Packet_Too_Small => "Packet Too Small",
            ParseErrorType::Unknown_Packet_Type => "Unknown Packet Type",
            ParseErrorType::Unknown_Link_Type => "Unknown Link Type",
            ParseErrorType::Unknown_Protocol => "Unknown protocol",
            ParseErrorType::Unknown_Frame_Type => "Unknown Frame Type",
            ParseErrorType::Unknown_Address_Family => "Unknown Address Family",
            ParseErrorType::Invalid_packet_index => "Invalid packet index",
            ParseErrorType::Invalid_timestamp => "Invalid timestamp",
            ParseErrorType::Invalid_Resource_Record => "Invalid resource record",
            ParseErrorType::Invalid_NSEC3PARAM => "Invalid NSEC3PARAM format",
            ParseErrorType::Invalid_Parameter => "Invalid Parameter",
            ParseErrorType::Invalid_Domain_name => "Invalid domain name",
            ParseErrorType::Invalid_Data => "Invalid Data",
            ParseErrorType::Invalid_IPAddress => "Invalid IP Address",
            ParseErrorType::Skipped_Message => "Skipped Message",
        };
        ParseError {
            error_type: err_t,
            error_str: s.to_owned(),
            value: val.to_owned(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.error_str, self.value)
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        &self.error_str
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub(crate) enum DnsErrorType {
    Invalid_RR,
    Invalid_Param,
    Invalid_Class,
    Invalid_reply_type,
    Invalid_Opcode,
    Invalid_Extended_Error_Code,
    Invalid_Extended_Option_Code,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsError {
    //error_type: DNS_Error_Type,
    error_str: String,
    value: String,
}

impl DnsError {
    pub(crate) fn new(err_t: DnsErrorType, val: &str) -> DnsError {
        let s = match err_t {
            DnsErrorType::Invalid_Class => "Invalid Class",
            DnsErrorType::Invalid_Param => "Invalid Parameter",
            DnsErrorType::Invalid_RR => "Invalid RR Type",
            DnsErrorType::Invalid_reply_type => "Invalid Reply type",
            DnsErrorType::Invalid_Opcode => "Invalid Opcode",
            DnsErrorType::Invalid_Extended_Error_Code => "Invalid Extended Error Code",
            DnsErrorType::Invalid_Extended_Option_Code => "Invalid Extended Option Code",
        };

        DnsError {
            //error_type: err_t,
            error_str: s.to_owned(),
            value: val.to_owned(),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.error_str, self.value)
    }
}

impl Error for DnsError {
    fn description(&self) -> &str {
        &self.error_str
    }
}
