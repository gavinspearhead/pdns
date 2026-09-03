use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use strum_macros::EnumIter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, Serialize, Deserialize, Hash)]
pub(crate) enum ParseErrorType {
    InvalidUdpHeader,
    InvalidTcpHeader,
    InvalidIpv6Header,
    InvalidIpv4Header,
    InvalidDnsPacket,
    InvalidTcpPacket,
    InvalidUdpPacket,
    InvalidIpVersion,
    PacketTooSmall,
    UnknownPacketType,
    UnknownLinkType,
    UnknownFrameType,
    InvalidPacketIndex,
    InvalidTimestamp,
    UnknownProtocol,
    UnknownAddressFamily,
    InvalidResourceRecord,
    InvalidNsec3param,
    InvalidParameter,
    InvalidDomainName,
    InvalidData,
    InvalidIpaddress,
    SkippedMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub error_type: ParseErrorType,
    error_str: String,
    value: String,
}

impl ParseError {
    pub fn new(err_t: ParseErrorType, val: &str) -> ParseError {
        let s = match err_t {
            ParseErrorType::InvalidUdpHeader => "Invalid UDP Header",
            ParseErrorType::InvalidTcpHeader => "Invalid TCP Header",
            ParseErrorType::InvalidTcpPacket => "Invalid TCP Packet",
            ParseErrorType::InvalidUdpPacket => "Invalid UDP Packet",
            ParseErrorType::InvalidIpv6Header => "Invalid IPv6 Header",
            ParseErrorType::InvalidIpv4Header => "Invalid IPv4 Header",
            ParseErrorType::InvalidDnsPacket => "Invalid DNS Packet",
            ParseErrorType::InvalidIpVersion => "Invalid IP Version",
            ParseErrorType::PacketTooSmall => "Packet Too Small",
            ParseErrorType::UnknownPacketType => "Unknown Packet Type",
            ParseErrorType::UnknownLinkType => "Unknown Link Type",
            ParseErrorType::UnknownProtocol => "Unknown protocol",
            ParseErrorType::UnknownFrameType => "Unknown Frame Type",
            ParseErrorType::UnknownAddressFamily => "Unknown Address Family",
            ParseErrorType::InvalidPacketIndex => "Invalid packet index",
            ParseErrorType::InvalidTimestamp => "Invalid timestamp",
            ParseErrorType::InvalidResourceRecord => "Invalid resource record",
            ParseErrorType::InvalidNsec3param => "Invalid NSEC3PARAM format",
            ParseErrorType::InvalidParameter => "Invalid Parameter",
            ParseErrorType::InvalidDomainName => "Invalid domain name",
            ParseErrorType::InvalidData => "Invalid Data",
            ParseErrorType::InvalidIpaddress => "Invalid IP Address",
            ParseErrorType::SkippedMessage => "Skipped Message",
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
    InvalidRr,
    InvalidParam,
    InvalidClass,
    InvalidReplyType,
    InvalidOpcode,
    InvalidExtendedErrorCode,
    InvalidExtendedOptionCode,
}

#[derive(Debug, Clone)]
pub struct DnsError {
    //error_type: DNS_Error_Type,
    error_str: String,
    value: String,
}

impl DnsError {
    pub(crate) fn new(err_t: DnsErrorType, val: &str) -> DnsError {
        let s = match err_t {
            DnsErrorType::InvalidClass => "Invalid Class",
            DnsErrorType::InvalidParam => "Invalid Parameter",
            DnsErrorType::InvalidRr => "Invalid RR Type",
            DnsErrorType::InvalidReplyType => "Invalid Reply type",
            DnsErrorType::InvalidOpcode => "Invalid Opcode",
            DnsErrorType::InvalidExtendedErrorCode => "Invalid Extended Error Code",
            DnsErrorType::InvalidExtendedOptionCode => "Invalid Extended Option Code",
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
