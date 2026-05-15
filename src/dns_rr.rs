use crate::dns_rr_type::DnsRRType;
use crate::errors::ParseError;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::rr::rr_a::RR_A;
use crate::rr::rr_a6::RR_A6;
use crate::rr::rr_aaaa::RR_AAAA;
use crate::rr::rr_afsdb::RR_AFSDB;
use crate::rr::rr_amtrelay::RR_AMTRELAY;
use crate::rr::rr_apl::RR_APL;
use crate::rr::rr_atma::RR_ATMA;
use crate::rr::rr_avc::RR_AVC;
use crate::rr::rr_brid::RR_BRID;
use crate::rr::rr_caa::RR_CAA;
use crate::rr::rr_cdnskey::RR_CDNSKEY;
use crate::rr::rr_cds::RR_CDS;
use crate::rr::rr_cert::RR_CERT;
use crate::rr::rr_cla::RR_CLA;
use crate::rr::rr_cname::RR_CNAME;
use crate::rr::rr_csync::RR_CSYNC;
use crate::rr::rr_dhcid::RR_DHCID;
use crate::rr::rr_dlv::RR_DLV;
use crate::rr::rr_dname::RR_DNAME;
use crate::rr::rr_dnskey::RR_DNSKEY;
use crate::rr::rr_doa::RR_DOA;
use crate::rr::rr_ds::RR_DS;
use crate::rr::rr_dsync::RR_DSYNC;
use crate::rr::rr_eid::RR_EID;
use crate::rr::rr_eui48::RR_EUI48;
use crate::rr::rr_eui64::RR_EUI64;
use crate::rr::rr_gid::RR_GID;
use crate::rr::rr_gpos::RR_GPOS;
use crate::rr::rr_hhit::RR_HHIT;
use crate::rr::rr_hinfo::RR_HINFO;
use crate::rr::rr_hip::RR_HIP;
pub use crate::rr::rr_https::RR_HTTPS;
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
use crate::rr::rr_mr::RR_MR;
use crate::rr::rr_mx::RR_MX;
use crate::rr::rr_naptr::RR_NAPTR;
use crate::rr::rr_nid::RR_NID;
use crate::rr::rr_nimloc::RR_NIMLOC;
use crate::rr::rr_ninfo::RR_NINFO;
use crate::rr::rr_ns::RR_NS;
use crate::rr::rr_nsap::RR_NSAP;
use crate::rr::rr_nsap_ptr::RR_NSAP_PTR;
use crate::rr::rr_nsec::RR_NSEC;
use crate::rr::rr_nsec3::RR_NSEC3;
use crate::rr::rr_nsec3param::RR_NSEC3PARAM;
use crate::rr::rr_null::RR_NULL;
use crate::rr::rr_nxname::RR_NXNAME;
use crate::rr::rr_nxt::RR_NXT;
use crate::rr::rr_openpgpkey::RR_OPENPGPKEY;
use crate::rr::rr_private::RR_Private;
use crate::rr::rr_ptr::RR_PTR;
use crate::rr::rr_px::RR_PX;
use crate::rr::rr_resinfo::RR_RESINFO;
use crate::rr::rr_rkey::RR_RKEY;
use crate::rr::rr_rp::RR_RP;
use crate::rr::rr_rrsig::RR_RRSIG;
use crate::rr::rr_rt::RR_RT;
use crate::rr::rr_sig::RR_SIG;
use crate::rr::rr_sink::RR_SINK;
use crate::rr::rr_smimea::RR_SMIMEA;
use crate::rr::rr_soa::RR_SOA;
use crate::rr::rr_spf::RR_SPF;
use crate::rr::rr_srv::RR_SRV;
use crate::rr::rr_sshfp::RR_SSHFP;
use crate::rr::rr_svcb::RR_SVCB;
use crate::rr::rr_ta::RR_TA;
use crate::rr::rr_talink::RR_TALINK;
use crate::rr::rr_tkey::RR_TKEY;
use crate::rr::rr_tlsa::RR_TLSA;
use crate::rr::rr_tsig::RR_TSIG;
pub use crate::rr::rr_txt::RR_TXT;
use crate::rr::rr_uid::RR_UID;
use crate::rr::rr_uinfo::RR_UINFO;
use crate::rr::rr_uri::RR_URI;
use crate::rr::rr_wallet::RR_WALLET;
use crate::rr::rr_wks::RR_WKS;
use crate::rr::rr_x25::RR_X25;
use crate::rr::rr_zonemd::RR_ZONEMD;
use tracing::debug;
use crate::statistics::Statistics;

pub(crate) fn dns_parse_rdata(
    rdata: &[u8],
    rrtype: DnsRRType,
    packet: &[u8],
    offset_in: usize,
    statistics: &mut Statistics
) -> Result<String, ParseError> {
    match rrtype {
        DnsRRType::A => Ok(RR_A::parse(rdata)?.to_string()),
        DnsRRType::A6 => Ok(RR_A6::parse(packet, offset_in)?.to_string()),
        DnsRRType::AAAA => Ok(RR_AAAA::parse(rdata)?.to_string()),
        DnsRRType::AFSDB => Ok(RR_AFSDB::parse(packet, offset_in)?.to_string()),
        DnsRRType::AMTRELAY => Ok(RR_AMTRELAY::parse(rdata, packet, offset_in)?.to_string()),
        DnsRRType::APL => Ok(RR_APL::parse(rdata)?.to_string()),
        DnsRRType::ATMA => Ok(RR_ATMA::parse(rdata)?.to_string()),
        DnsRRType::AVC => Ok(RR_AVC::parse(rdata)?.to_string()),
        DnsRRType::BRID => Ok(RR_BRID::parse(rdata)?.to_string()),
        DnsRRType::CAA => Ok(RR_CAA::parse(rdata)?.to_string()),
        DnsRRType::CDNSKEY => Ok(RR_CDNSKEY::parse(rdata)?.to_string()),
        DnsRRType::CDS => Ok(RR_CDS::parse(rdata)?.to_string()),
        DnsRRType::CERT => Ok(RR_CERT::parse(rdata)?.to_string()),
        DnsRRType::CLA => Ok(RR_CLA::parse(rdata)?.to_string()),
        DnsRRType::CNAME => Ok(RR_CNAME::parse(packet, offset_in)?.to_string()),
        DnsRRType::CSYNC => Ok(RR_CSYNC::parse(rdata)?.to_string()),
        DnsRRType::DHCID => Ok(RR_DHCID::parse(rdata)?.to_string()),
        DnsRRType::DLV => Ok(RR_DLV::parse(rdata)?.to_string()),
        DnsRRType::DNAME => Ok(RR_DNAME::parse(packet, offset_in)?.to_string()),
        DnsRRType::DNSKEY => Ok(RR_DNSKEY::parse(rdata)?.to_string()),
        DnsRRType::DOA => Ok(RR_DOA::parse(rdata)?.to_string()),
        DnsRRType::DS => Ok(RR_DS::parse(rdata)?.to_string()),
        DnsRRType::DSYNC => Ok(RR_DSYNC::parse(packet, offset_in)?.to_string()),
        DnsRRType::EID => Ok(RR_EID::parse(rdata)?.to_string()),
        DnsRRType::EUI48 => Ok(RR_EUI48::parse(rdata)?.to_string()),
        DnsRRType::EUI64 => Ok(RR_EUI64::parse(rdata)?.to_string()),
        DnsRRType::GID => Ok(RR_GID::parse(rdata)?.to_string()),
        DnsRRType::GPOS => Ok(RR_GPOS::parse(rdata)?.to_string()),
        DnsRRType::HINFO => Ok(RR_HINFO::parse(rdata)?.to_string()),
        DnsRRType::HHIT => Ok(RR_HHIT::parse(rdata)?.to_string()),
        DnsRRType::HIP => Ok(RR_HIP::parse(rdata, packet, offset_in)?.to_string()),
        DnsRRType::HTTPS => Ok(RR_HTTPS::parse(rdata, statistics)?.to_string()),
        DnsRRType::IPN => Ok(RR_IPN::parse(rdata)?.to_string()),
        DnsRRType::IPSECKEY => Ok(RR_IPSECKEY::parse(rdata, packet, offset_in)?.to_string()),
        DnsRRType::ISDN => Ok(RR_ISDN::parse(rdata)?.to_string()),
        DnsRRType::KEY => Ok(RR_KEY::parse(rdata)?.to_string()),
        DnsRRType::KX => Ok(RR_KX::parse(packet, offset_in)?.to_string()),
        DnsRRType::L32 => Ok(RR_L32::parse(rdata)?.to_string()),
        DnsRRType::L64 => Ok(RR_L64::parse(rdata)?.to_string()),
        DnsRRType::LOC => Ok(RR_LOC::parse(rdata)?.to_string()),
        DnsRRType::LP => Ok(RR_LP::parse(packet, offset_in)?.to_string()),
        DnsRRType::MAILA => Ok(RR_MAILA::parse(rdata)?.to_string()),
        DnsRRType::MAILB => Ok(RR_MAILB::parse(rdata)?.to_string()),
        DnsRRType::MB => Ok(RR_MB::parse(packet, offset_in)?.to_string()),
        DnsRRType::MD => Ok(RR_MD::parse(packet, offset_in)?.to_string()),
        DnsRRType::MF => Ok(RR_MF::parse(packet, offset_in)?.to_string()),
        DnsRRType::MG => Ok(RR_MG::parse(packet, offset_in)?.to_string()),
        DnsRRType::MINFO => Ok(RR_MINFO::parse(packet, offset_in)?.to_string()),
        DnsRRType::MR => Ok(RR_MR::parse(packet, offset_in)?.to_string()),
        DnsRRType::MX => Ok(RR_MX::parse(packet, offset_in)?.to_string()),
        DnsRRType::NAPTR => Ok(RR_NAPTR::parse(packet, offset_in)?.to_string()),
        DnsRRType::NID => Ok(RR_NID::parse(rdata)?.to_string()),
        DnsRRType::NIMLOC => Ok(RR_NIMLOC::parse(rdata)?.to_string()),
        DnsRRType::NINFO => Ok(RR_NINFO::parse(rdata)?.to_string()),
        DnsRRType::NS => Ok(RR_NS::parse(packet, offset_in)?.to_string()),
        DnsRRType::NSAP => Ok(RR_NSAP::parse(rdata)?.to_string()),
        DnsRRType::NSAP_PTR => Ok(RR_NSAP_PTR::parse(packet, offset_in)?.to_string()),
        DnsRRType::NSEC => Ok(RR_NSEC::parse(rdata, packet, offset_in)?.to_string()),
        DnsRRType::NSEC3 => Ok(RR_NSEC3::parse(rdata)?.to_string()),
        DnsRRType::NSEC3PARAM => Ok(RR_NSEC3PARAM::parse(rdata)?.to_string()),
        DnsRRType::NXNAME => Ok(RR_NXNAME::parse(rdata)?.to_string()),
        DnsRRType::NXT => Ok(RR_NXT::parse(rdata, packet, offset_in)?.to_string()),
        DnsRRType::NULL => Ok(RR_NULL::parse(rdata)?.to_string()),
        DnsRRType::OPENPGPKEY => Ok(RR_OPENPGPKEY::parse(rdata)?.to_string()),
        DnsRRType::Private => Ok(RR_Private::parse(rdata)?.to_string()),
        DnsRRType::PTR => Ok(RR_PTR::parse(packet, offset_in)?.to_string()),
        DnsRRType::PX => Ok(RR_PX::parse(packet, offset_in)?.to_string()),
        DnsRRType::RESINFO => Ok(RR_RESINFO::parse(rdata)?.to_string()),
        DnsRRType::RKEY => Ok(RR_RKEY::parse(rdata)?.to_string()),
        DnsRRType::RP => Ok(RR_RP::parse(packet, offset_in)?.to_string()),
        DnsRRType::RRSIG => Ok(RR_RRSIG::parse(packet, offset_in)?.to_string()),
        DnsRRType::RT => Ok(RR_RT::parse(packet, offset_in)?.to_string()),
        DnsRRType::SIG => Ok(RR_SIG::parse(packet, offset_in)?.to_string()),
        DnsRRType::SINK => Ok(RR_SINK::parse(rdata)?.to_string()),
        DnsRRType::SMIMEA => Ok(RR_SMIMEA::parse(rdata)?.to_string()),
        DnsRRType::SOA => Ok(RR_SOA::parse(packet, offset_in)?.to_string()),
        DnsRRType::SPF => Ok(RR_SPF::parse(rdata)?.to_string()),
        DnsRRType::SRV => Ok(RR_SRV::parse(packet, offset_in)?.to_string()),
        DnsRRType::SSHFP => Ok(RR_SSHFP::parse(rdata)?.to_string()),
        DnsRRType::SVCB => Ok(RR_SVCB::parse(rdata, statistics)?.to_string()),
        DnsRRType::TA => Ok(RR_TA::parse(rdata)?.to_string()),
        DnsRRType::TALINK => Ok(RR_TALINK::parse(packet, offset_in)?.to_string()),
        DnsRRType::TKEY => Ok(RR_TKEY::parse(packet, offset_in)?.to_string()),
        DnsRRType::TLSA => Ok(RR_TLSA::parse(rdata)?.to_string()),
        DnsRRType::TSIG => Ok(RR_TSIG::parse(packet, offset_in)?.to_string()),
        DnsRRType::TXT => Ok(RR_TXT::parse(rdata)?.to_string()),
        DnsRRType::UID => Ok(RR_UID::parse(rdata)?.to_string()),
        DnsRRType::UINFO => Ok(RR_UINFO::parse(rdata)?.to_string()),
        DnsRRType::URI => Ok(RR_URI::parse(rdata)?.to_string()),
        DnsRRType::WALLET => Ok(RR_WALLET::parse(rdata)?.to_string()),
        DnsRRType::WKS => Ok(RR_WKS::parse(rdata)?.to_string()),
        DnsRRType::X25 => Ok(RR_X25::parse(rdata)?.to_string()),
        DnsRRType::ZONEMD => Ok(RR_ZONEMD::parse(rdata)?.to_string()),
        _ => {
            debug!("Unknown RR type");
            Err(ParseError::new(Invalid_Resource_Record, rrtype.to_str()))
        }
    }
}
