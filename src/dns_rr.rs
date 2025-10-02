use crate::dns_rr_type::DNS_RR_type;
use crate::errors::ParseErrorType::Invalid_Resource_Record;
use crate::errors::Parse_error;
use crate::rr::rr_a::RR_A;
use crate::rr::rr_a6::RR_A6;
use crate::rr::rr_aaaa::RR_AAAA;
use crate::rr::rr_afsdb::RR_AFSDB;
use crate::rr::rr_amtrelay::RR_AMTRELAY;
use crate::rr::rr_apl::RR_APL;
use crate::rr::rr_atma::RR_ATMA;
use crate::rr::rr_avc::RR_AVC;
use crate::rr::rr_caa::RR_CAA;
use crate::rr::rr_cdnskey::RR_CDNSKEY;
use crate::rr::rr_cds::RR_CDS;
use crate::rr::rr_cert::RR_CERT;
use crate::rr::rr_cla::RR_CLA;
use crate::rr::rr_uri::RR_URI;
use tracing::debug;

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
use crate::rr::rr_wallet::RR_WALLET;
use crate::rr::rr_wks::RR_WKS;
use crate::rr::rr_x25::RR_X25;
use crate::rr::rr_zonemd::RR_ZONEMD;

pub(crate) fn dns_parse_rdata(
    rdata: &[u8],
    rrtype: DNS_RR_type,
    packet: &[u8],
    offset_in: usize,
) -> Result<String, Parse_error> {
    match rrtype {
        DNS_RR_type::A => Ok(RR_A::parse(rdata)?.to_string()),
        DNS_RR_type::A6 => Ok(RR_A6::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::AAAA => Ok(RR_AAAA::parse(rdata)?.to_string()),
        DNS_RR_type::AFSDB => Ok(RR_AFSDB::parse(rdata)?.to_string()),
        DNS_RR_type::AMTRELAY => Ok(RR_AMTRELAY::parse(rdata, packet, offset_in)?.to_string()),
        DNS_RR_type::APL => Ok(RR_APL::parse(rdata)?.to_string()),
        DNS_RR_type::ATMA => Ok(RR_ATMA::parse(rdata)?.to_string()),
        DNS_RR_type::AVC => Ok(RR_AVC::parse(rdata)?.to_string()),
        DNS_RR_type::CAA => Ok(RR_CAA::parse(rdata)?.to_string()),
        DNS_RR_type::CDNSKEY => Ok(RR_CDNSKEY::parse(rdata)?.to_string()),
        DNS_RR_type::CDS => Ok(RR_CDS::parse(rdata)?.to_string()),
        DNS_RR_type::CERT => Ok(RR_CERT::parse(rdata)?.to_string()),
        DNS_RR_type::CLA => Ok(RR_CLA::parse(rdata)?.to_string()),
        DNS_RR_type::CNAME => Ok(RR_CNAME::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::CSYNC => Ok(RR_CSYNC::parse(rdata)?.to_string()),
        DNS_RR_type::DHCID => Ok(RR_DHCID::parse(rdata)?.to_string()),
        DNS_RR_type::DLV => Ok(RR_DLV::parse(rdata)?.to_string()),
        DNS_RR_type::DNAME => Ok(RR_DNAME::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::DNSKEY => Ok(RR_DNSKEY::parse(rdata)?.to_string()),
        DNS_RR_type::DOA => Ok(RR_DOA::parse(rdata)?.to_string()),
        DNS_RR_type::DS => Ok(RR_DS::parse(rdata)?.to_string()),
        DNS_RR_type::DSYNC => Ok(RR_DSYNC::parse(rdata)?.to_string()),
        DNS_RR_type::EID => Ok(RR_EID::parse(rdata)?.to_string()),
        DNS_RR_type::EUI48 => Ok(RR_EUI48::parse(rdata)?.to_string()),
        DNS_RR_type::EUI64 => Ok(RR_EUI64::parse(rdata)?.to_string()),
        DNS_RR_type::GID => Ok(RR_GID::parse(rdata)?.to_string()),
        DNS_RR_type::GPOS => Ok(RR_GPOS::parse(rdata)?.to_string()),
        DNS_RR_type::HINFO => Ok(RR_HINFO::parse(rdata)?.to_string()),
        DNS_RR_type::HHIT   => Ok(RR_HHIT::parse(rdata)?.to_string()),
        DNS_RR_type::HIP => Ok(RR_HIP::parse(rdata)?.to_string()),
        DNS_RR_type::HTTPS => Ok(RR_HTTPS::parse(rdata)?.to_string()),
        DNS_RR_type::IPN => Ok(RR_IPN::parse(rdata)?.to_string()),
        DNS_RR_type::IPSECKEY => Ok(RR_IPSECKEY::parse(rdata)?.to_string()),
        DNS_RR_type::ISDN => Ok(RR_ISDN::parse(rdata)?.to_string()),
        DNS_RR_type::KEY => Ok(RR_KEY::parse(rdata)?.to_string()),
        DNS_RR_type::KX => Ok(RR_KX::parse(rdata)?.to_string()),
        DNS_RR_type::L32 => Ok(RR_L32::parse(rdata)?.to_string()),
        DNS_RR_type::L64 => Ok(RR_L64::parse(rdata)?.to_string()),
        DNS_RR_type::LOC => Ok(RR_LOC::parse(rdata)?.to_string()),
        DNS_RR_type::LP => Ok(RR_LP::parse(rdata)?.to_string()),
        DNS_RR_type::MAILA => Ok(RR_MAILA::parse(rdata)?.to_string()),
        DNS_RR_type::MAILB => Ok(RR_MAILB::parse(rdata)?.to_string()),
        DNS_RR_type::MB => Ok(RR_MB::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::MD => Ok(RR_MD::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::MF => Ok(RR_MF::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::MG => Ok(RR_MG::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::MINFO => Ok(RR_MINFO::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::MR => Ok(RR_MR::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::MX => Ok(RR_MX::parse(rdata, packet, offset_in)?.to_string()),
        DNS_RR_type::NAPTR => Ok(RR_NAPTR::parse(rdata)?.to_string()),
        DNS_RR_type::NID => Ok(RR_NID::parse(rdata)?.to_string()),
        DNS_RR_type::NIMLOC => Ok(RR_NIMLOC::parse(rdata)?.to_string()),
        DNS_RR_type::NINFO => Ok(RR_NINFO::parse(rdata)?.to_string()),
        DNS_RR_type::NS => Ok(RR_NS::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::NSAP => Ok(RR_NSAP::parse(rdata)?.to_string()),
        DNS_RR_type::NSAP_PTR => Ok(RR_NSAP_PTR::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::NSEC => Ok(RR_NSEC::parse(rdata)?.to_string()),
        DNS_RR_type::NSEC3 => Ok(RR_NSEC3::parse(rdata)?.to_string()),
        DNS_RR_type::NSEC3PARAM => Ok(RR_NSEC3PARAM::parse(rdata)?.to_string()),
        DNS_RR_type::NXNAME => Ok(RR_NXNAME::parse(rdata)?.to_string()),
        DNS_RR_type::NXT => Ok(RR_NXT::parse(rdata, packet, offset_in)?.to_string()),
        DNS_RR_type::NULL => Ok(RR_NULL::parse(rdata)?.to_string()),
        DNS_RR_type::OPENPGPKEY => Ok(RR_OPENPGPKEY::parse(rdata)?.to_string()),
        DNS_RR_type::Private => Ok(RR_Private::parse(rdata)?.to_string()),
        DNS_RR_type::PTR => Ok(RR_PTR::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::PX => Ok(RR_PX::parse(rdata)?.to_string()),
        DNS_RR_type::RESINFO => Ok(RR_RESINFO::parse(rdata)?.to_string()),
        DNS_RR_type::RKEY => Ok(RR_RKEY::parse(rdata)?.to_string()),
        DNS_RR_type::RP => Ok(RR_RP::parse(rdata)?.to_string()),
        DNS_RR_type::RRSIG => Ok(RR_RRSIG::parse(rdata)?.to_string()),
        DNS_RR_type::RT => Ok(RR_RT::parse(rdata)?.to_string()),
        DNS_RR_type::SIG => Ok(RR_SIG::parse(rdata)?.to_string()),
        DNS_RR_type::SINK => Ok(RR_SINK::parse(rdata)?.to_string()),
        DNS_RR_type::SMIMEA => Ok(RR_SMIMEA::parse(rdata)?.to_string()),
        DNS_RR_type::SOA => Ok(RR_SOA::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::SPF => Ok(RR_SPF::parse(rdata)?.to_string()),
        DNS_RR_type::SRV => Ok(RR_SRV::parse(rdata)?.to_string()),
        DNS_RR_type::SSHFP => Ok(RR_SSHFP::parse(rdata)?.to_string()),
        DNS_RR_type::SVCB => Ok(RR_SVCB::parse(rdata)?.to_string()),
        DNS_RR_type::TA => Ok(RR_TA::parse(rdata)?.to_string()),
        DNS_RR_type::TALINK => Ok(RR_TALINK::parse(packet, offset_in)?.to_string()),
        DNS_RR_type::TKEY => Ok(RR_TKEY::parse(rdata)?.to_string()),
        DNS_RR_type::TLSA => Ok(RR_TLSA::parse(rdata)?.to_string()),
        DNS_RR_type::TSIG => Ok(RR_TSIG::parse(rdata)?.to_string()),
        DNS_RR_type::TXT => Ok(RR_TXT::parse(rdata)?.to_string()),
        DNS_RR_type::UID => Ok(RR_UID::parse(rdata)?.to_string()),
        DNS_RR_type::UINFO => Ok(RR_UINFO::parse(rdata)?.to_string()),
        DNS_RR_type::URI => Ok(RR_URI::parse(rdata)?.to_string()),
        DNS_RR_type::WALLET => Ok(RR_WALLET::parse(rdata)?.to_string()),
        DNS_RR_type::WKS => Ok(RR_WKS::parse(rdata)?.to_string()),
        DNS_RR_type::X25 => Ok(RR_X25::parse(rdata)?.to_string()),
        DNS_RR_type::ZONEMD => Ok(RR_ZONEMD::parse(rdata)?.to_string()),
        _ => {
            debug!("Unknown RR type");
            Err(Parse_error::new(Invalid_Resource_Record, rrtype.to_str()))
        }
    }
}
