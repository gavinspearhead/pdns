dig +nocmd +nocomments +noquestion +nostats +multiline soa dns.netmeister.org. $1
dig +short a a.dns.netmeister.org. $1
dig +short txt a.dns.netmeister.org. $1
dig +short aaaa aaaa.dns.netmeister.org. $1
dig +short txt aaaa.dns.netmeister.org. $1
dig +short a6 a6.dns.netmeister.org. $1
dig +short a6 a6-prefix.dns.netmeister.org. $1
dig +short txt a6.dns.netmeister.org. $1
dig +short afsdb afsdb.dns.netmeister.org. $1
dig +short txt afsdb.dns.netmeister.org. $1
dig +short amtrelay amtrelay.dns.netmeister.org. $1
dig +short txt amtrelay.dns.netmeister.org. $1
dig +short txt $$.dns.netmeister.org. $1
dig +short txt ${RANDOM}.dns.netmeister.org. $1
dig +short txt not-actually-found-in-the-zone.dns.netmeister.org. $1
dig +short apl apl.dns.netmeister.org. $1
dig +short txt apl.dns.netmeister.org. $1
dig +short atma atma.dns.netmeister.org. $1
dig +short txt atma.dns.netmeister.org. $1
dig +short avc avc.dns.netmeister.org. $1
dig +short txt avc.dns.netmeister.org. $1
dig +short caa caa.dns.netmeister.org. $1
dig +short txt caa.dns.netmeister.org. $1
dig +short cdnskey cdnskey.dns.netmeister.org. $1
dig +short txt cdnskey.dns.netmeister.org. $1
dig +short cds cds.dns.netmeister.org. $1
dig +short txt cds.dns.netmeister.org. $1
dig +nocmd +nocomments +noquestion +nostats +multiline cert cert.dns.netmeister.org.  $1
dig +short txt cert.dns.netmeister.org. | more $1
dig +short cname cname.dns.netmeister.org. $1
dig +short txt cname.dns.netmeister.org $1
dig +short cname cname-loop.dns.netmeister.org. $1
dig +short csync csync.dns.netmeister.org. $1
dig +short txt csync.dns.netmeister.org. $1
dig +short dhcid dhcid.dns.netmeister.org. $1
dig +short txt dhcid.dns.netmeister.org. $1
dig +short dlv dlv.dns.netmeister.org. $1
dig +short txt dlv.dns.netmeister.org. $1
dig +short dname dname.dns.netmeister.org. $1
dig +short txt dname.dns.netmeister.org. $1
dig +short txt a.dname.dns.netmeister.org. $1
dig +short dnskey dnskey.dns.netmeister.org. $1
dig +short txt dnskey.dns.netmeister.org. $1
dig +short doa doa.dns.netmeister.org. $1
dig +short txt doa.dns.netmeister.org. $1
dig +short ds ds.dns.netmeister.org. $1
dig +short txt ds.dns.netmeister.org. $1
dig +short eid eid.dns.netmeister.org.  $1
dig +short txt eid.dns.netmeister.org.  $1
dig +short eui48 eui48.dns.netmeister.org. $1
dig +short txt eui48.dns.netmeister.org. $1
dig +short eui64 eui64.dns.netmeister.org. $1
dig +short txt eui64.dns.netmeister.org. $1
dig +short gpos gpos.dns.netmeister.org. $1
dig +short txt gpos.dns.netmeister.org. $1
dig +short hinfo hinfo.dns.netmeister.org. $1
dig +short txt hinfo.dns.netmeister.org. $1
dig +short @ns3.cloudflare.com  any cloudflare.com $1
dig +nocmd +nocomments +noquestion +nostats +multiline hip hip.dns.netmeister.org.  $1
dig +short txt hip.dns.netmeister.org.  $1
dig +nocmd +nocomments +noquestion +nostats +multiline TYPE65 https.dns.netmeister.org.  $1
dig +short txt https.dns.netmeister.org.  $1
dig +short ipseckey ipseckey.dns.netmeister.org.  $1
dig +short txt ipseckey.dns.netmeister.org.  $1
dig +short isdn isdn.dns.netmeister.org.  $1
dig +short txt isdn.dns.netmeister.org.  $1
dig +short key key.dns.netmeister.org.  $1
dig +short txt key.dns.netmeister.org.  $1
dig +short kx kx.dns.netmeister.org.  $1
dig +short txt kx.dns.netmeister.org.  $1
dig +short l32 l32.dns.netmeister.org.  $1
dig +short txt l32.dns.netmeister.org.  $1
dig +short l64 l64.dns.netmeister.org.  $1
dig +short txt l64.dns.netmeister.org.  $1
dig +short loc loc.dns.netmeister.org.  $1
dig +short txt loc.dns.netmeister.org.  $1
dig +short lp lp.dns.netmeister.org.  $1
dig +short txt lp.dns.netmeister.org.  $1
dig +short mb mb.dns.netmeister.org.  $1
dig +short txt mb.dns.netmeister.org.  $1
dig +short mg mg.dns.netmeister.org.  $1
dig +short txt mg.dns.netmeister.org.  $1
dig +short minfo minfo.dns.netmeister.org.  $1
dig +short txt minfo.dns.netmeister.org.  $1
dig +short mr mr.dns.netmeister.org.  $1
dig +short txt mr.dns.netmeister.org.  $1
dig +short mx mx.dns.netmeister.org.  $1
dig +short txt mx.dns.netmeister.org.  $1
dig +short naptr naptr.dns.netmeister.org.  $1
dig +short txt naptr.dns.netmeister.org.  $1
dig +short nid nid.dns.netmeister.org.  $1
dig +short txt nid.dns.netmeister.org.  $1
dig +short nimloc nimloc.dns.netmeister.org.  $1
dig +short txt nimloc.dns.netmeister.org.  $1
dig +short ninfo ninfo.dns.netmeister.org.  $1
dig +short txt ninfo.dns.netmeister.org.  $1
dig +short ns ns.dns.netmeister.org.  $1
dig +short txt ns.dns.netmeister.org.  $1
dig +short nsap nsap.dns.netmeister.org.  $1
dig +short txt nsap.dns.netmeister.org.  $1
dig +short nsap-ptr nsap-ptr.dns.netmeister.org.  $1
dig +short txt nsap-ptr.dns.netmeister.org.  $1
dig +short nsec nsec.dns.netmeister.org.  $1
dig +short txt nsec.dns.netmeister.org.  $1
dig +dnssec nsec3 nsec3.dns.netmeister.org. $1
dig +dnssec xxx.kmachine.nl  $1
dig +short txt nsec3.dns.netmeister.org.  $1
dig +short nsec3param nsec3param.dns.netmeister.org.  $1
dig +short txt nsec3param.dns.netmeister.org.  $1
dig +dnssec nsec3 nsec3.dns.netmeister.org.  $1
dig +short txt next.nsec3.dns.netmeister.org. $1
dig +dnssec +nocmd +nocomments +noquestion +nostats nsec3 next.nsec3.dns.netmeister.org.  $1
dig +short null null.dns.netmeister.org $1
dig +short null.dns.netmeister.org txt $1
dig +short nxt nxt.dns.netmeister.org.  $1
dig +short txt nxt.dns.netmeister.org.  $1
dig +multiline +nocmd +nocomments +noquestion +nostats openpgpkey openpgpkey.dns.netmeister.org. $1
dig +short txt openpgpkey.dns.netmeister.org.  $1
dig +multiline +nocmd +nocomments +noquestion +nostats openpgpkey f6d6048431f8b67313b5b8011e0be5b03f21b4458a7e67f3fb298900._openpgpkey.netmeister.org.                            $1
dig +short ptr ptr.dns.netmeister.org. $1
dig +short txt ptr.dns.netmeister.org. $1
dig +short ptr 166.84.7.99 $1
dig +short ptr 2001:470:30:84:e276:63ff:fe72:3900 $1
dig +short ptr 99.7.84.166.in-addr.arpa $1
dig +short ptr 0.0.9.3.2.7.e.f.f.f.3.6.6.7.2.e.4.8.0.0.0.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa $1
dig +short px px.dns.netmeister.org. $1
dig +short txt px.dns.netmeister.org. $1
dig +short rp rp.dns.netmeister.org. $1
dig +short txt rp.dns.netmeister.org. $1
dig +short txt contact.netmeister.org. $1
dig +multiline +nocmd +nocomments +noquestion +nostats rrsig rrsig.dns.netmeister.org. $1
dig +short txt rrsig.dns.netmeister.org. $1
dig +short rt rt.dns.netmeister.org  $1
dig +short txt rt.dns.netmeister.org  $1
dig +short sink sink.dns.netmeister.org  $1
dig +short txt sink.dns.netmeister.org  $1
dig +short smimea smimea.dns.netmeister.org  $1
dig +short txt smimea.dns.netmeister.org  $1
dig +multiline +nocmd +nocomments +noquestion +nostats soa soa.dns.netmeister.org. $1
dig +short txt soa.dns.netmeister.org  $1
dig +short spf spf.dns.netmeister.org  $1
dig +short txt spf.dns.netmeister.org  $1
dig +short srv srv.dns.netmeister.org  $1
dig +short txt srv.dns.netmeister.org  $1
dig +short sshfp sshfp.dns.netmeister.org  $1
dig +short txt sshfp.dns.netmeister.org  $1
dig +multiline +nocmd +nocomments +noquestion +nostats TYPE64 svcb.dns.netmeister.org. $1
dig +short txt svcb.dns.netmeister.org. $1
dig +short ta ta.dns.netmeister.org.  $1
dig +short txt ta.dns.netmeister.org.  $1
dig +short talink talink.dns.netmeister.org.  $1
dig +short talink _talink1.dns.netmeister.org.  $1
dig +short talink _talink2.dns.netmeister.org.  $1
dig +short txt talink.dns.netmeister.org.  $1
dig +short tlsa tlsa.dns.netmeister.org.  $1
dig +short txt tlsa.dns.netmeister.org.  $1
dig +multiline +nocmd +nocomments +noquestion +nostats -y hmac-sha256:tsig.dns.netmeister.org:g3VNiujhmzuXdEVTV0SiVG0ad2ViTI/AtiPMCDjj77s=  tsig tsig.dns.netmeister.org. $1
dig +multiline +nocmd +nocomments +noquestion +nostats  -y hmac-sha256:tsig.dns.netmeister.org:d2hhdGV2ZXIK tsig tsig.dns.netmeister.org. $1
dig +short txt tsig.dns.netmeister.org. $1 
dig +short txt txt.dns.netmeister.org. $1
dig +short txt jschauma._pka.netmeister.org. $1
dig +short txt netmeister.org. $1
dig +short txt 2021._domainkey.netmeister.org. $1
dig +short txt _dmarc.netmeister.org. $1
dig +short txt _mta-sts.netmeister.org. $1
dig +short txt _smtp._tls.netmeister.org. $1
dig +short uri uri.dns.netmeister.org. $1
dig +short txt uri.dns.netmeister.org. $1
dig +short wks wks.dns.netmeister.org. $1
dig +short txt wks.dns.netmeister.org. $1
dig +short x25 x25.dns.netmeister.org. $1
dig +short txt x25.dns.netmeister.org. $1
dig +short zonemd zonemd.dns.netmeister.org. $1
dig +short txt zonemd.dns.netmeister.org. $1
dig +short @f.root-servers.net hostname.bind chaos txt $1
dig +nocmd +nocomments +noquestion +nostats +multiline any any.dns.netmeister.org. $1
dig www.dns-as.org avc $1
dig resolver64.dns4all.eu resinfo $1
dig resolver.dns4all.eu resinfo $1
dig _dns.resolver.arpa svcb @1.1.1.1
dig _dns.resolver.arpa svcb @8.8.8.8
dig _dns.resolver.arpa svcb @9.9.9.9
dig https defo.ie
dig zagreb._deleg.nlnetlabs.nl. SVCB
dig type666 xs4all.nl

