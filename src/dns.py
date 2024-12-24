#! /usr/bin/env python3.10

from scapy.all import DNS, DNSQR, IP, sr1, UDP, Raw, raw, DNSRR,send

domains = [
"www.google.com",
 "faß.de",
# "Ⱥbby.com",
   "aoheuntahuanthuaonshuaonetuhaenuthaoentuhaontuhaoenuhaonteuhaontehu.com",
     "nu..nl",
       "",
       'root',
".nl",
"nu.nl..",
"nu,nl",
#"https://nu.nl",
"\x00",
"google.com",
"a.t.t.t.t.t.t.t.t.t.n.n.n.t.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.u.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.com"
]

servers = [
 '1.1.1.1',
 '80.80.80.80',
 '9.9.9.9',
 '8.8.8.8',
"192.168.178.21",
"192.168.178.1",
 "88.221.162.33",
 "46.166.189.67",
 "77.249.205.162",
 "84.243.234.180",
"46.183.248.45",
 "212.71.8.234"	,
 "77.68.94.230",
 "94.30.109.224",
]

server = '1.1.1.1'
# server = '80.80.80.80'
# server = '9.9.9.9'
# server = '8.8.8.8'
# server="192.168.178.21"
# server="192.168.178.1"
# server = "88.221.162.33"
# server = "46.166.189.67"
# server = "77.249.205.162"
# server = "84.243.234.180"
# server ="46.183.248.45"
# server = "212.71.8.234"
# server = "77.68.94.230"
# server = "94.30.109.224"

q_type= 1
q_class = 1
dns_req1 = IP(dst=server)/UDP(dport=53)/DNS(rd=1, id=1, tc=0,ad=1, cd=1, qd=DNSQR(qname=domains[0], qtype=q_type, qclass=q_class))
print(dns_req1)
answer = sr1(dns_req1, verbose=1)
print(answer[DNSRR])
for server in servers :
    c = bytearray(raw(answer[DNSRR]))
    a = bytearray(raw(dns_req1[DNS]))
    b = bytearray(raw(dns_req1[DNSQR]))
    b[12] = ord('2');
   # a[25] = 0xc0; 
   # a[26] = 0x0c; 
    #a[30] = 0x01; 
    #a[2] = 0x81
    a[5] = 1
    a[7]=1

    print(b)
    print(a)
    print(c[0:29])
    #print(a)
    #print(type(a))
    print()
    print()
    e = bytearray([0xc0, 0x0c, 0, 1, 0, 1, 0, 0,0, 0x34,0, 4, 0x4d, 0xac, 0x0f, 0x41])
    d = a+e

    dns_req=IP(dst=server)/UDP(dport=53)/Raw(load=d)
    print(dns_req)
    send(dns_req, verbose=1)
    answer.show()



dns_req = IP(dst='1.1.1.1')/UDP(dport=53)/DNS(rd=1,z=1, id=1, qd=DNSQR(qname="faß.de", qtype=1, qclass=1))
answer = sr1(dns_req, verbose=0)
answer.show()

dns_req = IP(dst='1.1.1.1')/UDP(dport=53)/DNS(rd=1,z=1, id=1, qd=DNSQR(qname="Ⱥbby.com", qtype=1, qclass=1))
answer = sr1(dns_req, verbose=0)
answer.show()
###