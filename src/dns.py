#! /usr/bin/env python3.10

from scapy.all import DNS, DNSQR, IP, sr1, UDP, Raw, raw, DNSRR,send

domains = [
    "xn--ABCDEF.tjeb.nl",
    "www.google.com",
    "faß.de",
    # "Ⱥbby.com",
    "aoheuntahuanthuaonshuaoneuuuutuhaenutheuaeuaeaoentuhaoeuaeontuh.aoenuhaonteuhaontehu.com",
    "nu..nl",
    "",
    'root',
    ".nu.nl"
    ".nl",
    "nu.nl..",
    "nu,nl",
    "https://nu.nl",
    "\x00",
    "google.com",
    "a.t.t.t.t.t.t.t.t.t.n.n.n.t.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.u.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.n.com"
]

servers = [
#"192.168.178.21",
# '1.1.1.1',
# '80.80.80.80',
 '9.9.9.9',
# '8.8.8.8',
#"192.168.178.1",
# "88.221.162.33",
# "46.166.189.67",
# "77.249.205.162",
# "84.243.234.180",
#"46.183.248.45",
# "212.71.8.234"	,
# "77.68.94.230",
# "94.30.109.224",
]

#server = '1.1.1.1'
# server = '80.80.80.80'
# server = '9.9.9.9'
server = '8.8.8.8'
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
for domain in domains:
    dns_req1 = IP(dst=server)/UDP(dport=53)/DNS(rd=1, id=1, tc=0,ad=1, cd=1, qd=DNSQR(qname=domain, qtype=q_type, qclass=q_class))
    print(dns_req1)
    answer = sr1(dns_req1, verbose=1)
    try:
        print(answer[DNSRR])
    except: pass
    print("loop")
    for server in servers :
        try:
           # c = bytearray(raw(answer[DNSRR]))
            a = bytearray(raw(dns_req1[DNS]))
            #b = bytearray(raw(dns_req1[DNSQR]))
            print(len(domain))
            if len(domain)> 63:
                print("updating domainnam")
                a[76] = ord('X')
            #a[12] = ord('')
            a[28] = 0x01
            #a[len(domain) + 17] = 0xff
            #A[30] = 0x01
            #a[32] = 0x81
           #a[5] = 1
          # a[7]=1

            #print(b)
            print(a)
           # print(c[0:29])
        #print(a)
        #print(type(a))
     #   e = bytearray([0xc0, 0x0c, 0, 1, 0, 1, 0, 0,0, 0x34,0, 4, 0x4d, 0xac, 0x0f, 0x41])
     #   d = a+e
            #d =a
            dns_req=IP(dst=server)/UDP(dport=53)/Raw(load=a)
            print(dns_req)
            send(dns_req, verbose=1)
            print("Answer:")
            answer.show()
        except Exception as e: print(e)
    input("Press Enter to continue...")



dns_req = IP(dst='1.1.1.1')/UDP(dport=53)/DNS(rd=1,z=1, id=1, qd=DNSQR(qname="faß.de", qtype=1, qclass=1))
answer = sr1(dns_req, verbose=0)
answer.show()

dns_req = IP(dst='1.1.1.1')/UDP(dport=53)/DNS(rd=1,z=1, id=1, qd=DNSQR(qname="Ⱥbby.com", qtype=1, qclass=1))
answer = sr1(dns_req, verbose=0)
answer.show()
###
