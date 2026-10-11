#!/usr/bin/env python3
"""Generate PQC validation PCAP for post-quantum cryptography model testing.

KEMs: Kyber-512/768/1024, NTRU-HPS-2048, Classic McEliece
Sigs: Dilithium-2/3/5, Falcon-512, SPHINCS+-SHA2-128f
Classical: RSA-2048, ECDSA-P256, X25519

Traffic: PQ/classical TLS handshakes, PQ downgrade, HNDL, timing side-channel,
session replay, benign encrypted, IoT PQ.  60% labeled / 40% unlabeled.

Outputs: pqc_validation_benchmark.pcap (~120-150MB), pqc_validation_ground_truth.csv
Usage: python generate_pqc_validation_pcap.py [--flows 40000]
"""
import argparse, csv, os, random, struct, time as _time
import dpkt

random.seed(2026_02)

# PQ algorithm profiles – realistic key/signature sizes (bytes)
PQ_ALGORITHMS = {
    "Kyber-512":      {"pk": 800,  "ct": 768,  "sig": 0},
    "Kyber-768":      {"pk": 1184, "ct": 1088, "sig": 0},
    "Kyber-1024":     {"pk": 1568, "ct": 1568, "sig": 0},
    "NTRU-HPS-2048":  {"pk": 699,  "ct": 699,  "sig": 0},
    "McEliece-348864":{"pk": 261120,"ct": 128, "sig": 0},
    "Dilithium-2":    {"pk": 1312, "ct": 0, "sig": 2420},
    "Dilithium-3":    {"pk": 1952, "ct": 0, "sig": 3293},
    "Dilithium-5":    {"pk": 2592, "ct": 0, "sig": 4595},
    "Falcon-512":     {"pk": 897,  "ct": 0, "sig": 690},
    "SPHINCS+-128f":  {"pk": 32,   "ct": 0, "sig": 17088},
    # Classical (smaller)
    "RSA-2048":       {"pk": 256,  "ct": 256, "sig": 256},
    "ECDSA-P256":     {"pk": 64,   "ct": 0,  "sig": 64},
    "X25519":         {"pk": 32,   "ct": 32, "sig": 0},
}

PQC_TRAFFIC_CLASSES = {
    "PQ-Handshake-Kyber512": 0.08,  "PQ-Handshake-Kyber768": 0.10,
    "PQ-Handshake-Kyber1024": 0.06, "PQ-Handshake-NTRU": 0.04,
    "PQ-Handshake-Dilithium2": 0.06,"PQ-Handshake-Dilithium3": 0.05,
    "PQ-Handshake-Falcon512": 0.04, "PQ-Handshake-SPHINCS": 0.03,
    "Classical-TLS-RSA": 0.06,      "Classical-TLS-ECDSA": 0.06,
    "Classical-TLS-X25519": 0.06,
    "Benign-PQ-Encrypted": 0.10,    "Benign-Classical-Encrypted": 0.08,
    "Attack-PQ-Downgrade": 0.04,    "Attack-HNDL-Capture": 0.04,
    "Attack-PQ-TimingSideChannel": 0.03, "Attack-PQ-SessionReplay": 0.03,
    "IoT-PQ-Constrained": 0.04,
}

# Handshake dispatch: label -> (kem_algo, sig_algo)
_PQ_HS = {
    "PQ-Handshake-Kyber512":   ("Kyber-512", "Dilithium-2"),
    "PQ-Handshake-Kyber768":   ("Kyber-768", "Dilithium-3"),
    "PQ-Handshake-Kyber1024":  ("Kyber-1024", "Dilithium-5"),
    "PQ-Handshake-NTRU":       ("NTRU-HPS-2048", "Falcon-512"),
    "PQ-Handshake-Dilithium2": ("Kyber-512", "Dilithium-2"),
    "PQ-Handshake-Dilithium3": ("Kyber-768", "Dilithium-3"),
    "PQ-Handshake-Falcon512":  ("Kyber-512", "Falcon-512"),
    "PQ-Handshake-SPHINCS":    ("Kyber-768", "SPHINCS+-128f"),
}
_CL_HS = {"Classical-TLS-RSA": ("RSA-2048", "RSA-2048"),
           "Classical-TLS-ECDSA": ("ECDSA-P256", "ECDSA-P256"),
           "Classical-TLS-X25519": ("X25519", "ECDSA-P256")}

CLIENT_NETS = ["192.168.1.", "192.168.2.", "10.0.1.", "10.10.1."]
SERVER_NETS = ["10.0.2.", "10.50.1.", "172.16.1.", "172.16.2."]
ATTACKER_NETS = ["198.51.100.", "203.0.113.", "192.168.99."]
IOT_NETS = ["10.100.1.", "10.100.2.", "192.168.50."]
TLS_PORTS = [443, 8443, 4433]

# -- Helpers (same pattern as generate_validation_pcap.py) ---------------------

def rand_ip(nets):
    return random.choice(nets) + str(random.randint(1, 254))

def ip_to_bytes(ip_str):
    return bytes(int(o) for o in ip_str.split('.'))

def make_tcp(src, dst, sport, dport, flags, payload=b''):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags,
                       seq=random.randint(0, 2**31), data=payload)
    ip = dpkt.ip.IP(src=ip_to_bytes(src), dst=ip_to_bytes(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp, len=20 + len(bytes(tcp)))
    ip.id = random.randint(0, 65535)
    return bytes(ip)

def make_udp(src, dst, sport, dport, payload=b''):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(src=ip_to_bytes(src), dst=ip_to_bytes(dst),
                    p=dpkt.ip.IP_PROTO_UDP, data=udp, len=20 + len(bytes(udp)))
    ip.id = random.randint(0, 65535)
    return bytes(ip)

def make_icmp(src, dst, icmp_type=8, payload=b''):
    icmp = dpkt.icmp.ICMP(type=icmp_type, data=dpkt.icmp.ICMP.Echo(
        id=random.randint(0, 65535), seq=random.randint(0, 65535), data=payload))
    ip = dpkt.ip.IP(src=ip_to_bytes(src), dst=ip_to_bytes(dst),
                    p=dpkt.ip.IP_PROTO_ICMP, data=icmp, len=20 + len(bytes(icmp)))
    return bytes(ip)

def rp(lo=100, hi=1400):
    return random.randbytes(random.randint(lo, hi))

def rport():
    return random.randint(1024, 65535)

SYN = dpkt.tcp.TH_SYN
ACK = dpkt.tcp.TH_ACK
PSH_ACK = dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK

# -- TLS handshake builder (works for both PQ and classical) -------------------

def _tls_handshake(src, dst, kem_name, sig_name, ts):
    """Simulate TLS handshake: 3-way, ClientHello, ServerHello, Cert, app data."""
    pkts, sp, dp = [], rport(), random.choice(TLS_PORTS)
    kem, sig = PQ_ALGORITHMS[kem_name], PQ_ALGORITHMS[sig_name]
    # TCP 3-way handshake
    for fl, s, d in [(SYN, src, dst), (SYN | ACK, dst, src), (ACK, src, dst)]:
        ts += random.uniform(0.001, 0.005)
        sp2, dp2 = (sp, dp) if s == src else (dp, sp)
        pkts.append((ts, make_tcp(s, d, sp2, dp2, fl, b'')))
    # ClientHello with KEM public key
    ts += random.uniform(0.001, 0.01)
    pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK,
                 b'\x16\x03\x03' + random.randbytes(kem["pk"] + random.randint(50, 150)))))
    # ServerHello with ciphertext
    ct_sz = max(kem["ct"], 32)
    ts += random.uniform(0.005, 0.02)
    pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK,
                 b'\x16\x03\x03' + random.randbytes(ct_sz + random.randint(30, 100)))))
    # Certificate with signature
    sig_sz = max(sig["sig"], sig["pk"])
    ts += random.uniform(0.002, 0.01)
    pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK,
                 b'\x16\x03\x03' + random.randbytes(sig_sz + sig["pk"] + random.randint(100, 300)))))
    # Application data
    for _ in range(random.randint(4, 12)):
        ts += random.uniform(0.01, 0.3)
        pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(200, 1400))))
        ts += random.uniform(0.01, 0.2)
        pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK, rp(200, 1400))))
    return pkts, ts

# -- Flow generator ------------------------------------------------------------

def gen_flow(label, ts_base):
    """Return (src_ip, dst_ip, [(timestamp, raw_packet), ...]) for one flow."""
    pkts, ts = [], ts_base
    src, dst = rand_ip(CLIENT_NETS), rand_ip(SERVER_NETS)

    if label in _PQ_HS:
        kem, sig = _PQ_HS[label]
        pkts, ts = _tls_handshake(src, dst, kem, sig, ts)

    elif label in _CL_HS:
        kem, sig = _CL_HS[label]
        pkts, ts = _tls_handshake(src, dst, kem, sig, ts)

    elif label == "Benign-PQ-Encrypted":
        sp, dp = rport(), random.choice(TLS_PORTS)
        for _ in range(random.randint(10, 30)):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(400, 1400))))
            ts += random.uniform(0.01, 0.3)
            pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK, rp(400, 1400))))

    elif label == "Benign-Classical-Encrypted":
        sp, dp = rport(), random.choice(TLS_PORTS)
        for _ in range(random.randint(8, 20)):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(100, 800))))
            ts += random.uniform(0.01, 0.3)
            pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK, rp(100, 800))))

    elif label == "Attack-PQ-Downgrade":
        src, sp, dp = rand_ip(ATTACKER_NETS), rport(), random.choice(TLS_PORTS)
        kem = PQ_ALGORITHMS["Kyber-768"]
        ts += random.uniform(0.001, 0.01)
        pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK,
                     b'\x16\x03\x03' + random.randbytes(kem["pk"] + random.randint(50, 150)))))
        ts += random.uniform(0.005, 0.02)
        pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK,
                     b'\x16\x03\x03' + random.randbytes(random.randint(80, 160)))))
        ts += random.uniform(0.002, 0.01)
        pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK,
                     b'\x16\x03\x03' + random.randbytes(random.randint(200, 400)))))
        for _ in range(random.randint(5, 15)):
            ts += random.uniform(0.01, 0.3)
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(200, 1000))))

    elif label == "Attack-HNDL-Capture":
        src, sp, dp = rand_ip(ATTACKER_NETS), rport(), random.choice(TLS_PORTS)
        for _ in range(random.randint(30, 60)):
            ts += random.uniform(0.001, 0.05)
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(800, 1400))))
        exfil_dst = rand_ip(ATTACKER_NETS)
        for _ in range(random.randint(20, 40)):
            ts += random.uniform(0.001, 0.02)
            pkts.append((ts, make_tcp(src, exfil_dst, rport(), 9443, PSH_ACK, rp(800, 1400))))

    elif label == "Attack-PQ-TimingSideChannel":
        src, sp, dp = rand_ip(ATTACKER_NETS), rport(), random.choice(TLS_PORTS)
        for _ in range(random.randint(40, 80)):
            ts += random.uniform(0.0005, 0.002)
            ct_sz = PQ_ALGORITHMS[random.choice(["Kyber-512", "Kyber-768", "Kyber-1024"])]["ct"]
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK,
                         b'\x16\x03\x03' + random.randbytes(ct_sz + random.randint(10, 30)))))
            ts += random.uniform(0.0001, 0.001)
            pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK, rp(30, 60))))

    elif label == "Attack-PQ-SessionReplay":
        src, sp, dp = rand_ip(ATTACKER_NETS), rport(), random.choice(TLS_PORTS)
        ticket = b'\x16\x03\x03' + random.randbytes(random.randint(200, 500))
        for _ in range(random.randint(10, 25)):
            ts += random.uniform(0.1, 1.0)
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, ticket)))
            ts += random.uniform(0.01, 0.05)
            pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK, rp(50, 200))))

    elif label == "IoT-PQ-Constrained":
        src, dp, sp = rand_ip(IOT_NETS), random.choice([5683, 5684, 8883]), rport()
        mk = make_udp if dp in (5683, 5684) else make_tcp
        mk_args = {} if dp in (5683, 5684) else {"flags": PSH_ACK}
        for _ in range(random.randint(5, 15)):
            ts += random.uniform(0.5, 5.0)
            if dp in (5683, 5684):
                pkts.append((ts, make_udp(src, dst, sp, dp, rp(20, 200))))
                ts += random.uniform(0.1, 1.0)
                pkts.append((ts, make_udp(dst, src, dp, sp, rp(20, 150))))
            else:
                pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(30, 250))))
                ts += random.uniform(0.1, 1.0)
                pkts.append((ts, make_tcp(dst, src, dp, sp, PSH_ACK, rp(20, 150))))
    else:
        sp, dp = rport(), 443
        for _ in range(random.randint(5, 15)):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(200, 1000))))

    return src, dst, pkts

# -- Main ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Generate PQC validation PCAP")
    ap.add_argument("--flows", type=int, default=40000)
    ap.add_argument("--output", default="pqc_validation_benchmark.pcap")
    ap.add_argument("--labeled-ratio", type=float, default=0.6)
    args = ap.parse_args()

    output_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(output_dir, args.output)
    csv_path = os.path.join(output_dir, args.output.replace('.pcap', '_ground_truth.csv'))

    flow_labels = []
    for label, weight in PQC_TRAFFIC_CLASSES.items():
        flow_labels.extend([label] * max(1, int(args.flows * weight)))
    random.shuffle(flow_labels)
    while len(flow_labels) < args.flows:
        flow_labels.append(random.choice(list(PQC_TRAFFIC_CLASSES.keys())))
    flow_labels = flow_labels[:args.flows]
    random.shuffle(flow_labels)

    print(f"Generating {args.flows:,} PQC flows -> {pcap_path}")
    print(f"Labeled ratio: {args.labeled_ratio:.0%}  |  Classes: {len(set(flow_labels))}\n")

    writer = dpkt.pcap.Writer(open(pcap_path, 'wb'), linktype=dpkt.pcap.DLT_RAW)
    csv_f = open(csv_path, 'w', newline='')
    cw = csv.writer(csv_f)
    cw.writerow(['flow_id', 'src_ip', 'dst_ip', 'label', 'true_label', 'is_labeled', 'n_packets'])

    ts = _time.time() - args.flows * 0.5
    class_counts, total_bytes, labeled_count = {}, 0, 0

    for i, label in enumerate(flow_labels):
        src, dst, packets = gen_flow(label, ts)
        is_labeled = random.random() < args.labeled_ratio
        if is_labeled:
            labeled_count += 1
        fid = f"PQ{i + 1:06d}"
        for pkt_ts, pkt_data in packets:
            writer.writepkt(pkt_data, pkt_ts)
            total_bytes += len(pkt_data)
        cw.writerow([fid, src, dst, label if is_labeled else '', label, is_labeled, len(packets)])
        ts = packets[-1][0] if packets else ts + 0.1
        class_counts[label] = class_counts.get(label, 0) + 1
        if (i + 1) % 5000 == 0:
            print(f"  [{i+1:,}/{args.flows:,}] {total_bytes / (1024*1024):.1f} MB generated...")

    writer.close()
    csv_f.close()

    pcap_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    csv_mb = os.path.getsize(csv_path) / (1024 * 1024)
    unlabeled = args.flows - labeled_count
    print(f"\n{'=' * 60}")
    print(f"Generated: {pcap_path} ({pcap_mb:.1f} MB)")
    print(f"Ground truth: {csv_path} ({csv_mb:.2f} MB)")
    print(f"Total flows: {args.flows:,}  |  Labeled: {labeled_count:,} ({labeled_count/args.flows:.1%})")
    print(f"Unlabeled: {unlabeled:,} ({unlabeled/args.flows:.1%})")
    print(f"\nClass distribution:")
    for lbl, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        print(f"  {lbl:40s} {cnt:6,} ({cnt/args.flows*100:5.1f}%)")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
