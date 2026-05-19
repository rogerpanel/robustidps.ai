# agent-xdp

Kernel-level fast-path packet drop for the RobustIDPS.ai edge agent. Loads a
small XDP program into the kernel that consults an LPM-trie of blocked
IPv4 / IPv6 CIDRs and returns `XDP_DROP` on hit — well before the packet
reaches the network stack.

## Architecture

```text
┌────────────────────────────────┐
│ userspace: robustidps-xdp      │   gRPC/IPC updates (step 6)
│ ┌────────────────────────────┐ │   ───────────────►
│ │ aya::Ebpf::load()          │ │       ┌─────────┐
│ │ XdpAgent::start(cfg)       │ │       │ control │
│ │ update_blocks()/read_stats │ │ ◄──── │  plane  │
│ └────────────────────────────┘ │       └─────────┘
│           │ pin                │
│           ▼                    │
│ ┌────────────────────────────┐ │
│ │ BPF maps (in kernel)       │ │
│ │   blocked_v4 : LPM_TRIE    │ │
│ │   blocked_v6 : LPM_TRIE    │ │
│ │   stats      : ARRAY[4]    │ │
│ └────────────────────────────┘ │
└──────────────┬─────────────────┘
               │
               ▼
       ┌─────────────────┐
       │ kernel XDP hook │   ◄── runs in NIC driver before SKB alloc
       │ xdp_drop.bpf.o  │
       │ XDP_DROP / PASS │
       └─────────────────┘
```

## Layout

| Path | Role |
|---|---|
| `bpf/xdp_drop.bpf.c` | Kernel-side eBPF program (C, 187 lines). Compiled by `build.rs`. |
| `build.rs` | Invokes `clang -O2 -g --target=bpfel` then `pahole -J` for BTF; gracefully falls back to an empty placeholder when the toolchain is missing so the workspace stays buildable on non-Linux dev machines. |
| `src/lib.rs` | Userspace loader library (`XdpAgent`, `XdpStats`, `XdpConfig`, `AttachMode`). |
| `src/main.rs` | `robustidps-xdp` daemon binary (clap CLI + SIGINT/SIGTERM handling + optional periodic stats). |

## BPF program contract

The Rust loader and the C source agree on these names. Changing one without
the other will fail at runtime with `program/map not found in object`.

| Element | Name | Type |
|---|---|---|
| XDP program | `xdp_drop_blocked` (section `xdp`) | `int xdp_drop_blocked(struct xdp_md *)` |
| Block map (v4) | `blocked_v4` | `BPF_MAP_TYPE_LPM_TRIE`, key `{prefixlen,u32 addr_be}`, value `u8`, max 8192 |
| Block map (v6) | `blocked_v6` | `BPF_MAP_TYPE_LPM_TRIE`, key `{prefixlen,u8 addr[16]}`, value `u8`, max 8192 |
| Stats array | `stats` | `BPF_MAP_TYPE_ARRAY`, key `u32`, value `u64`, max 4 |
| Stat index 0 | `STAT_PKT_TOTAL` | total packets seen by the hook |
| Stat index 1 | `STAT_PKT_DROPPED` | matched the block list |
| Stat index 2 | `STAT_PKT_PASSED` | IP packets that did not match |
| Stat index 3 | `STAT_PKT_NON_IP` | non-IP (ARP, etc.); passed |

The C side keeps source addresses in **network byte order** inside LPM keys
because the LPM trie matches bytewise from the MSB end — which is exactly
CIDR semantics on big-endian bytes. The Rust loader's `v4_key` / `v6_key`
helpers reproduce this.

## Deploy host requirements

Tested target: **Hetzner CCX23 running Ubuntu 24.04 LTS**.

Required kernel features (verify with the checklist below):

- Linux kernel **≥ 5.7**. XDP, `BPF_F_NO_PREALLOC` on LPM tries, BTF.
- `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_XDP_SOCKETS=y`,
  `CONFIG_DEBUG_INFO_BTF=y` in the running kernel.
- `CAP_NET_ADMIN` + `CAP_BPF` (kernel ≥ 5.8 split CAP_BPF off CAP_SYS_ADMIN;
  on older 5.7 kernels you need `CAP_SYS_ADMIN` instead).
- A NIC with XDP support. **Native** XDP requires driver support
  (`virtio_net`, `mlx5`, `ixgbe`, `i40e`, `ena`, etc.); on Hetzner cloud VMs
  the `virtio_net` driver supports native XDP from kernel ≥ 5.4. The
  generic / SKB-mode fallback works on every interface but at lower
  throughput.

Build-time deps:

- `clang ≥ 14` (we use clang 18 in CI).
- `dwarves` (provides `pahole` for BTF generation).
- `libbpf-dev`, `linux-libc-dev`, `gcc-multilib` (for the `<asm/types.h>`
  pulled in by `<linux/bpf.h>`).

## Hetzner deployment checklist

Run these on the Hetzner box (as root or via `sudo`). Each step prints what
to expect — if any check fails, that's what we need to obtain via the
provider console.

### 1. Kernel version

```bash
uname -r
# Expected: 6.x.y-... (Ubuntu 24.04 ships 6.8 by default)
# Minimum acceptable: 5.7
```

### 2. Required kernel configs

```bash
grep -E 'BPF_SYSCALL|BPF_JIT|XDP_SOCKETS|DEBUG_INFO_BTF' /boot/config-$(uname -r)
# Expected (all =y):
#   CONFIG_BPF_SYSCALL=y
#   CONFIG_BPF_JIT=y
#   CONFIG_XDP_SOCKETS=y
#   CONFIG_DEBUG_INFO_BTF=y
```

If any line is missing or `=n`, the stock Hetzner kernel needs replacing —
unusual on Ubuntu 24.04. **If you see a missing config**, please paste the
full output here.

### 3. Kernel BTF blob

```bash
ls -la /sys/kernel/btf/vmlinux
# Expected: a file ~3-7 MB. If "No such file or directory", BTF isn't
# exposed and step 5 of the agent stack will not work on this kernel.
```

### 4. Interface + XDP attach mode

```bash
ip -br link
# Pick the interface to attach to (typically eth0 or enp1s0).
# Then check it supports native XDP:
ethtool -i eth0 | grep driver
# Expected drivers with native XDP support: virtio_net, mlx5_core,
# ena, ixgbe, i40e, ice, bnxt_en. Anything else → use --mode skb.
```

### 5. Capabilities

If running the daemon directly under `systemd`, add:

```ini
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON
```

`CAP_PERFMON` is required from kernel 5.8 onward for some BPF map
operations. On older kernels substitute `CAP_SYS_ADMIN`.

### 6. Install build deps + Rust toolchain

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev gcc-multilib \
                        dwarves bpftool pkg-config build-essential
# Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
```

### 7. Build the crate

```bash
cd ~/robustidps.ai/agent
cargo build --release -p agent-xdp
# Watch for: "BPF object built + BTF-annotated at ..." — if you see
# "BPF compile skipped — emitting zero-byte placeholder ...", paste the
# `Reason:` line back here so we can fix the missing dep.
```

### 8. First attach (dry run on loopback)

```bash
sudo ./target/release/robustidps-xdp --interface lo --mode skb \
    --blocks 203.0.113.0/24,2001:db8::/32 --stats-interval 5
# Expected:
#   xdp attached: interface=lo mode=Skb
#   [xdp-stats periodic] total=... dropped=0 passed=... non_ip=...
# Press Ctrl-C to stop. The XDP program detaches automatically.
```

### 9. Production attach

```bash
sudo ./target/release/robustidps-xdp --interface eth0 --mode auto \
    --blocks-file /etc/robustidps/blocks.txt --stats-interval 60
# (--blocks-file is a step-6 follow-on; for now use comma-separated --blocks)
```

## Local-dev / CI behaviour

Outside Linux + clang-bpf, the build script writes a zero-byte
`xdp_drop.bpf.o` so the workspace still compiles. `XdpAgent::start` will
then fail loudly at runtime with:

> `failed to load BPF object: error parsing ELF data`

— that's the marker for "rebuild on a host with the BPF toolchain".

## Roadmap

This crate is step 5 of the 6-step Rust edge-agent migration. The follow-on
step 6 wires `XdpAgent::update_blocks` to the gRPC control plane so the
block list can be pushed across the fleet in seconds.
