# RobustIDPS Rust Agent

Native (Rust) sidecar binaries for the RobustIDPS.ai detection plane. Built as
a Cargo workspace; each member crate addresses one numbered item in the v3
edge-agent roadmap (see `papers/robustidps_documentation_v3.tex`
§16 "Future Directions" item 5 + the May 2026 architecture brief).

## Crates

| Crate | Role |
|---|---|
| `agent-features` | Library: pure-Rust PCAP/PCAPNG parser → bidirectional flow assembly → CICIDS2018-style 77-column feature vector. |
| `agent-cli` | Thin CLI driver shipping the `robustidps-agent` binary. |
| `agent-netfilter` | Library + `robustidps-netfilter` binary: safe, batched, atomic firewall-rule applier. Reads JSON `TransactionRequest`, renders a single `iptables-restore -n` / `nft -f -` payload, applies in one process spawn. |
| `agent-edge` | Library + `robustidps-edge` daemon: live or PCAP-replay capture → streaming flow assembly → stub classifier → gRPC `EdgeAgent` service streaming `FlowRecord`s upstream. Built on tokio + tonic. |

## Build

```bash
cd agent
cargo build --release
# binary lands at agent/target/release/robustidps-agent (~1.9 MB, statically linked)
```

## Use

```bash
# CSV to stdout
./target/release/robustidps-agent path/to/capture.pcap

# CSV to file with stats on stderr
./target/release/robustidps-agent capture.pcap -o flows.csv --verbose

# Stream into the Python backend's existing parse path
./target/release/robustidps-agent capture.pcap | \
  curl -F 'file=@-;filename=capture.csv' http://localhost:8000/api/predict
```

## Output schema

77 CICIDS2018-style numeric features (CICFlowMeter conventions) followed by
`src_ip`, `dst_ip`, `timestamp`. Column names are listed in
`agent-features/src/columns.rs::FEATURE_COLUMNS` and are kept identical to
`backend/features.py::CICIDS2018_FEATURES_FULL` so the CSV is a drop-in
replacement for the NFStream-produced DataFrame that `backend/features.py`
expects on `/api/predict` and the multi-dataset pages.

## Performance

On the bundled `sample_data/adversarial_benchmark.pcap` (28,100 packets,
17,089 assembled flows) on a single CPU core:

| Implementation | Time |
|---|---|
| Python + NFStream (`backend/features.py::pcap_to_dataframe`) | ~5–15 s |
| **Rust agent (this crate)** | **38 ms** |

That is a ~150–400× speed-up on a typical demo PCAP, with no libpcap dynamic
dependency (pure Rust via `pcap-parser` + `etherparse`). The headroom grows
with file size because the Rust path is memory-streaming and avoids pandas's
DataFrame construction overhead.

## Wiring into the Python backend

`backend/ingestion.py` (or any caller of `pcap_to_dataframe`) can invoke the
agent as a subprocess and feed the returned CSV directly into
`extract_features`:

```python
import subprocess, io, pandas as pd

def pcap_to_dataframe_rust(pcap_path: str) -> pd.DataFrame:
    proc = subprocess.run(
        ["robustidps-agent", pcap_path],
        capture_output=True, check=True, text=False,
    )
    return pd.read_csv(io.BytesIO(proc.stdout))
```

A `--features-binary` knob in `backend/config.py` will toggle between the
existing NFStream path and the Rust agent in a future change; until then the
agent ships alongside the Python fallback rather than replacing it.

## `robustidps-netfilter` usage

```bash
# Dry-run a batch of 3 rules
cat <<EOF | ./target/release/robustidps-netfilter --verbose
{
  "transaction": {
    "rule_type": "iptables",
    "transaction_id": "batch-001",
    "rules": [
      {"source": "203.0.113.42", "action": "drop", "protocol": "tcp", "dst_port": 22, "comment": "ssh-brute"},
      {"source": "198.51.100.0/24", "action": "reject"},
      {"source": "2001:db8::/32", "action": "drop"}
    ]
  },
  "dry_run": true
}
EOF
```

On hosts with `iptables-restore` / `nft` installed, set `"dry_run": false`
to apply atomically — one process spawn for N rules, the kernel either
accepts the whole transaction or rejects it.

Security properties:

* Source IP / CIDR must parse via `ipnet::IpNet::from_str`; anything else
  (including shell-metacharacter payloads) is rejected with a structured
  `failed` response.
* No raw shell command strings — callers describe intent (action + source +
  optional protocol/dport), the binary renders the kernel-bound payload.
* Comments are sanitised: control characters and quote characters are
  stripped, length capped at 64 chars.
* On non-zero exit / timeout, the agent emits a `failed` response with
  process status and captured stderr — never silently succeeds.

## `robustidps-edge` daemon usage

```bash
# One-shot PCAP-replay smoke test, no gRPC, prints stats to stderr
./target/release/robustidps-edge --pcap sample_data/adversarial_benchmark.pcap --no-grpc

# Long-running daemon with gRPC server bound to :50090
./target/release/robustidps-edge --config /etc/robustidps/edge.toml
```

Minimal `edge.toml`:

```toml
agent_id = "edge-01"

[capture]
mode = "live"
interface = "eth0"
snaplen = 1600
promisc = true

[grpc]
bind = "0.0.0.0:50090"

[flow]
idle_timeout_secs = 15
active_timeout_secs = 120
sweep_interval_secs = 2
max_flows = 200000

[inference]
block_ips = ["203.0.113.0/24"]
min_severity = "low"
```

The agent exposes a `robustidps.edge.v1.EdgeAgent` gRPC service:

| RPC | Direction | Purpose |
|---|---|---|
| `StreamFlows(StreamRequest) -> stream FlowRecord` | server-streaming | continuous push of finalised + classified flows |
| `GetStats(StatsRequest) -> AgentStats` | unary | counters (packets, flows, verdicts by severity, uptime) |
| `UpdateConfig(ConfigUpdate) -> ConfigAck` | unary | hot-swap block list + min-severity threshold |
| `ClassifyFlow(FlowRecord) -> Verdict` | unary | one-off classification for a control-plane-supplied flow |

The proto schema lives at `agent-edge/proto/edge.proto`; the Python control
plane should `protoc`-generate a client matching that schema.

## Roadmap

The agent is part of the 6-step edge-agent migration:

1. **Rust feature-extraction CLI ← (shipped)**
2. **Rust netfilter wrapper ← (shipped)**
3. **Edge agent MVP — gRPC + capture + flow assembly + stub classifier ← (shipped)**
4. Student-model distillation + INT8 inference
5. eBPF/XDP drop helper
6. Online model update channel

Each step lands as additional crates in this workspace.

## Testing

```bash
cargo test --release
```

The integration test parses `sample_data/adversarial_benchmark.pcap` and
asserts column count + finiteness of every value across all flows. The unit
tests confirm the feature-column list stays aligned with the Python schema.
