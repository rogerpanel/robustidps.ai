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

## Roadmap

The agent is part of the 6-step edge-agent migration:

1. **Rust feature-extraction CLI ← (this crate, shipped)**
2. Rust netfilter wrapper (replaces `backend/prevention.py::_execute_iptables_rule`)
3. Edge agent MVP (gRPC + zero-copy packet capture)
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
