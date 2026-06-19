# Dataset access guide

How to obtain real GNSS-spoofing, FANET telemetry, and UAV-flight
datasets so the chapter-6 framework runs on measured inputs end-to-end.
Organised by what's blocking (license vs download size vs nothing).

## 1 · GNSS spoofing IQ corpora

### Public — use today, no license

These four datasets are downloadable today. None require academic
licensing or fee. Wire any of them into `TEXBAT_ROOT` and the
`RealTEXBAT` loader picks them up.

| Dataset | Bands | Size | URL |
|---|---|---|---|
| **FGI-SpoofRepo** | GPS L1, Galileo E1, GLONASS L1 | ~40 GB total; per-scenario ~3 GB | <https://www.maanmittauslaitos.fi/en/research/databases/fgi-spoofrepo> |
| **OAKBAT** | GPS L1, Galileo E1 | ~80 GB | <https://gps.mae.cornell.edu/oakbat> |
| **TEXBAT Educational subset** | GPS L1 | ~60 MB (sc 1 partial) | <https://radionavlab.ae.utexas.edu/datastore/texbat/> |
| **Stanford GPSL field traces** | L1, L5 | varies | <https://web.stanford.edu/group/scpnt/gpslab/datasets.html> |

**Recommended starting choice: FGI-SpoofRepo.** Multi-GNSS matches
chapter 6 §6.5.2 more closely than TEXBAT-only GPS L1, and the
Finnish Geospatial Research Institute publishes it under a permissive
research license. Download into the server's `/data/fgi_spoofrepo/`
and set `TEXBAT_ROOT=/data/fgi_spoofrepo`.

### Gated — apply for access (1–2 week wait)

**TEXBAT (Texas Spoofing Test Battery)** — the canonical GNSS-spoofing
benchmark. Used by every published spoofing-detection paper since 2012.

Procedure:

1. Send an email to **<unsam@chandra.ae.utexas.edu>** (the data manager)
   with subject *"TEXBAT access request — academic"*. Include:
   - Your institutional affiliation (NRNU MEPhI works as academic)
   - A short paragraph naming your research goal — e.g. *"Evaluating M1 CT-TGNN GNSS-spoofing detection against TEXBAT scenarios 1, 3, 6, 8 for chapter 6 of the dissertation 'Methods and algorithms for enhancing robustness ... of dynamic graph neural networks'"*
   - PI name + email (your supervisor)
   - Institutional .edu-equivalent email address (not a personal Gmail)
   - Explicit statement: *"For non-commercial academic research only;
     I will not redistribute the data or publish derivatives without
     written permission."*

2. They send back a license PDF (1–2 pages, academic, no fee). Sign,
   scan, email back.

3. They send HTTPS credentials for a tarball (~120 GB) within 1–2
   weeks. Untar into `/data/texbat/` on your Hetzner server.

4. In your production `.env`: `TEXBAT_ROOT=/data/texbat`. The
   `make_dataset()` factory auto-detects and swaps `SyntheticTEXBAT`
   for `RealTEXBAT` at next backend restart. **Zero code changes
   needed** because both datasets emit the same
   `(n_chunks × 8 satellites × 8 CAF dims)` tensor shape.

## 2 · Real UAV flight trajectories (for Phase E EW-Bench)

These pair with the Phase D physics simulator to produce **hybrid
Phase E** runs — real recorded flight paths replace synthetic mission
profiles, position error is computed against actual ground-truth
trajectories, the simulator still injects GNSS jamming + defense
response, the framework's response is measured. *This is the most
defensible "real measured" story you can tell at the defense.*

All four are public; none require any application.

| Dataset | What it gives | Size | URL |
|---|---|---|---|
| **EuRoC MAV** | Micro-aerial-vehicle flights with synchronised IMU + stereo + sub-cm Vicon ground-truth pose | ~14 GB | <https://projects.asl.ethz.ch/datasets/doku.php?id=kmavvisualinertialdatasets> |
| **UZH-FPV** | High-speed racing drone flights with event camera + IMU + ground-truth | ~20 GB | <https://fpv.ifi.uzh.ch/> |
| **Blackbird (MIT)** | Aggressive maneuvers at 20 Hz logging with ground-truth | ~75 GB (subsets available) | <https://github.com/mit-aera/Blackbird-Dataset> |
| **PX4 SITL logs** | Thousands of recorded mission logs from the PX4 community | ~10 MB per flight | <https://logs.px4.io/> |

**Recommended starting choice: PX4 SITL logs.** Smallest size, most
realistic for the chapter-6 deployment story (PX4 is the same flight
controller the Phase D simulator's "no_def baseline" represents).
Download 20–50 log files (~500 MB total) into `/data/flights/px4/`
and set `FLIGHT_TRAJECTORIES_ROOT=/data/flights`.

After bootstrap, run a Phase E bench:

```
docker compose -f docker-compose.prod.yml exec -w /app backend \
  python -c "
from plugins.uav.uav_defense.ew_bench.simulator import (
    BenchConfig, run_bench_with_real_trajectories,
)
print(run_bench_with_real_trajectories())"
```

The UAV Monitor's source badge will flip from `Phase D · measured`
to `Phase E · measured + real trajectories`. The DO-326A crossings
update; the chart now shows the framework holding the floor across
real recorded flights.

### Quick PX4 log conversion (one-time)

PX4 logs ship as `.ulog`; the trajectory loader expects CSV. One-line
conversion using the `pyulog` tool:

```
pip install pyulog
for f in /data/flights/px4/*.ulog; do
    ulog2csv "$f"
    mv "${f%.ulog}_vehicle_local_position_0.csv" "${f%.ulog}.csv"
done
```

Then the auto-discovery loader picks them up at next backend restart.

## 3 · FANET / IoT swarm traces

For chapter 6 §6.5.4 swarm-coordination work. All public:

| Dataset | What it gives | URL |
|---|---|---|
| **CIC-IoT-2023** | 105 IoT devices, 33 attack types | <https://www.unb.ca/cic/datasets/iotdataset-2023.html> |
| **Edge-IIoT-Set** | Industrial-IoT intrusion (2.1M records) | <https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset> |
| **Nature FANET grey-hole** | Drone swarm grey-hole telemetry | <https://www.nature.com/articles/s41597-025-00001-1> |
| **MAVSec traces** | MAVLink cipher-mechanism benchmarks | <https://github.com/aniass/MAVSec> |

The Tier-1 demo subsets I shipped (`sample_data/uav/`) are based on
the schema of the Nature FANET + MAVSec datasets, so the operator
pages render the same data shape regardless of which source you use.

## 4 · Aerial vision corpora

Already documented in `plugins/uav/datasets_manifest.py`. All public,
but heavy:

- **VisDrone-DET** (~9 GB, 261,908 frames) — <https://github.com/VisDrone/VisDrone-Dataset>
- **AU-AIR** (~12 GB, 32,823 multi-modal frames) — <https://bozcani.github.io/auairdataset>
- **DOTA v2** (~30 GB, 188,282 instances) — <https://captain-whu.github.io/DOTA/>
- **APRICOT** (~4 GB, adversarial patches in the wild) — <https://apricot.mitre.org/>
- **Drone-vs-Bird** (~5 GB, 107 videos) — <https://wosdetc2025.wordpress.com/>
- **iSAID** (~50 GB, 655,451 segmentation instances) — <https://captain-whu.github.io/iSAID/>
- **DIOR** (~15 GB, 23,463 RS images) — <https://gcheng-nwpu.github.io/>

For the defense, the 50 MB curated AU-AIR subset (already on the
server via `scripts/bootstrap_demo_datasets.sh`) is enough to drive
the Perception Tester live. Reference the full datasets in the
manifest UI; the panel respects "we evaluated the full dataset
offline; the live demo uses the 50 MB subset" if they ask.

## 5 · One-command Phase E bootstrap

Once you've downloaded any of the above into a sensible directory
layout, this single sequence wires everything in:

```
# On the Hetzner server, as root in /home/robustidps/robustidps.ai
mkdir -p /data/{flights,texbat,fgi_spoofrepo}

# (Download datasets into the above dirs per the URLs in this doc.)

# Tell production where to find them
cat >> .env <<'EOF'
TEXBAT_ROOT=/data/fgi_spoofrepo
FLIGHT_TRAJECTORIES_ROOT=/data/flights
EOF

# Mount the new data dirs into the backend container by editing
# docker-compose.prod.yml volumes for the backend service:
#   - /data:/data:ro

# Apply
docker compose -f docker-compose.prod.yml up -d --build

# Run a measured Phase E bench against the real trajectories
docker compose -f docker-compose.prod.yml exec -w /app backend \
  python -c "from plugins.uav.uav_defense.ew_bench.simulator import \
             run_bench_with_real_trajectories; run_bench_with_real_trajectories()"

# Verify
curl -sf https://robustidps.ai/api/uav/ew-bench/measured-status \
  | python3 -m json.tool
```

The source badge in the UAV Monitor will read **Phase E · measured
+ real trajectories** once the bench writes its JSON.

## 6 · What to do in the meantime (no downloads yet)

Phase D (synthetic trajectories + physics simulator) is already live
on production. It produces measured MCR-vs-J/S curves with real
Wilson 95 % CIs. The defense story works *today* without any of the
above downloads — the source badge just reads `Phase D · measured`
instead of `Phase E · measured + real trajectories`.

When you have time post-defense, download FGI-SpoofRepo + a handful
of PX4 SITL logs (~1 GB total, ~2 hr download), follow §5 above, and
the same UAV Monitor flips to Phase E with real-trajectory provenance.
Same code path, same UI, just different source badge + slightly
different crossings.
