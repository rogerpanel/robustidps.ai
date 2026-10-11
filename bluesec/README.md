# RobustIDPS agent for BlueSec1

An investigation agent for the BlueSec1 runtime. It is installed into a clone
of the organisers' reference agent
(<https://github.com/False-Positive-Community/bluesec1-agent>). Their runtime
client and their reference agent stay exactly as published; this adds
`src/bluesec1_agent/robust/` next to them.

## What it changes compared with the reference agent

| | Reference agent | This agent |
|---|---|---|
| Tool calls | one per LLM turn, through a fixed JSON wrapper | native tool calling, built from each task's `available_tools`; independent calls can share a turn |
| Repeated call | spent again | answered from a local cache, nothing spent |
| Bad arguments | sent, spent, then the error comes back | validated locally against the advertised schema first (an unchanged retry is still sent, so the server stays the authority) |
| Invented ids in the submission | sent as is | one local warning listing ids never seen in the alert or any result |
| Budget | 100 steps, then the task fails | soft budget (told to wrap up) and a hard cap (evidence calls refused, so it submits instead of failing) |
| Method | general rules | competing hypotheses including a benign one, a decisive call per hypothesis, a per-kind guide to `ir_artifacts` and `legitimacy_evidence` |
| Models | any OpenAI-compatible | Claude (adaptive thinking, effort, prompt caching, server-side fallback) or any OpenAI-compatible |
| Record | log lines | `traces/<run>/<task>.json`: every call with its reasoning, cached and refused calls, the submission and the server's quality and efficiency scores; plus `summary.json` |

## Run it on the server

Run it on the Hetzner server, over SSH, inside `tmux`. If the SSH session
drops and kills the agent, the run stays open on the competition side until it
is released, and you cannot start another one.

```bash
# 0. uv (skip if `uv --version` works)
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.local/bin/env

# 1. the organisers' agent, next to the robustidps.ai checkout
cd ~ && git clone https://github.com/False-Positive-Community/bluesec1-agent.git
cd ~/robustidps.ai && git pull            # use your actual checkout path

# 2. add this agent to it, install, run all tests
bash ~/robustidps.ai/bluesec/install.sh ~/bluesec1-agent
cd ~/bluesec1-agent
uv sync
uv run --with anthropic --with jsonschema pytest

# 3. configuration
cp .env.example .env
nano .env    # SCENARIO_RUNTIME_TOKEN from bluesec.team, plus the lines in
             # ~/robustidps.ai/bluesec/env.robust.example (ANTHROPIC_API_KEY, ...)
chmod 600 .env

# 4. offline check: real model, built-in mock tasks, no competition run used
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --mock

# 5. practice arena, then read the traces
tmux new -s bluesec
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --arena practice
```

### Parallel mode and the finals deadline

The finals give 3 hours (12:00–15:00 Moscow time) for 40 tasks. Run several
tasks at once and set the deadline:

```bash
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --concurrency 4 --deadline 14:58
```

- `--concurrency N`: N tasks are investigated in parallel. If the runtime
  holds fewer tasks at once, the agent learns its limit from the refusal and
  waits for a free slot. That costs no calls and fails no tasks; the log says
  `Runtime holds K task(s) at a time`.
- `--deadline HH:MM` (Moscow time): no new tasks are taken from 6 minutes
  before it, and from 2 minutes before it running investigations may only
  submit (`ROBUST_LEASE_STOP_MINUTES`, `ROBUST_FINISH_MINUTES`).
- Parallel tasks share your LLM rate limit. The SDK retries rate-limit errors
  with backoff; if the log shows many of them, lower `--concurrency`.

Check parallel mode offline first, with your real key (16 mock tasks,
imitating a runtime that holds 2 at a time):

```bash
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --mock --mock-tasks 8 --mock-limit 2 --concurrency 4
```

If tasks abort with `model refused: ...`, run the probe. It sends only the
first request in three variants and shows which one is declined (a few cents):

```bash
uv run --with anthropic --with jsonschema --env-file .env python -m bluesec1_agent.robust.probe
```

The runtime's free-text fields are called `reasoning`. Claude declines
requests that ask it to write out its reasoning (`reasoning_extraction`), so
the model sees them as `purpose` (what a call checks) and `summary` (the
incident summary), and they are renamed back to `reasoning` before sending.

Options: `--provider openai` (uses `LLM_BASE_URL`, `LLM_API_KEY`,
`LLM_DEFAULT_MODEL`), `--model`, `--effort low|medium|high|xhigh|max`,
`--agent-name`, `--arena`.

The original agent still runs as before with `uv run --env-file .env bluesec1-agent`.
(The moderator's note says `uv launch`; the command is `uv run`.)

## Practice on public attack telemetry (no competition token needed)

`--local` runs the agent on 11 practice tasks built from **OTRF
Security-Datasets** (Open Threat Research Forge, MIT licence): real Sysmon and
Windows Security telemetry recorded while ATT&CK techniques were executed in
a lab. The telemetry becomes the same kind of evidence graph the competition
uses (processes, files, registry keys, connections and their relations),
served through the same tools, so the agent runs unchanged.

| Scenario | Verdict | ATT&CK | What happened |
|---|---|---|---|
| lsass-dump-comsvcs | malicious | T1003.001 | LSASS memory dumped to disk with comsvcs.dll |
| logon-script-persistence | malicious | T1037.001 | Logon script set via UserInitMprLogonScript |
| service-binpath-hijack | malicious | T1543.003 | Fax service binPath pointed at PowerShell |
| hta-startup-folder | malicious | T1218.005 | HTA downloaded into Startup, run by mshta |
| firewall-rule-added | malicious | T1562.004 | Inbound allow rule added with netsh |
| python-http-server | malicious | T1059 | Python HTTP server from AppData, firewall opened |
| bits-download | malicious | T1197 | BITS job downloading a remote file |
| run-key-and-beacon | malicious | T1547.001 | Run key persistence plus repeated beaconing |
| lsass-query-by-svchost | benign | – | svchost opened LSASS with query-only access |
| w32time-runtime-key | benign | – | W32Time `\RunTime\` key mistaken for a Run key |
| gpsvc-service-host | benign | – | Group Policy service host started as SYSTEM |

Benign tasks are real background events from the same recordings that a naive
rule would flag: the false positives a SOC agent must clear.

```bash
cd ~/bluesec1-agent
uv run --with anthropic --with jsonschema python -m bluesec1_agent.robust.localdata.fetch
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --local --concurrency 4
```

`fetch` downloads 8 datasets (about 10 MB) into `datasets/otrf/`; `--list`
shows the scenarios, and `--local id1,id2` runs a subset.

**Scoring (ours, not the competition's).** Quality is half verdict, half
artifacts. For malicious tasks, artifacts are scored as F1: recall over a core
set (the activity, its output or persistence, the host, the account; a fitting
response kind earns full credit, another kind half) and precision against
everything the operator session touched. For benign tasks, the evidence must
cite the legitimate anchors with a decisive property (for example
`granted_access` 0x1000 on the LSASS handle). Efficiency is
`min(1, (optimal + 1) / calls)`. Each task's trace records the score breakdown,
including any missed core items.

### Linux scenarios (Splunk attack_data, Sysmon for Linux)

| Scenario | Verdict | ATT&CK | What happened |
|---|---|---|---|
| linux-shadow-read | malicious | T1003.008 | sudo'd script reads /etc/shadow, /etc/passwd, /etc/sudoers |
| linux-wiper-shred | malicious | T1485 | shred of /boot and systemd units, rm -rf /home |
| linux-kernel-module | malicious | T1547.006 | module copied into /lib/modules and loaded with insmod |
| linux-account-created | malicious | T1136.001 | useradd / adduser of new local accounts |
| linux-sudoers-nopasswd | malicious | T1548.003 | NOPASSWD sudo rules written |
| linux-ld-preload-hijack | malicious | T1574.006 | freshly compiled binary run as root through hook scripts |
| linux-service-stopped | malicious | T1489 | operator stops and disables apache2 |
| linux-dpkg-service-start | benign | – | dpkg postinst starts apache2 (same alert as the line above) |
| linux-motd-discovery | benign | – | MOTD scripts run uname/who as root at SSH login |
| linux-motd-tmp-cleanup | benign | – | MOTD scripts delete their temp files as root |

The forwarder's own checkpoint-file writes under /opt/splunkforwarder are
dropped as collector self-telemetry; its processes and connections stay as
benign background.

### The practice pack (no downloads needed)

All 21 tasks in one zip (0.55 MB): `tasks/` (alert + graph, no answers),
`answers/`, `manifest.json`, README and upstream licences. Download it from
robustidps.ai at `/downloads/robustidps-bluesec-pack.zip`, or rebuild it:

```bash
uv run --with anthropic --with jsonschema python -m bluesec1_agent.robust.localdata.pack --out pack.zip
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --pack pack.zip --concurrency 4
```

### Ablation study

`--ablate` turns components off to measure what each contributes:
`cache`, `validation`, `grounding`, `budget`, `method` (a minimal prompt like
the reference agent's). `--ablation-suite` runs the full agent and each
single-component ablation on the same tasks (6 runs, so 6x the cost of one
run) and writes `traces/ablation-*.md` and `.csv`:

```bash
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --pack pack.zip --concurrency 4 --ablation-suite
```

Every `summary.json` records the configuration and these metrics, overall,
per platform and per expected verdict: quality, efficiency, reward, verdict
accuracy, false-positive rate (benign judged malicious), false-negative rate
(malicious judged benign), calls and seconds per task, cache savings, local
refusals and tokens.

## Reviewing runs on robustidps.ai

The **BlueSec Runs** page (SOC Intelligence → BlueSec Runs, `/bluesec-runs`)
stores runs in your account and shows each task step by step, with the
scores and a trend across runs. Two ways to add a run:

- **Upload**: drop a `traces/<run>/` folder onto the page, or choose its files.
- **Import from server** (admins): mount the agent's traces folder into the
  backend once. Add this line to `~/robustidps.ai/.env`, then rebuild:

  ```bash
  BLUESEC_TRACES_DIR=/home/robustidps/bluesec1-agent/traces
  ```

  New run folders then appear on the page with an Import button.

**Comparison and ablation.** Tick two or more runs in Saved runs: the page
shows the ablation table (Δ against a chosen baseline, best values in bold),
a quality/efficiency chart, a Windows/Linux and malicious/benign breakdown,
and a per-task matrix with verdict marks. Each table exports to CSV, and the
page exports to PDF/PNG.

**Practice pack.** Download the pack, or browse it on the page: task list,
each task's alert and graph composition, a searchable entity explorer, and
the ground truth behind a "Show answers" toggle.

## Improving between runs

The leaderboard keeps your current result, so iterate on the practice arena:

1. Open `traces/<run>/summary.json` and sort tasks by `quality_score`.
2. For a low-quality task, read its trace: wrong verdict, missing artifacts,
   wrong `kind`, or legitimacy evidence citing the wrong fields.
3. For a low-efficiency task, look for calls whose result changed nothing.
4. Adjust `SYSTEM_PROMPT` in `src/bluesec1_agent/robust/prompt.py` (or in
   this repo and reinstall), or the budgets in `.env`, and run again.
