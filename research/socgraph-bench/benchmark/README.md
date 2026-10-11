# SOCGraph-21 (v1)

21 alert-investigation tasks built from public attack telemetry, in the
evidence-graph form of the BlueSec1 runtime: entities (processes, files,
registry keys, network connections, users, hosts) and typed relations
(process creation, file write/execute/delete, registry write, connect,
process access, ...).

- File: `socgraph-21-v1.zip` (sha256 in `SHA256SUMS`), 0.55 MB
- 21 tasks: Windows 8 malicious + 3 benign;
  Linux 7 malicious + 3 benign;
  15 distinct ATT&CK techniques
- Graph size per task: 47-1602 entities
  (median 174), 75-3951 relations
  (median 265); 10 entity types and
  16 relation types overall (`stats.json`)

| Task | Platform | Verdict | ATT&CK | Alert | Entities | Relations | Core / anchors |
|---|---|---|---|---|---|---|---|
| `lsass-dump-comsvcs` | windows | malicious | T1003.001 | Process opened LSASS with full access | 88 | 115 | 5 |
| `logon-script-persistence` | windows | malicious | T1037.001 | User environment registry value written by reg.exe | 47 | 75 | 6 |
| `service-binpath-hijack` | windows | malicious | T1543.003 | Service configuration changed with sc.exe | 157 | 219 | 6 |
| `hta-startup-folder` | windows | malicious | T1218.005 | mshta.exe executed an HTA file | 338 | 717 | 6 |
| `firewall-rule-added` | windows | malicious | T1562.004 | Inbound firewall rule added from the command line | 174 | 365 | 4 |
| `python-http-server` | windows | malicious | T1059 | Interpreter from a user profile started a network service | 300 | 633 | 6 |
| `bits-download` | windows | malicious | T1197 | BITS transfer job started from the command line | 186 | 247 | 4 |
| `run-key-and-beacon` | windows | malicious | T1547.001 | Autostart Run key value set by PowerShell | 74 | 87 | 5 |
| `lsass-query-by-svchost` | windows | benign | - | Process opened a handle to LSASS | 186 | 247 | 2 |
| `w32time-runtime-key` | windows | benign | - | Registry value written under a path matching '\Run' | 300 | 633 | 3 |
| `gpsvc-service-host` | windows | benign | - | New service host process started as SYSTEM | 174 | 365 | 2 |
| `linux-shadow-read` | linux | malicious | T1003.008 | Credential file read by a script run with sudo | 50 | 76 | 6 |
| `linux-wiper-shred` | linux | malicious | T1485 | shred overwrote a system directory | 317 | 672 | 7 |
| `linux-kernel-module` | linux | malicious | T1547.006 | Kernel module loaded with insmod | 78 | 142 | 6 |
| `linux-account-created` | linux | malicious | T1136.001 | Local account created | 76 | 127 | 5 |
| `linux-sudoers-nopasswd` | linux | malicious | T1548.003 | Passwordless sudo rule written | 141 | 245 | 5 |
| `linux-ld-preload-hijack` | linux | malicious | T1574.006 | Freshly compiled binary executed as root from a home directory | 150 | 265 | 8 |
| `linux-service-stopped` | linux | malicious | T1489 | Service state changed by systemctl as root | 1602 | 3951 | 5 |
| `linux-dpkg-service-start` | linux | benign | - | Service state changed by systemctl as root | 1602 | 3951 | 3 |
| `linux-motd-discovery` | linux | benign | - | Session discovery command run as root | 317 | 672 | 3 |
| `linux-motd-tmp-cleanup` | linux | benign | - | Files deleted by rm as root | 317 | 672 | 3 |

## Layout of the zip

| Member | Content |
|---|---|
| `manifest.json` | task index: platform, verdict, ATT&CK, alert title, source dataset and URL, graph size |
| `tasks/<id>.json` | what the agent sees: the alert and the evidence graph (no answers) |
| `answers/<id>.json` | ground truth: verdict, `core`, `acceptable`, `evidence_fields` |
| `README.md`, `LICENSES/` | build notes, sources, scoring, upstream licences |

## Ground truth

- **Malicious tasks.** The operator's recorded shell session is the root of
  the activity. `core` is what a complete response must name: the session
  root and the triggering process, the key commands, any persistence or
  output artifact (for example the LSASS dump file, the Run key, the module
  copied into `/lib/modules`), the host and the operator account.
  `acceptable` adds everything the session touched (its processes and the
  files, registry keys and connections they wrote or used); naming these is
  not penalised, naming anything else is.
- **Benign tasks.** Real background events from the same recordings that a
  naive rule would flag (for example `svchost` opening LSASS with access mask
  0x1000, the W32Time `\RunTime\` key matching a `\Run` rule, `dpkg` starting
  a service, MOTD scripts running discovery commands at SSH login).
  `evidence_fields` lists the anchors that prove legitimacy and their real
  property fields.
- Ground truth is written as selectors over the graph and rebuilt from the raw
  recordings by `agent/robust/localdata/scenarios.py`.

## Scoring

Quality Q in [0, 1]: half for the verdict, half for the artifacts (a wrong
verdict scores 0). Malicious: F1 of recall over `core` (an entity named with a
fitting response kind counts 1, with another kind 0.5) and precision against
`acceptable`. Benign: the share of anchors cited with a decisive property
field, minus a penalty for citing other ids. Efficiency
E = min(1, (optimal + 1) / tool calls). Reward R = Q (0.8 + 0.2 E).

## Rebuilding from the original recordings

```bash
uv run --with anthropic --with jsonschema python -m bluesec1_agent.robust.localdata.fetch
uv run --with anthropic --with jsonschema python -m bluesec1_agent.robust.localdata.pack --out socgraph-21-v1.zip
```

`fetch` downloads 8 OTRF zips and 7 Splunk logs (about 125 MB) into
`datasets/`. The Splunk forwarder's own checkpoint-file events under
`/opt/splunkforwarder/` are dropped as collector self-telemetry.
