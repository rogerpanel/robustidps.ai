# Linux (and macOS) Attack Telemetry Datasets from Security Vendors and Open Threat-Research Projects

Research date: 2026-10-10. Method: blobless `git clone` of the GitHub repos (the GitHub REST API was blocked in this environment, but git-over-HTTPS and raw/media.githubusercontent.com worked), direct download and inspection of sample files, and web search. zenodo.org could not be reached (proxy CONNECT 403 and WebFetch DNS failure), so Zenodo-hosted facts (AIT-LDS, DongTing) come from search-result snippets only and are marked as such. Several GitHub wiki pages returned HTTP 504.

Abbreviations: EID = Sysmon EventID; GUID = Sysmon ProcessGuid; ER-graph = entity-relation graph (process/file/socket/user nodes).

---

## 1. OTRF Security-Datasets (Mordor): Linux/macOS content

### Takeaway
OTRF has only **two** Linux datasets (SDLIN-201110074812 and SDLIN-201110081941). Both are tiny raw auditd captures of single Atomic Red Team commands from Nov 2020, and the repo has **no macOS content**. They are fine as toy examples with clean ground truth, but they are far too small to stand alone as investigation tasks. The repo is not archived, but its last commit was in Sep 2023.

### Cited Findings
- The repo licence is MIT ("Copyright (c) 2021 Open Threat Research Forge"). The latest commit on master is dated 2023-09-20 ("Merge pull request #65"), so the repo is effectively dormant but not archived — [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
- The whole tree has exactly two Linux data files:
  - `datasets/atomic/linux/discovery/host/sh_arp_cache.zip` (714 B zipped, 1,884 B unzipped `.log`)
  - `datasets/atomic/linux/defense_evasion/host/sh_binary_padding_dd.zip` (680 B zipped, 995 B unzipped)
  
  Each has a metadata YAML in `datasets/atomic/_metadata/SDLIN-*.yaml` and a notebook in `docs/notebooks/atomic/linux/`. A search of the tree for "mac|osx|darwin" found only Windows Covenant "executeexcel4macro" files, so there are no macOS datasets — [repo tree](https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/linux)
- **SDLIN-201110074812, "Arp Cache Discovery"**: T1018 (TA0007). It runs `arp -a | grep -v '^?'` from Atomic Red Team T1018 test 6. Environment: "Lab VM", host UBUNTU5, user wardog — [metadata YAML](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/_metadata/SDLIN-201110074812.yaml)
- **SDLIN-201110081941, "DD Binary Padding Hash Change"**: T1027.001 (TA0005). It runs `dd if=/dev/zero bs=1 count=1 >> /tmp/psexec.py` from Atomic Red Team T1027.001 test 1 — [metadata YAML](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/_metadata/SDLIN-201110081941.yaml)
- The format is **raw auditd text**, with full multi-record events:
  - record types SYSCALL (`syscall=59` execve), EXECVE, CWD, PATH and PROCTITLE (hex)
  - SYSCALL fields: `ppid`, `pid`, `auid`, `uid`, `euid`, `tty`, `ses`, `comm`, `exe`, `key`
  - EXECVE carries argv (a0..aN), and PATH carries inode, mode and ouid
  
  Inspected directly; the file is fetchable at `https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/linux/discovery/host/sh_arp_cache.zip` — [download](https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/linux/discovery/host/sh_arp_cache.zip)
- Ground truth is per-dataset technique labels in the YAML `attack_mappings`, plus the attacker command in `adversary_view`. There are no per-event labels — [metadata YAML](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/_metadata/SDLIN-201110081941.yaml)

### Inferences
- These recordings contain essentially no benign background (a handful of execve records only), so they cannot exercise a benign-vs-malicious decision.
- Converting them to a graph is trivial: pid→ppid edges, `exe`/argv for the process node, `cwd`, and PATH for file nodes. There are no network records.

### Gaps
- I did not verify whether the OTRF "compound" or APT datasets include any Linux hosts. My search of all tree paths for "linux" found only the files above, so they almost certainly do not.

---

## 2. Splunk attack_data (github.com/splunk/attack_data)

### Takeaway
This is the largest actively maintained source of real-sensor Linux attack telemetry: ~249 Linux-related log files covering ~60 ATT&CK technique IDs. The repo has a commit as recent as 2026-10-06 and is Apache-2.0 licensed. Individual files can be fetched one at a time.

The **Sysmon for Linux XML** recordings (73 `sysmon_linux`/`linux-sysmon` files plus 48 `snapattack_linux.log` files, also Sysmon-for-Linux XML) are the graph-friendly part. They carry GUID-keyed process create with parent fields, network connect and file create, plus lots of benign background. The **auditd** files are tiny, single-record-type extracts that have been filtered for a detection and are poor for graph building.

### Cited Findings
- **Licence, activity and storage**
  - Apache License 2.0. The latest master commit is 2026-10-06 ("Merge pull request #1237 from splunk/braodo_2026"). The repo has 3,763 tracked files — [splunk/attack_data](https://github.com/splunk/attack_data)
  - Data is stored in **Git LFS**. `.gitattributes` routes `datasets/**/*.json`, `*.log`, `*.ndjson` and `*.csv` to LFS. The README recommends `git lfs install --skip-smudge` and selective `git lfs pull --include=datasets/attack_techniques/<TID>/<folder>/` — [README](https://github.com/splunk/attack_data/blob/master/README.md)
- **Single-file download (verified)**
  - `https://media.githubusercontent.com/media/splunk/attack_data/master/<path>` returns the real file content.
  - The git blobs are LFS pointer files (`version … oid sha256:… size N`), so `raw.githubusercontent.com` is expected to return the pointer rather than the data. That is inferred from the pointers in the clone; I did not test raw for Splunk.
  - Verified example: `datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log`, 18.2 MB, 18,085 events — [example file](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log)
- **Layout**
  - The general pattern is `datasets/attack_techniques/<ATT&CK ID>/<scenario_folder>/<file>.log`, plus one `<folder>.yml` metadata file per folder.
  - Some Linux content sits in `datasets/suspicious_behaviour/linux_post_exploitation/` (`LinuxEnumd.log`, `autoSUID.log`, `linpeasdataset.log`, `linuxexploitsuggesterdatasets.log`, `mimipenguin.log`) and `datasets/malware/` (for example `cyclopsblink/sysmon_linux.log`, 80.2 MB, the largest Linux file) — [repo tree](https://github.com/splunk/attack_data/tree/master/datasets)
- **Metadata YAML example** (`T1548.003/linux_auditd_sudo_su/linux_auditd_sudo_su.yml`)
  - Fields: `author` (Teoderick Contreras, Splunk), `id`, `date` (2025-02-20), `description` ("Generated datasets for linux auditd sudo su in attack range."), `environment: attack_range`, `directory`, and `mitre_technique: [T1548.003]`.
  - `datasets:` is a list of name, path, `sourcetype: auditd` and `source: auditd`.
  - Ground truth is therefore **per-folder technique labels only**, with no per-event labels — [yml](https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1548.003/linux_auditd_sudo_su/linux_auditd_sudo_su.yml)
- **Inventory (my count from LFS pointer sizes in the blobless clone)**
  - Selection: paths containing "linux" or "auditd" and ending in `.log`/`.json`. That gives 249 files totalling ~775 MB; median 2.9 KB, p90 ~8.6 MB, max 80.2 MB. 238 of them are under `attack_techniques/`.
  - Sourcetypes in the YAMLs: `auditd` (~100 datasets), `sysmon:linux` with source `Syslog:Linux-Sysmon/Operational` (35), and a few `linux_messages_syslog`, `linux_secure`, `/var/log/kern`, `/var/log/auth` and `/var/log/syslog`.
  - By name: "sysmon" files = 73 (722.7 MB), "auditd" files = 103 (only **1.55 MB** total), other = 73 (50.5 MB, including the 48 `snapattack_linux.log` files) — [repo](https://github.com/splunk/attack_data)
- **ATT&CK IDs with Linux/auditd folders** (60): T1003.008, T1014, T1016, T1021.004, T1027, T1030, T1033, T1036, T1036.004, T1037.005, T1046, T1053.002, T1053.003, T1053.006, T1059, T1059.004, T1068, T1082, T1083, T1098, T1098.004, T1102, T1105, T1115, T1129, T1136, T1136.001, T1140, T1190, T1200, T1204.002, T1222.002, T1485, T1489, T1496, T1505, T1529, T1531, T1542, T1543.002, T1546.004, T1547, T1547.006, T1548, T1548.001, T1548.003, T1552.001, T1552.003, T1552.004, T1555.005, T1562, T1562.004, T1562.012, T1564.001, T1567, T1569.002, T1572, T1574.006, T1608, T1610.
  - Recent 2025–2026 folders include `T1068/linux_dirtyfrag`, `T1068/linux_pedit`, `T1068/linux_auditd_copy_fail` and `react2shell_linux.log` — [attack_techniques tree](https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques)
- **Sysmon for Linux format (inspected)**
  - One XML `<Event>` per line with Provider "Linux-Sysmon" and Channel `Linux-Sysmon/Operational`.
  - EID 1 fields: ProcessGuid, ProcessId, Image, CommandLine, CurrentDirectory, User, LogonGuid, LogonId, Hashes, **ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine, ParentUser**.
  - EID 3 fields: Protocol, Initiated, SourceIp/Port, DestinationIp/Port, plus ProcessGuid and Image.
  - EID 11 (FileCreate) fields: TargetFilename and Image.
  - The T1016 file contains EID 11 ×17,609, EID 5 ×184, EID 1 ×132, EID 3 ×102, EID 23 ×57 and EID 9 ×1. Most of it is benign Splunk forwarder activity (`/opt/splunkforwarder/bin/splunkd` checkpoint files, `streamfwd` connections to 10.0.1.12:8000) alongside the discovery commands (`ps -e -o pid,ppid,state,command`, `who -q`, `uname -r`, ...) — [file](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log)
  - The SnapAttack files are the same Sysmon-for-Linux XML (with an xmlns attribute). Example: `T1033/linux_root_execution_of_id/snapattack_linux.log` shows `id` run as root in `/home/ubuntu/spring-cloud-gateway-sample` — [file](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/linux_root_execution_of_id/snapattack_linux.log)
- **auditd format (inspected)**
  - I downloaded 100 of the 103 auditd files (those under 3 MB). Each contains essentially **one record type**:
    - 25 PROCTITLE-only, 25 EXECVE-only, 20 SYSCALL-only, 10 PATH-only
    - 6 CWD+PATH, 5 SERVICE_STOP, 2 PATH+SYSCALL, 1 EXECVE+PROCTITLE, 1 EXECVE+PATH
    - 2 are actually syslog (`su` PAM lines)
  - Only 28 contain EXECVE and 23 contain SYSCALL. None has the full SYSCALL+EXECVE+CWD+PATH bundle of a complete auditd event.
  - Example: `T1548.003/linux_auditd_sudo_su/linux_auditd_sudo_su.log` is 108 lines, all `type=PROCTITLE` — [file](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_auditd_sudo_su/linux_auditd_sudo_su.log)
- A third-party project reports a similar measurement: "154 recordings across 55 techniques" for the Splunk Linux set, and that "the 8 auditd extracts contain no EXECVE record". These are the author's own numbers and do not match my count, which used a different selection — [gauntlet-detection-coverage](https://github.com/rakshit-737/gauntlet-detection-coverage)
- **macOS content exists in small quantity**: `T1016/atomic_red_team/macos_net_discovery/*.log`, `T1553.001/atomic_red_team/macos_gatekeeper_bypass_xattr/*.log`, `T1059.004/macos_lolbin/osquery.log` and `T1059/macos_browser_spawned_script_external_network_connection/nvm_flowdata.log` (Cisco NVM flow data). There are also osquery datasets (`T1030/osquery_data_chunking`, `T1037.002/osquery_logon_scripts`, `T1053.004/osquery_persistence`) — [repo tree](https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques)

### Inferences
- **Best fit for the stated objective.** The Sysmon-for-Linux files give a GUID-keyed process tree (child→parent via ParentProcessGuid), file-write edges (EID 11), network edges (EID 3) and a user attribute, together with substantial benign background from the Attack Range host. That background supports the malicious-vs-benign decision.
- **Size issue.** Many sysmon files are 18–80 MB, dominated by EID 11 noise from the Splunk forwarder. A task builder should time-window around the technique's EID 1 events.
- **Benign label gap.** Events not tied to the technique are only implicitly benign, so per-event malicious labels must be derived (for example, the technique's process subtree).
- **auditd extracts are unusable for graph building.** Pid/ppid linkage requires SYSCALL records and argv requires EXECVE, and few files have both.

### Gaps
- I did not count Linux datasets whose paths lack "linux"/"auditd" (for example, Linux-related folders named after a tool only), so ~249 is approximate.
- I could not use the GitHub API to list LFS storage quota or download bandwidth limits. media.githubusercontent.com may be rate-limited for bulk fetches.
- I did not verify whether every Sysmon-for-Linux file includes EID 3 and EID 11 (it depends on the Attack Range sysmon config used).

---

## 3. Elastic (detection-rules repo, Elastic Security Labs)

### Takeaway
I found **no publicly downloadable Linux attack event recordings** from Elastic. The detection-rules repo holds rules (376 files under `rules/linux/`) plus ECS schemas, but no Linux test event data. Elastic emulates behaviour with RTA scripts, which generate activity rather than ship recorded data.

### Cited Findings
- The `elastic/detection-rules` master was active on 2026-10-09. A path search outside `rules/` found only `detection_rules/etc/ecs_schemas/*/ecs_flat.json.gz` and `ecs_nested.json.gz` (schemas), `detection_rules/etc/custom-consolidated-rules.ndjson`, and `tests/data/` containing only `__init__.py` and a dummy rule `.toml`. There are no `.ndjson`/`.jsonl` event samples for Linux — [elastic/detection-rules](https://github.com/elastic/detection-rules)
- Elastic's team uses Red Team Automation (RTA) scripts "to simulate threat behavior" and unit-test rules across Stack releases. These are emulation scripts, not datasets — [Elastic Security Labs: handy tools](https://www.elastic.co/security-labs/handy-elastic-tools-for-the-enthusiastic-detection-engineer)
- Elastic Security 7.8 (2020) added out-of-the-box Linux rules. That is not a dataset release — [Elastic blog](https://www.elastic.co/blog/elastic-security-7-8-0-released)

### Inferences
- Elastic's Linux rule queries (Elastic Defend / auditbeat ECS field names such as `process.parent.*`, `process.entity_id`) are useful as a schema target for the graph and as rule-based labelling, but they provide no data.

### Gaps
- I did not search the RTA repo or Elastic's `integrations` repo test fixtures (`packages/*/data_stream/*/_dev/test/pipeline/*.log`). Those contain small sample events (for example, auditd and endpoint pipeline tests), but they are not attack recordings. This remains unverified.

---

## 4. Sysmon for Linux sample logs (Microsoft SysmonForLinux, community)

### Takeaway
Microsoft's repo ships **no sample event logs**, only code, docs and performance-test configurations. In practice, the public Sysmon-for-Linux attack recordings are the Splunk attack_data files (section 2).

### Cited Findings
- `microsoft/SysmonForLinux` was active on 2026-09-14. Its non-source files are build/packaging files, `doc/01..08_*.md` eBPF tutorials, `perftest/` (CSV/PNG benchmark results) and `perftest/tests/` auditd/auditbeat rule configs. There are no `.xml`/`.log` event samples — [microsoft/SysmonForLinux](https://github.com/microsoft/SysmonForLinux)
- Sysmon-for-Linux events in Splunk's data use the Windows Sysmon XML schema with Linux paths (field list in section 2) — [Splunk sample](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log)
- A third-party project ("rootline") claims Sysmon-for-Linux + AUOMS recordings of a Log4Shell chain plus two atomic auditd captures. This comes from a search-result summary only; I did not verify sizes or licence — [rakshit-737/rootline](https://github.com/rakshit-737/rootline)

### Gaps
- No other community Sysmon-for-Linux attack corpus was found in search.

---

## 5. Falco event-generator, Tetragon and Tracee

### Takeaway
These projects publish **generators and rule tests, not recorded attack datasets**. Falco's event-generator has ~60 Go syscall "actions" mapped to Falco rules, which could be run to produce Falco JSON. I found no official downloadable corpus of Falco, Tetragon or Tracee output events.

### Cited Findings
- `falcosecurity/event-generator` was active on 2026-09-12. `events/` contains 95 files, including `events/syscall/*.go` actions such as:
  - `adding_ssh_keys_to_authorized_keys.go`, `fileless_execution_via_memfd_create.go`, `execution_from_dev_shm.go`
  - `detect_crypto_miners_using_the_stratum_protocol.go`, `polkit_local_privilege_escalation_vulnerability_cve20214034.go`
  - `netcat_remote_code_execution_in_container.go`, `search_private_keys_or_passwords.go`, `schedule_cron_jobs.go`, `read_sensitive_file_untrusted.go`
  - `ptrace_attached_to_process.go`, `clear_log_activities.go` and others
  
  Each one triggers a specific Falco rule — [falcosecurity/event-generator](https://github.com/falcosecurity/event-generator)
- Tracee writes one JSON object per line in JSON output mode. DefectDojo documents it as an import format, not a dataset — [DefectDojo Tracee parser](https://docs.defectdojo.com/supported_tools/parsers/file/tracee/)
- A web search for published Falco/Tetragon/Tracee sample-event datasets found none — [search result context: Mordor/MSTICpy docs](https://msticpy.readthedocs.io/en/v2.2.0/data_acquisition/MordorData.html)

### Inferences
- To use these sensors, generate your own data: run event-generator actions (or Atomic Red Team) on a VM with Falco/Tetragon/Tracee in JSON mode. Tetragon `process_exec` events carry `process.exec_id` and `parent.exec_id`, which give a clean graph key (from general knowledge, not verified in this session).
- event-generator actions are synthetic single-step triggers with little realistic context.

### Gaps
- My attempt to list Tetragon/Tracee testdata JSON files (for example, Tetragon `testdata/` or docs example events) did not finish: the clone timed out in the background. Unverified.

---

## 6. Atomic Red Team Linux recordings published by others

### Takeaway
Apart from OTRF (2 files) and Splunk attack_data (Attack Range plus SnapAttack Sysmon-for-Linux and auditd), I found no substantial public corpus of ART-on-Linux recordings. Search results surface mostly small personal or student projects.

### Cited Findings
- The ART Linux index lists the Linux atomic tests, for example "Auditd keylogger [linux]". These are test definitions, not recordings — [ART linux-index](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/linux-index.md)
- A student project ran ART on Linux and recorded the terminal with `script` instead of auditd or Sysmon. It notes that without auditd or Sysmon, T1059 and T1053 "leave almost no trace" — [vishwakarmameenal105-a11y/Atomic-Red-Team-Simulation-and-Detection](https://github.com/vishwakarmameenal105-a11y/Atomic-Red-Team-Simulation-and-Detection)
- `bfuzzy/auditd-attack` is an ATT&CK-mapped auditd **rule set**, which helps label raw auditd via `key=` but is not data — [bfuzzy/auditd-attack](https://github.com/bfuzzy/auditd-attack)

### Gaps
- I did not search Kaggle directly. I found no reliable sources for a Kaggle "Linux auditd ATT&CK" dataset.

---

## 7. Academic auditd/syscall/provenance datasets (LID-DS, ADFA-LD, DongTing, AIT-LDS, DARPA TC)

### Takeaway
- **LID-DS 2021** (sysdig syscalls with arguments, plus pcap per recording and exploit timestamps) is the only syscall dataset here with enough argument detail (fd paths, IPs) and process/thread IDs to build a partial entity graph.
- **ADFA-LD** and **DongTing** are syscall-number/name sequences with **no file or network entities**.
- **AIT-LDS v2.0** (Zenodo, 2022) has auditd logs from Linux hosts with per-line attack labels and is the strongest labelled multi-host candidate, but I could not verify its details.
- **DARPA TC E3/E5** (THEIA/TRACE on Ubuntu) are large provenance (CDM) datasets, far larger than "small-to-medium".

### Cited Findings
- **LID-DS**
  - Repo active 2026-08-29; GPL-3.0 licence (stated for the code). Download links for LID-DS 2021 and LID-DS 2019 are on Proton Drive (`drive.proton.me/urls/BWKRGQK994...` and `.../4DCRHJC9XC...`), with no registration — [LID-DS/LID-DS README](https://github.com/LID-DS/LID-DS)
  - LID-DS 2021 has 15 scenarios. It consists of a recording framework, a "modern and comprehensive system call dataset" and an evaluation library. The reference is CRITIS 2022, LNCS 13723, pp. 63–73, doi 10.1007/978-3-031-35190-7_6 — [LID-DS 2021 dataset report PDF](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf); [extended abstract](https://dbs.uni-leipzig.de/file/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
  - Each recording is a zip containing `<name>.sc` (syscalls), `<name>.pcap`, `<name>.json` (metadata) and `<name>.res` (resource stats).
  - Syscall line layout: `timestamp_ns user_id process_id process_name thread_id syscall_name direction(>/<) params...`. Params are name=value pairs, which in sysdig format include fd paths and socket tuples. Read from the dataloader source — [dataloader/syscall_2021.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_2021.py); [dataloader/recording_2021.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/recording_2021.py)
  - The repo's dataloaders also include ADFA-LD, CTF, "real_world" and SCAP readers — [dataloader/](https://github.com/LID-DS/LID-DS/tree/master/dataloader)
- **ADFA-LD** (UNSW Canberra; Creech and Hu)
  - "Free use … for academic research purposes … in perpetuity. Use for commercial purposes is strictly prohibited" — [UNSW ADFA IDS Datasets](https://research.unsw.edu.au/projects/adfa-ids-datasets)
  - Reported counts: 833 normal training traces, 4,372 validation traces and 746 attack traces. Attack classes: Adduser, Hydra_FTP, Hydra_SSH, Java_Meterpreter, Meterpreter, Web Shell. Traces are integer syscall IDs only, with no arguments — [arXiv 1904.07118](https://arxiv.org/pdf/1904.07118); [arXiv 2201.08066](https://arxiv.org/pdf/2201.08066)
- **DongTing 2022** (Hunan University; Zenodo 6627050, published 2022-10-22)
  - 18,966 labelled normal and attack sequences, ~85 GB decompressed.
  - Attack sequences: 12,116, from 17,855 bug-triggering programs across 26 kernel releases. Normal programs: 6,850, from 4 kernel regression test suites.
  - The record also includes baseline models (CNN/RNN, LSTM, Wavenet, ECOD).
  - Source: search snippet only; Zenodo was unreachable — [Zenodo 6627050](https://zenodo.org/records/6627050)
- **AIT-LDS v2.0** (AIT Austrian Institute of Technology; Zenodo 5789064, published 2022-02-24)
  - Logs include Apache access/error, auth, DNS, VPN, **audit logs**, Suricata, pcaps and more "from all hosts".
  - Separate ground-truth files label attack-related events by line number with attack-step labels and the rules that matched.
  - Source: search snippet only — [Zenodo 5789064](https://zenodo.org/records/5789064)
  - A log-parsing study used 2,000 audit lines from `russellmitchell/gather/intranet_server/logs/audit`, which confirms the scenario/host directory layout — [arXiv 2504.04877](https://arxiv.org/pdf/2504.04877)
- **DARPA TC**
  - E3 (2018) and E5 (2019). The E3 THEIA data is described as 106 M audit events, 40 GB uncompressed, from an Ubuntu host over 12 days. DARPA did not release benign background data separately, and CADETS is FreeBSD — [arXiv 2503.19370](https://arxiv.org/pdf/2503.19370); [arXiv 2404.03162](https://arxiv.org/pdf/2404.03162)
  - OpTC is Windows-only — [Kairos arXiv 2308.05034](https://arxiv.org/pdf/2308.05034)

### Inferences
- **LID-DS 2021** can yield a process/file/socket graph from syscall args (open/execve/connect with fd info). However, it lacks parent-pid linkage unless clone/fork return values are tracked. Each recording is a single containerised service (a web app plus exploit), and its labels are recording-level (normal/attack) plus an exploit timestamp. That suits "was this container exploited" tasks.
- **ADFA-LD and DongTing** should be marked **"syscall sequence only — no file/network entity detail"**. They are unsuitable for an ER-graph agent.
- **AIT-LDS v2** is the best academic candidate for labelled Linux host tasks (auditd plus per-line labels plus benign user simulation), pending verification of file sizes and licence.

### Gaps
- I could not verify AIT-LDS v2 file names, sizes, licence (likely CC-BY, unverified), or exact attack steps, because Zenodo was unreachable.
- LID-DS 2021 scenario names, sizes and data licence are unverified (the wiki returned HTTP 504). The GPL-3.0 is stated for the code.
- DARPA TC download location and licence are unverified (the GitHub page returned HTTP 504).

---

## 8. Other vendor-released Linux telemetry (Securonix, Datadog, Red Canary, SANS, CrowdStrike)

### Takeaway
I found no vendor-released Linux endpoint attack telemetry datasets from Securonix, Datadog, Red Canary or SANS. The only vendor-sensor Linux data located is in Splunk attack_data: the Attack Range sensors and community SnapAttack contributions.

### Cited Findings
- Splunk attack_data includes `crowdstrike_falcon.log` files, but only under Windows techniques (T1003.001/.002/.003 atomic_red_team), plus `suspicious_behaviour/crowdstrike_stream/event_stream_events` — [splunk/attack_data](https://github.com/splunk/attack_data/tree/master/datasets/suspicious_behaviour)
- The CrowdStrike Falcon Events Data Dictionary is a schema reference (Markdown/CSV), not data — [erickatwork/CrowdStrike-Falcon-Events-Data-Dictionary](https://github.com/erickatwork/CrowdStrike-Falcon-Events-Data-Dictionary)

### Inferences
- For practical task-building, the ranking is:
  1. Splunk Sysmon-for-Linux files (time-windowed)
  2. AIT-LDS v2 auditd (if verified)
  3. LID-DS 2021 (syscall-level, container scope)
  4. Self-generated Falco/Tetragon captures using event-generator or Atomic Red Team

### Gaps
- Red Canary, Datadog, Securonix and SANS were not individually searched beyond the general queries above (search budget). There may be conference-workshop datasets (for example, SANS SEC-course VMs) that are not publicly downloadable.
