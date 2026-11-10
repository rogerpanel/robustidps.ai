# Splunk and DARPA data anchor Linux investigations

The best public starting point for Linux provenance-graph investigation tasks is **Splunk's attack_data repository**. It holds about 121 Sysmon-for-Linux recordings across roughly 60 ATT&CK techniques, under Apache-2.0, and individual files can be fetched one at a time. Because these use the same XML schema and EventIDs as Windows Sysmon, the existing OTRF converter carries over almost unchanged. The catch is that ground truth is a technique label per folder, not per event. **DARPA Transparent Computing E3 (THEIA on Ubuntu, CADETS on FreeBSD)** is the only public Unix provenance corpus with entity-level malicious labels. It is public domain, and research groups have published node-UUID label sets for it (Orthrus/PIDSMaker and ThreaTrace). However, even the smallest slices arrive as gigabyte-scale dumps, so you have to cut subgraphs before they fit a small server. **AIT-LDS v2** (auditd with line-level labels across simulated enterprise networks) and **LID-DS 2021** (container syscall recordings with exploit timestamps) are the strongest academic follow-ons. Their sizes and data licences could not be verified from the research environment. Everything else falls short in one of three ways. Some datasets lack host entities: Kubernetes flow sets, UNSW-NB15, CIC-IDS flows and syscall-number corpora such as ADFA-LD. Some lack a benign class: honeypots. And some lack a process graph altogether: CloudTrail and LANL. One gap stands out: **no public labelled Falco, Tetragon or Tracee attack corpus exists**, so a Kubernetes or eBPF track will have to be self-generated.

## Few Linux datasets carry both a process tree and ground truth

The research surveyed about 25 candidate datasets, and most fail at least one of the two hard requirements. The first requirement is host-level entities joined by relations: process to parent, process to file, process to socket, and process to user. The second is ground truth that can be turned into a malicious-or-benign verdict on those entities. The table below covers the Linux and Unix host datasets that pass, or nearly pass, both tests. A second table later covers cloud, Kubernetes, macOS, enterprise and honeypot sources. "Unverified" means the source pages (Zenodo, Google Drive, Proton Drive, LANL) were unreachable from the research sandbox. It does not mean the facts are wrong.

| Dataset | Publisher / licence / access | Format and platform | Size | Attacks | Ground truth | Graph conversion | Fits under ~100 MB? |
|---|---|---|---|---|---|---|---|
| Splunk attack_data (Linux subset) | Splunk; Apache-2.0; no registration; Git LFS | Sysmon-for-Linux XML (73 files + 48 SnapAttack), auditd fragments (103), syslog; Ubuntu "Attack Range" hosts | 249 Linux files, ~775 MB total; median 2.9 KB, max 80.2 MB | ~60 ATT&CK IDs plus malware (Cyclops Blink) and post-exploitation tools (linpeas, mimipenguin) | Technique ID per folder (YAML); no event labels | High for Sysmon files; auditd fragments unusable | Yes, per file |
| OTRF Security-Datasets (Linux) | OTRF; MIT per repo LICENSE (a mirror lists GPL-3.0) | Raw auditd; Ubuntu lab VM | 2 files, ~1–2 KB each | T1018, T1027.001 | Technique ID plus attacker command per dataset | Trivial, but no benign background and no network | Yes |
| DARPA TC E3 THEIA / TRACE (Linux), CADETS (FreeBSD) | DARPA I2O; public domain; no registration; Google Drive | CDM18 Avro/JSON provenance | THEIA_E3 dump 1.1 GB compressed / 12 GB loaded; CADETS_E3 1.4 / 10.1 GB; TRACE_E3 ~100 GB | Drakon implant via Firefox backdoor, browser-extension dropper, Nginx backdoor, pine exploit, phishing executable | Official PDF narrative; node-UUID labels from Orthrus (58–61 nodes per THEIA attack) and ThreaTrace (25,358 THEIA UUIDs) | High; UUID-keyed subjects, files and netflows; open parsers exist | No; extract subgraphs |
| DARPA TC E5 THEIA / CADETS / TRACE | Same; CDM20 | CDM20 provenance | THEIA_E5 5.8 / 36 GB; CADETS_E5 36 / 276 GB; TRACE_E5 ~710 GB | Firefox Drakon APT with BinFmt elevation and injection; Nginx Drakon APT | Orthrus node labels (70 TP nodes for THEIA E5) | High, but very large | No |
| AIT-LDS v2.0 | AIT; Zenodo 5789064; licence unverified (believed CC BY) | auditd, Apache, auth, DNS, VPN, syslog, Suricata, pcap; 8 simulated enterprise testbeds | Unverified | Multi-step intrusions (exact step list unverified) | Line-level labels with attack-step names | High, but needs auditd reassembly | Per-host slices likely; unverified |
| LID-DS 2021 | Leipzig University; code GPL-3.0, data licence unverified; Proton Drive, no registration | sysdig syscalls with arguments, plus pcap and JSON metadata per recording; Docker containers | Unverified | 15 CVE/CWE scenarios | Per-recording normal/attack label plus exploit timestamp | Medium-high; parent links need clone tracking | Likely per recording; unverified |
| CICAPT-IIoT2024 | UNB CIC | auditd → SPADE provenance graph, plus network logs | Unverified | APT29 emulation via Caldera, 20+ techniques, 8 tactics | To be checked; provenance reportedly from one node | Medium-high; already a graph | Unknown |
| NodLink Simulated Data (host hw17) | NodLink authors; citation requested, no licence seen | `benign.json` / `anomaly.json`; Ubuntu 20.04 (other hosts are Windows) | Small (GitHub-hosted); unverified | 1 Ubuntu attack | Benign vs anomaly split plus written annotation | Medium | Likely |
| Unicorn SC-1/SC-2 | Seltzer lab; GitHub; no licence seen | CamFlow provenance | SC-1: 64 GiB benign + 12 GiB attack | Supply-chain APT on CI server | Graph-level only | Medium; huge | No |
| StreamSpot | Stony Brook / UIC | TSV edge list with one-letter types | 600 graphs | Drive-by download | Graph-level only | Poor: no names, paths or IPs | Yes, but useless for SOC tasks |
| ADFA-LD, DongTing | UNSW (academic use only); Hunan Univ. (Zenodo) | Syscall-number sequences | DongTing ~85 GB | Meterpreter, web shell, Hydra; kernel bug triggers | Sequence labels | Unsuitable: no file or network entities | Varies |

Sources for the table: Splunk ([repo](https://github.com/splunk/attack_data), [README](https://github.com/splunk/attack_data/blob/master/README.md)); OTRF ([repo](https://github.com/OTRF/Security-Datasets), [metadata](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/_metadata/SDLIN-201110081941.yaml)); DARPA TC ([E3 README](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md), [TC README](https://github.com/darpa-i2o/Transparent-Computing), [PIDSMaker sizes](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/settings/ten-minute-install.md), [Orthrus labels](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/main/Ground_Truth/orthrus/readme.md), [ThreaTrace](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/README.md)); AIT-LDS ([Zenodo](https://zenodo.org/records/5789064), [ACM](https://dl.acm.org/doi/fullHtml/10.1145/3675741.3675748)); LID-DS ([GitHub](https://github.com/LID-DS/LID-DS), [CRITIS 2022](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)); CICAPT ([UNB](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html), [ProvICS](https://arxiv.org/html/2607.05989)); NodLink ([GitHub](https://github.com/Nodlink/Simulated-Data)); Unicorn ([arXiv](https://arxiv.org/pdf/2001.01525)); StreamSpot ([README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)); ADFA-LD ([UNSW](https://research.unsw.edu.au/projects/adfa-ids-datasets), [arXiv](https://arxiv.org/pdf/1904.07118)); DongTing ([Zenodo](https://zenodo.org/records/6627050)).

The table points to a structural problem. The **datasets with the best labels are the hardest to fit on disk**, namely DARPA TC with node UUIDs. The **datasets that fit easily have the weakest labels**, namely Splunk and OTRF with one technique label per recording. AIT-LDS and LID-DS sit in between, but they need the most parsing work and their sizes are unverified. A practical benchmark therefore needs two things. For the small datasets, a label-derivation step turns recording-level truth into entity-level truth. For the large ones, an offline extraction step cuts labelled subgraphs down to task size.

## Splunk's Sysmon-for-Linux files reuse the Windows converter almost verbatim

Splunk attack_data is the **largest actively maintained corpus of real-sensor Linux attack telemetry**. Its latest commit is dated 2026-10-06 and its data folders include 2025–2026 additions such as `T1068/linux_dirtyfrag` and `linux_auditd_copy_fail` ([splunk/attack_data](https://github.com/splunk/attack_data)). Files are stored in Git LFS. A single file can be fetched directly from `media.githubusercontent.com/media/splunk/attack_data/master/<path>`, or a single folder with `git lfs install --skip-smudge` followed by a selective `git lfs pull --include=...` ([README](https://github.com/splunk/attack_data/blob/master/README.md)). This matters on a disk-limited Hetzner box, because you never need the whole repository.

The graph-friendly portion is the **Sysmon-for-Linux XML**: 73 Attack Range files plus 48 `snapattack_linux.log` community contributions in the same format. Each `<Event>` uses the Windows Sysmon schema with Linux paths. EID 1 carries ProcessGuid, ProcessId, Image, CommandLine, CurrentDirectory, User, LogonId, Hashes, **ParentProcessGuid, ParentImage, ParentCommandLine and ParentUser**. EID 3 adds network connections keyed by ProcessGuid, and EID 11 adds file creation ([T1016 sample](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log)). The verified example `T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log` is 18.2 MB with 18,085 events. Its event mix is:

- 17,609 FileCreate (EID 11)
- 184 process terminate (EID 5)
- 132 process create (EID 1)
- 102 network connect (EID 3)
- 57 file delete (EID 23)

That mix is both a strength and a nuisance. Most of the volume is **benign Splunk forwarder activity** (`splunkd` checkpoint files, `streamfwd` connections), which gives the agent real benign context to rule out. But the attack itself, a handful of discovery commands such as `ps`, `who -q` and `uname -r`, is a needle of roughly a dozen process creations.

The **auditd files in the same repository are not usable for graph building**. All 103 together total only 1.55 MB. In the 100 files inspected, each held essentially one record type: PROCTITLE-only, EXECVE-only or SYSCALL-only. None contained the full SYSCALL+EXECVE+CWD+PATH bundle that links a pid to its ppid, argv and file paths ([linux_auditd_sudo_su.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_auditd_sudo_su/linux_auditd_sudo_su.log)). They were evidently filtered down to whatever a single detection needed.

Ground truth is the folder's YAML, which gives `mitre_technique`, a one-line description and `environment: attack_range`, with **no per-event labels** ([example YAML](https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1548.003/linux_auditd_sudo_su/linux_auditd_sudo_su.yml)). Entity-level truth must be derived, and it has to be defended in any publication. The defensible approach is to anchor on the EID 1 events whose command lines match the Atomic Red Team test for that technique, mark their ProcessGuid subtree and touched files and sockets as malicious, and treat everything else in the window as benign. The residual risk is that "everything else" is only implicitly benign.

Coverage spans 60 technique IDs. The list includes credential access (T1003.008, T1552.001/.003/.004), persistence (T1053.003 cron, T1543.002 systemd, T1546.004 shell config, T1098.004 SSH keys), privilege escalation (T1548.001 setuid, T1548.003 sudo, T1068), defence evasion (T1562.004, T1564.001, T1222.002) and impact (T1485, T1496, T1529) ([attack_techniques tree](https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques)). Several of these exercise exactly the `systemd_unit` and `linux_user` entities in the target vocabulary.

Elastic, Microsoft and the eBPF sensor projects add no recorded data. Elastic's detection-rules repo ships 376 Linux rules and ECS schemas but no Linux event samples ([elastic/detection-rules](https://github.com/elastic/detection-rules)). Microsoft's SysmonForLinux repo has no sample logs ([microsoft/SysmonForLinux](https://github.com/microsoft/SysmonForLinux)). Falco's event-generator ships about 60 syscall "actions" (memfd fileless execution, SSH-key injection, crypto-miner stratum, CVE-2021-4034), which you would have to run yourself to produce data ([falcosecurity/event-generator](https://github.com/falcosecurity/event-generator)).

## DARPA TC supplies the only entity-level Unix truth, at gigabyte cost

DARPA's Transparent Computing engagements are the canonical provenance benchmark. Their terms are the cleanest available: "DARPA is releasing these files in the public domain to stimulate further research", with no registration ([README-E3](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)).

**E3** ran in April 2018. Its two Unix-relevant performers are THEIA (Ubuntu 12.04 with Firefox as the attack surface) and CADETS (FreeBSD with Nginx); TRACE is also Linux. **E5** followed in May 2019. Both use the CDM schema: typed Subject (process), FileObject and NetFlowObject nodes, typed events, and UUID identity ([TC README](https://github.com/darpa-i2o/Transparent-Computing); [Kairos](https://arxiv.org/pdf/2308.05034)). That maps almost one-to-one onto `linux_process`, `linux_file` and `network_connection`.

The **official ground truth is prose only**. TA5.1 wrote PDF reports with IOCs that "should be (but are not always) present in the data", and the IPs and domains in them are fictional ([README-E3](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)). Usable labels come from research groups, and the two main label sets differ by orders of magnitude. **ThreaTrace** (MIT) publishes one CDM UUID per line: 25,358 unique UUIDs for THEIA, 12,858 for CADETS and 68,172 for TRACE ([ThreaTrace cadets.txt](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/groundtruth/cadets.txt)). **Orthrus/PIDSMaker** (Apache-2.0, maintained into 2026) curates per-attack key nodes and drops failed or off-host attacks. For THEIA E3 that leaves Firefox_Backdoor_Drakon_In_Memory with 58 nodes and Browser_Extension_Drakon_Dropper with 61. For CADETS E3 it leaves three partially successful Nginx backdoors with 8, 43 and 24 nodes. THEIA E5 gets 70 nodes ([Orthrus labels](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/main/Ground_Truth/orthrus/readme.md)). Against the roughly 699k benign nodes in THEIA E3 ([Orthrus README](https://raw.githubusercontent.com/ubc-provenance/orthrus/main/README.md)), the Orthrus set makes a precise "key malicious entities" answer key, while ThreaTrace serves as a lenient "anything attack-related" key. A task spec must name which one it scores against.

Size is the obstacle. PIDSMaker's preprocessed Postgres dumps are the lightest entry point: **THEIA_E3 is 1.1 GB compressed and 12 GB loaded**, and CADETS_E3 is 1.4 GB and 10.1 GB. E5 jumps to 36 GB loaded for THEIA and 276 GB for CADETS. CLI download requires a Google OAuth token ([PIDSMaker install](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/settings/ten-minute-install.md)). The raw route is per-topic JSON tarballs such as `ta1-theia-e3-official-6r.json.tar.gz` from Google Drive. MAGIC warns that every split chunk must be kept, because entity definitions for malicious nodes appear in later chunks ([MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)). No DARPA slice under 100 MB was found.

Data quality needs explicit handling. Several attacks only partly succeeded; on THEIA E3, for example, the drakon loader failed but the micro APT ran, so expected answers should distinguish attempted from succeeded steps. ClearScope E3 (Android) has null netflow nodes and should be skipped ([PIDSMaker velox README](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/README.md)). None of the datasets ships an official ATT&CK mapping, so technique tags must be hand-assigned from the GT reports. Likely candidates are T1190 for the Nginx exploit, T1189/T1203 for Firefox, T1055 for libdrakon injection into sshd and T1068 for elevation.

OpTC, ATLAS, ATLASv2 and FiveDirections are **Windows-only** ([OpTC-data](https://github.com/FiveDirections/OpTC-data); [ATLAS](https://raw.githubusercontent.com/purseclab/ATLAS/main/README.md)). They add nothing to a Linux track, though OpTC's eCAR process/file/flow model could provide a Windows contrast to the existing OTRF material.

## Academic auditd and syscall sets trade convenience for labelled realism

**AIT-LDS v2.0** is the most attractive academic candidate on paper. It covers eight testbeds simulating enterprise networks with mail, file share, WordPress, VPN and firewall components. It collects "low-level Audit logs, Apache access logs, DNS logs, syslog" and pcaps "from every component in the network", with **line-level ground truth** naming the attack step ([Landauer et al.](https://www.skopik.at/ait/2024_cset.pdf); [ACM](https://dl.acm.org/doi/fullHtml/10.1145/3675741.3675748)). A log-parsing study confirms the layout: `<scenario>/gather/<host>/logs/audit`, for example `russellmitchell/gather/intranet_server/logs/audit` ([arXiv 2504.04877](https://arxiv.org/pdf/2504.04877)).

Line-level labels on auditd are the closest thing to Sysmon-quality event truth on Linux, and the benign user simulation supplies a real negative class. The cost is conversion. Raw auditd spreads one logical event across SYSCALL, EXECVE, CWD, PATH, SOCKADDR and PROCTITLE records that share a serial number, and process trees have to be rebuilt from `pid`/`ppid` plus clone/fork syscalls. File sizes, the exact attack steps and the licence (believed CC BY) could not be verified because Zenodo was unreachable. Confirm all three before committing.

**LID-DS 2021** offers 15 CVE- or CWE-linked scenarios in Docker containers. Each recording is a zip containing a sysdig `.sc` syscall trace (timestamp, uid, pid, process name, tid, syscall name, direction, and parameters including fd paths and socket tuples), a `.pcap`, JSON metadata with the exploit timestamp, and resource stats ([dataloader source](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_2021.py); [CRITIS 2022](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)). Downloads are public Proton Drive links with no registration ([LID-DS](https://github.com/LID-DS/LID-DS)). Its natural task shape is "was this container exploited, and which process did it?". The graph needs fork tracking from clone return values to get parent edges, and the scope is a single service rather than a host.

**CICAPT-IIoT2024** ships auditd-derived SPADE provenance graphs from an APT29 Caldera campaign covering more than 20 techniques ([UNB](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html); [CLIProv](https://arxiv.org/pdf/2507.09133)). However, a later paper reports that system provenance came from only one node ([ProvICS](https://arxiv.org/html/2607.05989)). Its label granularity and size still need checking.

**NodLink's** Ubuntu 20.04 host hw17 provides small `benign.json`/`anomaly.json` files with a written attack annotation ([NodLink](https://github.com/Nodlink/Simulated-Data)). It is a cheap second Linux scenario if its schema converts cleanly.

The two **OTRF Linux datasets** are raw, complete auditd: SYSCALL with ppid, pid, auid, uid and exe; EXECVE argv; CWD; PATH with inode; and hex PROCTITLE. Each covers one Atomic Red Team command (ARP discovery T1018; `dd` binary padding T1027.001) ([OTRF metadata](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/_metadata/SDLIN-201110074812.yaml)). They are too small and too clean to pose an investigation, but they make ideal unit-test fixtures for an auditd parser.

The notes conflict on OTRF's Log4Shell compound dataset. Its notebook page describes auditd, syslog and Sysmon-for-Linux files ([securitydatasets.com](https://securitydatasets.com/notebooks/compound/Log4Shell.html)). Yet a path search of the cloned repository found no Linux data beyond the two atomic files. Treat it as unconfirmed until you locate the files.

Three syscall-based datasets should be excluded:

- **ADFA-LD** stores traces as integer syscall IDs only, and commercial use is prohibited ([UNSW](https://research.unsw.edu.au/projects/adfa-ids-datasets)).
- **DongTing** is about 85 GB of syscall sequences ([Zenodo](https://zenodo.org/records/6627050)).
- **TON_IoT Linux** is atop resource snapshots, with no parent links or command lines ([arXiv 2010.08521](https://arxiv.org/pdf/2010.08521)).

None of them contains file or network entities to walk.

## Cloud, Kubernetes, macOS and honeypot data fill side tracks only

Outside Linux hosts, the public ecosystem offers graphs of different shapes. CloudTrail datasets yield principal → API call → resource graphs rather than process trees. Honeypots give attacker session chains with no benign class. The Kubernetes sets are network flows and metrics without runtime telemetry.

| Dataset | Licence / access | Format | Size | Truth | Use |
|---|---|---|---|---|---|
| Stratus Red Team detonation logs | Datadog docs, open | CloudTrail JSON per technique, anonymised with LogLicker | KB per technique | One ATT&CK technique per log | Cloud identity side-cases |
| Invictus aws_dataset | MIT | CloudTrail from a Stratus simulation | Unverified, small repo | Scenario-level | Same |
| flaws.cloud CloudTrail | Summit Route release; Kaggle mirror says Apache-2.0 | CloudTrail | ~240 MB, 1.94M events | None per event; mostly attacker traffic | Hunting practice, weak benign baseline |
| Splunk BOTSv3 | CC0 | Pre-indexed Splunk app incl. `osquery:results`, `linux_audit`, `linux_secure`, O365/AAD | 320.1 MB | CTF questions and answers | Rich, but needs Splunk to export |
| LANL cyber1 | LANL public release; terms unverified | auth/proc/flows/dns/redteam text | ~12 GB compressed, 1.65B events | 749 red-team auth events | Windows/AD lateral movement only; proc has no parent or cmdline |
| Sever & Dogan K8s | GitHub, no licence | CICFlowMeter flows | Unverified | 11 labels incl. CVE-2019-5736 runc escape | No host entities |
| Kube-IDS0 / DataPort pod metrics | Kaggle / IEEE DataPort | pcap, flows, Prometheus metrics | Unverified | DoS, brute force, SQLi | No host entities |
| Cowrie 160-instance set | Zenodo | JSON/JSONL sessions plus 1,770 captured files | 211M events | All hostile | Malicious-only; contains live malware |
| shell-attack-evolution | GitHub / HF | ATT&CK-annotated Cowrie commands | Unverified | Command-level ATT&CK | Graft attacker chains onto benign hosts |
| sbousseaden macOS-ATTACK-DATASET | GitHub | Elastic Endpoint (macOS) JSON per technique | Small | Technique per file | Only public macOS endpoint set; ~2020–21 |

Sources: [Stratus](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/), [Invictus](https://github.com/invictus-ir/aws_dataset), [Summit Route](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/), [flaws size](https://medium.com/@george.fekkas/quick-and-dirty-cloudtrail-threat-hunting-log-analysis-b64af10ef923), [BOTSv3](https://github.com/splunk/botsv3), [LANL readme](https://dibbs.ai.arizona.edu/dibbs/comprehensive-multi-source-cybersecurity-events/readme.txt), [G-Research loader](https://github.com/G-Research/dgraph-lanl-csr), [K8s dataset](https://github.com/yigitsever/kubernetes-dataset), [Kube-IDS0](https://www.kaggle.com/datasets/redamorsli/kube-ids0), [Cowrie Zenodo](https://zenodo.org/records/21260400), [shell-attack-evolution](https://github.com/zyw-286/shell-attack-evolution-dataset), [macOS dataset](https://github.com/sbousseaden/macOS-ATTACK-DATASET).

Two points deserve emphasis. First, licensing for the UNSW sets (UNSW-NB15, TON_IoT) is academic-only or copyright-reserved ([UNSWorks](https://unsworks.unsw.edu.au/items/4dc0e35c-6196-4c9d-945a-c50b981e5955)), which rules them out of commercial demos even before considering their lack of host entities. Second, **no public labelled Kubernetes corpus with host runtime telemetry was found**. Kubernetes Goat has a Tetragon container-escape lab ([Kubernetes Goat](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-21/ebpf-runtime-security-monitoring-and-detection-in-kubernetes-cluster-using-cilium-tetragon/welcome/)) and Falco ships event-generator, so a Kubernetes track means recording your own captures. A useful side effect of self-generation is that you control the labels exactly.

## Ranked starting set and how to convert each

The ranking weighs three factors: label quality at the entity level, conversion cost given the existing Sysmon converter, and disk footprint on a Hetzner server.

### 1. Splunk attack_data Sysmon-for-Linux files: start here this week

The Splunk files share the Windows Sysmon schema, so the converter needs a platform switch rather than a rewrite. The mapping is:

- **EID 1** → a `linux_process` node keyed by ProcessGuid, plus a `linux_process_create` edge from ParentProcessGuid.
- **The User field** → a `linux_user` node.
- **EID 3** → `connected_to` a `network_connection`.
- **EID 11** → `wrote_file` to a `linux_file`.
- **EID 5 and EID 23** → end-time and deleted attributes.

Two vocabulary gaps need decisions. First, Sysmon for Linux emits no separate fork record (the inspected file contains only EIDs 1, 3, 5, 9, 11 and 23), so `forked` and `execve_transitioned` cannot be distinguished. Record every EID 1 as `linux_process_create`. Second, a `systemd_unit` node can only be inferred, for example from a ParentImage of systemd plus the persistence techniques' file writes under `/etc/systemd/`.

Fetch only chosen files from `media.githubusercontent.com`. Time-window each file around the technique's EID 1 events to strip forwarder FileCreate noise. Then derive labels by marking the Atomic command's process subtree and its file and socket neighbours as malicious. The 48 SnapAttack files are the same format and add community-authored variety.

### 2. DARPA TC E3 THEIA (Linux), with CADETS E3 as a FreeBSD variant: the scored benchmark

This is the only option where the answer key names malicious entities. Load PIDSMaker's THEIA_E3 dump (1.1 GB download, 12 GB in Postgres) on a temporary Hetzner volume or a workstation, not on the production disk. Then export per-attack subgraphs: the Orthrus key nodes, their 2-hop neighbourhood, and sampled benign processes from the same time window. Each export should come to a few MB of JSON. Keep only the exports.

The mapping:

- **Subject** → `linux_process`.
- **FileObject** → `linux_file`.
- **NetFlowObject** → `network_connection`.
- **EVENT_FORK/CLONE** → `forked`.
- **EVENT_EXECUTE** → `execve_transitioned`.
- **EVENT_WRITE / EVENT_READ** → `wrote_file` / read edges.
- **EVENT_CONNECT** → `connected_to`.

Take the exact CDM event names from the shipped `CDM18.avdl`. Score against Orthrus for precision and against ThreaTrace for recall, and encode partial-success attacks in the expected answer. This dataset is the strongest fit for the `forked` vs `execve_transitioned` distinction in the target vocabulary.

### 3. AIT-LDS v2 auditd: the realistic multi-host Linux track, pending verification

Before downloading, confirm the licence and per-scenario sizes on Zenodo, then pull one scenario's audit logs for the affected hosts. Build or adopt an auditd reassembler that groups records by `msg=audit(ts:serial)`. Map them as follows:

- **SYSCALL execve plus EXECVE argv** → `linux_process` with `execve_transitioned`.
- **clone/fork return pids** → `forked`.
- **openat/write with PATH records** → `linux_file` and `wrote_file`.
- **connect with SOCKADDR** → `connected_to`.
- **auid/uid** → `linux_user`.

The two OTRF auditd files are ready-made parser fixtures for this. Propagate AIT's line-level labels to the entities each labelled line touches. That yields true event-derived entity labels on Linux, with a real benign user population, and the Apache and DNS logs add cross-host context.

### 4. LID-DS 2021: compact container-exploit tasks

Download individual scenario recordings and parse the `.sc` sysdig lines. Track clone/fork return values to rebuild parent edges, map execve to `execve_transitioned`, resolve fd parameters to `linux_file` and `wrote_file`, and resolve socket tuples to `connected_to` (with `unix_socket` for AF_UNIX fds). Label the exploited process and everything it spawns after the metadata's exploit timestamp as malicious, and treat the normal recordings as benign controls. The tasks are narrow, one service per container, but cheap and numerous.

### 5. NodLink hw17 plus OTRF Linux atomics: smoke tests

Use NodLink's Ubuntu `benign.json`/`anomaly.json` as a second end-to-end Linux scenario if its schema maps cleanly. Use the two OTRF auditd captures as regression fixtures for the auditd path. Neither is a benchmark on its own.

## Conclusion

The Linux side of the security-dataset ecosystem is roughly where Windows was before OTRF. It has one vendor corpus with real sensors but recording-level truth (Splunk), and one academic corpus with entity-level truth but heavyweight distribution (DARPA TC). In between sit a few labelled academic sets that nobody has yet normalised into graphs. So the unique asset in this project is not any single dataset but the **label-derivation and subgraph-extraction layer**: the code that turns "this folder is T1543.002" or "these 58 UUIDs are malicious" into per-entity answer keys at task scale. Publishing that layer, together with the extracted sub-100 MB task graphs (both permitted by Apache-2.0 and public-domain terms), would itself be a contribution.

The second implication is that the vocabulary is ahead of the data. `forked` vs `execve_transitioned`, `unix_socket` and `systemd_unit` are expressible in DARPA CDM, auditd and sysdig, but not in Sysmon for Linux. Kubernetes runtime evidence does not exist publicly at all. Expect to self-record a small Tetragon or Falco corpus, using Atomic Red Team and Kubernetes Goat, to cover those relations with labels you fully control.
