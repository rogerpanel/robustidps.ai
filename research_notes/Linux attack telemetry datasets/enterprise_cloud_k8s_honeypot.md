# Enterprise multi-source, Kubernetes/container, cloud, network and honeypot security datasets: what to add to a Linux-focused SOC investigation benchmark

Research date: 2026-10-10. Research environment note: from this sandbox, csr.lanl.gov, lanl.ma.ic.ac.uk, research.unsw.edu.au, zenodo.org, arxiv.org/ar5iv and securitydatasets.com all failed DNS resolution or returned proxy 403. **That is a sandbox restriction. It is not evidence that the links are broken publicly.** As a result, many facts below come from search-engine snippets of those official pages, from mirrors (GitHub, Kaggle, the FKIE COMIDDS catalogue) or from papers, and are cited as such. GitHub pages could be fetched directly.

## Q1. Publisher, download location and licence/terms

### Takeaway
Licensing is clean for the cloud, Splunk BOTS and GitHub-hosted sets: CC0 (BOTSv3), MIT (Invictus AWS), GPL-3.0 (LID-DS code and OTRF repo, with a conflicting MIT label on a mirror) and Apache-2.0 on a Kaggle mirror of flaws.cloud. **The UNSW sets (UNSW-NB15, TON_IoT) are academic-only or copyright-reserved.** LANL's terms could not be verified from here. CSE-CIC-IDS2018 explicitly allows redistribution with citation.

### Cited Findings
**LANL "Comprehensive, Multi-Source Cyber-Security Events" (cyber1)**
- Published by LANL's Advanced Research in Cyber Systems at csr.lanl.gov/data/cyber1/. The files are auth.txt.gz, proc.txt.gz, flows.txt.gz, dns.txt.gz and redteam.txt.gz. Citation: Kent, A. D., LANL, doi 10.17021/1179829 (2015) — [LANL cyber1 page (search snippet)](https://csr.lanl.gov/data/cyber1/); [Arizona DIBBS mirror readme](https://dibbs.ai.arizona.edu/dibbs/comprehensive-multi-source-cybersecurity-events/readme.txt)
- Mirrors and derivatives exist: Imperial College (lanl.ma.ic.ac.uk), Arizona DIBBS, Hugging Face (Taqui/lanl-cyber-datasets) and a G-Research Dgraph loader — [Imperial mirror](https://lanl.ma.ic.ac.uk/data/cyber1/); [HF](https://huggingface.co/datasets/Taqui/lanl-cyber-datasets); [G-Research dgraph-lanl-csr](https://github.com/G-Research/dgraph-lanl-csr)
- The G-Research loader repo states no licence for the LANL data — [G-Research dgraph-lanl-csr](https://github.com/G-Research/dgraph-lanl-csr)

**LANL "Unified Host and Network Data Set" (2017)**
- Published at csr.lanl.gov/data/2017/ as daily files (e.g. `wls_day-$i.bz2`). It is also mirrored at lanl.ma.ic.ac.uk/data/2017/ and listed on IMPACT (idDataset=919) — [LANL 2017 page (search snippet)](https://csr.lanl.gov/data/2017/); [Imperial mirror](https://lanl.ma.ic.ac.uk/data/2017/); [IMPACT](https://www.impactcybertrust.org/dataset_view?idDataset=919)
- LANL describes the two data sets as "released ... for public use" (Kent 2014, 2016) — [Unified Host and Network Data Set paper (ar5iv snippet)](https://ar5iv.arxiv.org/html/1708.07518)

**CIC / UNB**
- CSE-CIC-IDS2018 (CIC and the Communications Security Establishment, hosted on AWS Open Data). UNB terms: "You may redistribute, republish, and mirror the CSE-CIC-IDS2018 dataset in any form. However, any use or redistribution of the data must include a citation ... and a link to this page in AWS." Third-party mirrors carry different labels: Kaggle CC BY-NC-SA 4.0 and Mendeley CC BY 4.0 — [UNB IDS 2018](https://www.unb.ca/cic/datasets/ids-2018.html); [AWS Registry](https://registry.opendata.aws/cse-cic-ids2018/); [Kaggle mirror](https://www.kaggle.com/datasets/dhoogla/csecicids2018); [Mendeley mirror](https://data.mendeley.com/datasets/29hdbdzx2r/1)
- CICAPT-IIoT2024 is hosted by UNB CIC at unb.ca/cic/datasets/iiot-dataset-2024.html, with the paper at arXiv 2407.11278 — [UNB IIoT 2024](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html); [arXiv 2407.11278](https://arxiv.org/pdf/2407.11278)

**UNSW**
- UNSW-NB15 (UNSW Canberra Cyber Range). UNSWorks: "free use is granted for academic research, and commercial use is strictly prohibited". The metadata record also lists a "GPL" rights field, which conflicts — [UNSWorks access](https://unsworks.unsw.edu.au/items/4dc0e35c-6196-4c9d-945a-c50b981e5955); [UNSWorks full record](https://unsworks.unsw.edu.au/entities/dataset/4dc0e35c-6196-4c9d-945a-c50b981e5955/full)
- TON_IoT: "The Copyright is reserved to the Author, Dr Nour Moustafa ... sponsored by the Australian Research Data Commons ... should be publicly published." DOIs are 10.26190/5d7ac9bfe8487 (UNSW) and 10.21227/fesz-dm97 (IEEE DataPort). No open licence was found — [UNSWorks TON_IoT record](https://unsworks.unsw.edu.au/entities/dataset/6e5fb343-fcd7-42ce-99c8-2c64acd301a6/full); [IEEE DataPort](https://ieee-dataport.org/documents/toniot-datasets); [UNSW project page](https://research.unsw.edu.au/projects/toniot-datasets)

**Linux host / container syscall sets**
- LID-DS (Leipzig Intrusion Detection Data Set) 2019 and 2021. The GitHub library and framework are GPL-3.0-or-later (copyright 2022–2025). Data downloads are Proton Drive links on the GitHub README — [LID-DS GitHub](https://github.com/LID-DS/LID-DS)
- The AIT Log Data Set V2.0 (AIT-LDSv2) is on Zenodo (record 5789064, referenced by secondary sources). Its predecessor, the Kyoushi Log Data Set, is Zenodo 5779411. A derived AIT Netflow set is Zenodo 6610489 — [Kyoushi Zenodo](https://zenodo.org/records/5779411); [AIT Netflow Zenodo](https://zenodo.org/records/6610489); [AIT alert-data-set GitHub](https://github.com/ait-aecid/alert-data-set)

**Kubernetes / container**
- Sever & Dogan, "A Kubernetes dataset for misuse detection" (ITU J-FET vol. 4 issue 2, June 2023). Data is at github.com/yigitsever/kubernetes-dataset (no licence stated), and an updated version is on Kaggle — [GitHub](https://github.com/yigitsever/kubernetes-dataset); [ITU paper PDF](https://www.itu.int/dms_pub/itu-s/opb/jnl/S-JNL-VOL4.ISSUE2-2023-A26-PDF-E.pdf)
- "Kubernetes Intrusion Detection Datasets" (Kaggle redamorsli/kube-ids0) — [Kaggle](https://www.kaggle.com/datasets/redamorsli/kube-ids0)
- "Pod-Level Labelled Resource Utilization Dataset for Intrusion Detection in Kubernetes" (IEEE DataPort, DOI 10.21227/mg8w-cs31). Some DataPort tooling is restricted to institutional subscribers — [IEEE DataPort](https://ieee-dataport.org/documents/pod-level-labelled-resource-utilization-dataset-intrusion-detection-kubernetes)

**Cloud**
- Stratus Red Team (Datadog). Each technique page has a "Detonation logs" section of raw CloudTrail JSON captured with Grimoire and anonymised with LogLicker — [Stratus: cloudtrail-stop](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/); [Stratus: event-selectors](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-event-selectors/)
- invictus-ir/aws_dataset: "A dataset with CloudTrail events from an attack simulation using Stratus". MIT licence, 3 commits — [GitHub](https://github.com/invictus-ir/aws_dataset)
- flaws.cloud CloudTrail logs, released by Summit Route (Scott Piper) in October 2020 for security research. A Kaggle mirror lists Apache 2.0 (not verified against Summit Route's own terms) — [Summit Route blog](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/); [Kaggle mirror](https://www.kaggle.com/datasets/nobukim/aws-cloudtrails-dataset-from-flaws-cloud)
- OTRF Security-Datasets (formerly Mordor). GitHub lists GPL-3.0 and a SourceForge mirror says MIT (conflict) — [GitHub](https://github.com/OTRF/Security-Datasets); [SourceForge mirror](https://sourceforge.net/projects/security-datasets.mirror/)
- Splunk attack_data: replayable datasets with per-dataset pages on research.splunk.com, e.g. an aws:cloudtrail dataset from attack_range, replayed with `replay.py --dataset` — [Splunk research attack_data entry](https://research.splunk.com/attack_data/09f580b9-cbc0-4d90-8e26-7dd4584a5650/)
- Splunk Boss of the SOC v3 (BOTSv3) has a CC0-1.0 licence on GitHub. The download is a 320.1 MB pre-indexed Splunk app (MD5 d7ccca99a01cff070dff3c139cdc10eb on the official repo). An older blog route required emailing bots@splunk.com — [GitHub splunk/botsv3](https://github.com/splunk/botsv3); [Splunk blog](https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html)

**Honeypot**
- Zenodo 21260400: "Deployment of 160 Cowrie SSH honeypot instances across four distinct configurations" — [Zenodo](https://zenodo.org/records/21260400)
- CyberLab honeynet dataset (Zenodo 10.5281/zenodo.3687527) — [OpenAIRE](https://explore.openaire.eu/search/dataset?pid=10.5281%2Fzenodo.3687527)
- shell-attack-evolution-dataset: ATT&CK-annotated Cowrie data (2021–22 vs 2024) from an IEEE SRDS 2025 paper, also on Hugging Face — [GitHub](https://github.com/zyw-286/shell-attack-evolution-dataset)
- "Honey for the Agent": LLM-agent attackers against one real Ubuntu server and four Cowrie variants (Zenodo 20818246) — [Zenodo](https://zenodo.org/records/20818246)
- DShield/SANS ISC: no official bulk research download was found. Sensor owners can download raw firewall, web and ssh/telnet logs from the portal. On-sensor Cowrie JSON is rotated and only 7 days are kept — [ISC diary 30024](https://isc.sans.edu/diary/DShield%20Honeypot%20Maintenance%20and%20Data%20Retention/30024)

**macOS**
- sbousseaden/macOS-ATTACK-DATASET: JSON recorded with Elastic Endpoint Security for macOS, organised by ATT&CK tactic. Last updated about 2,083 days ago (around 2020–21) — [GitHub](https://github.com/sbousseaden/macOS-ATTACK-DATASET)

### Inferences
- For a benchmark that will be demoed and published, the lowest-friction sources are BOTSv3 (CC0), the Invictus AWS set (MIT), the Stratus detonation logs (embedded in open documentation), LID-DS (GPL library and public downloads) and CSE-CIC-IDS2018 (redistribution allowed with citation).
- Data from UNSW-NB15 and TON_IoT should only be used for non-commercial academic purposes unless written permission is obtained.

### Gaps
- LANL's licence or terms of use could not be read because csr.lanl.gov was unreachable. In particular, it is unverified whether cyber1 needs a registration or acceptance form before download. Check the page directly.
- The CIC-IDS2017 licence was not confirmed. It is probably the same template as IDS2018, but that is unverified.
- The LID-DS dataset (data, not code) licence, AIT-LDSv2 licence (believed CC BY on Zenodo, unverified) and Cowrie Zenodo record licences were not verified.
- The Splunk attack_data repo page timed out (504), so its licence (believed Apache-2.0, unverified) and full source-type list were not confirmed.

## Q2. Format, entities and relations: which carry host-level process/file/user/connection detail?

### Takeaway
Few public datasets beyond Windows telemetry give process-tree-quality host data with ground truth.

- **Strong host-level process/file detail:** LID-DS (container syscalls), AIT-LDSv2 (auditd plus app logs, multi-host), OTRF Log4Shell (auditd, syslog, Sysmon for Linux), BOTSv3 (osquery, linux_audit), CICAPT-IIoT2024 (auditd-derived SPADE provenance graph) and the macOS ESF JSON.
- **Coarse host data:** LANL cyber1 proc.txt has only process-name start/end per user and computer, with no parent and no command line. TON_IoT Linux has atop per-process resource counters, with no parent/child and no command lines.
- **Network or authentication only:** UNSW-NB15, the Sever & Dogan K8s set, Kube-IDS0, CIC-IDS2017 flows and the LANL auth/flows/dns files.
- **Cloud API events, not hosts:** Stratus, Invictus, flaws.cloud and OTRF AWS.
- **Honeypots:** attacker sessions and commands, with no OS process tree.

### Cited Findings
**LANL cyber1 (enterprise, mostly Windows, multi-source)**
- 58 consecutive days of de-identified events from five sources on LANL's internal network — [LANL cyber1 page snippet](https://csr.lanl.gov/data/cyber1/)
- proc.txt example line: `1,C553$@DOM1,C553,P16,Start`, i.e. time, user@domain, computer, process name and start/end. Missing values are shown as `?` — [LANL cyber1 page snippet](https://csr.lanl.gov/data/cyber1/); [Alan Turing Institute notes](https://alan-turing-institute.github.io/wrangling-tests/2017/01/31/lanl/)
- redteam.txt example: `151648,U748@DOM1,C17693,C728`, i.e. time, user@domain, source computer and destination computer — [LANL cyber1 page snippet](https://csr.lanl.gov/data/cyber1/)
- Graph model in the Dgraph loader: AuthEvent (6 properties, 2 edges), ProcessEvent (4 properties, 1 edge), FlowDuration (9 properties, 2 edges), DnsEvent (2/2) and CompromiseEvent (2/2). It adds User, Computer and ComputerUser entities: 100,162 User nodes, 17,684 Computer nodes and 900,983 ComputerUser nodes — [G-Research dgraph-lanl-csr](https://github.com/G-Research/dgraph-lanl-csr)
- Missing values: authentication type is null in 55% of auth rows and logon type in 14%; flow source port is null in 71% and destination port in 64% — [G-Research dgraph-lanl-csr](https://github.com/G-Research/dgraph-lanl-csr)

**LANL Unified Host and Network (2017)**
- About 90 days of data. The host logs come from most of LANL's Windows computers via the Windows Logging Service. The NetFlow v9 records come from core routers and cover 89 days because the first day is missing. Format: JSON, one record per line, daily files — [arXiv 1708.07518](https://arxiv.org/pdf/1708.07518); [LANL 2017 page snippet](https://csr.lanl.gov/data/2017/)
- Event IDs include 4688/4689 (process start/end), 4608/4609 and 1100, with logon events 4624/4625/4634 referenced. Flow fields: Time, Duration, SrcDevice, DstDevice, Protocol, SrcPort, DstPort, SrcPackets, DstPackets, SrcBytes, DstBytes. De-identified IDs are consistent across the host and network files, so they can be joined. Some system hosts and user names were left unmasked — [arXiv 1708.07518](https://arxiv.org/pdf/1708.07518); [Imperial mirror snippet](https://lanl.ma.ic.ac.uk/data/2017/)

**CIC / UNB**
- CSE-CIC-IDS2018: per day and per machine, raw PCAPs plus "event logs (windows and Ubuntu event Logs)". The IT department machines run Ubuntu. Ubuntu logs sit under paths such as `Network Traffic and Log data/Friday-16-02-2018/logs/U172.31.69.25` — [UNB IDS 2018](https://www.unb.ca/cic/datasets/ids-2018.html); [FKIE COMIDDS](https://fkie-cad.github.io/COMIDDS/content/datasets/cse_cic_ids2018/)
- CIC-IDS2017: five days of network traffic with 80 CICFlowMeter flow features. No host logs were found in the sources checked — [FKIE COMIDDS / search summary](https://fkie-cad.github.io/COMIDDS/content/datasets/cse_cic_ids2018/); [arXiv 2203.05232](https://arxiv.org/pdf/2203.05232)
- CICAPT-IIoT2024: "Provenance data and network logs", each collected in two phases. Auditd collects the system logs and SPADE builds provenance graphs from them (secondary source; the paper describes SPADE tracking provenance from OS auditing) — [UNB IIoT 2024](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html); [Moonlight review](https://www.themoonlight.io/en/review/cicapt-iiot-a-provenance-based-apt-attack-dataset-for-iiot-environment); [arXiv 2407.11278](https://arxiv.org/pdf/2407.11278)
- One later paper says CICAPT-IIoT system provenance was collected from only a single node — [ProvICS arXiv 2607.05989](https://arxiv.org/html/2607.05989)

**UNSW-NB15 / TON_IoT**
- UNSW-NB15: 100 GB of raw traffic generated with IXIA PerfectStorm and captured with tcpdump. 49 features plus a class label were built with Argus and Bro-IDS. PCAP, Bro, Argus and CSV files are available. This is network data only — [UNSW-NB15 page](https://research.unsw.edu.au/node/134656)
- TON_IoT Linux: atop captured memory, process and disk data on Ubuntu 14 and 18. Raw data is in TXT/CSV. Feature groups cover disk, memory and process scheduling (about 34 features cited). It has `label` and `type` columns. TON_IoT also includes Windows 7/10 datasets (around 125 features for Windows 10) — [arXiv 2010.08521](https://arxiv.org/pdf/2010.08521); [UNSW TON_IoT page snippet](https://research.unsw.edu.au/projects/toniot-datasets); [arXiv 2010.08522 (Windows)](https://arxiv.org/pdf/2010.08522)

**Linux host / container syscall and log sets**
- LID-DS 2019: a single Ubuntu 18.04 host inside a Docker container. LID-DS 2021: an x86_64 Docker environment with system calls plus network traffic, labels for benign and malicious behaviour, and 15 CVE- or CWE-linked scenarios — [FKIE COMIDDS LID-DS 2019](https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/); [LID-DS 2021 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- The LID-DS library loader also reads ADFA-LD, CTF (WRTD) and scap (CB-DS) recordings — [LID-DS GitHub](https://github.com/LID-DS/LID-DS)
- AIT-LDSv2: eight testbeds simulating enterprise networks with mail servers, file shares, WordPress, VPN and firewall. Data includes PCAPs and logs: "low-level Audit logs, Apache access logs, DNS logs, syslog", "from every component in the network", with line-level ground truth — [Landauer et al. AIT-ADS paper](https://www.skopik.at/ait/2024_cset.pdf); [ACM full text](https://dl.acm.org/doi/fullHtml/10.1145/3675741.3675748); [arXiv 2602.06777](https://arxiv.org/pdf/2602.06777)
- OTRF Log4Shell compound dataset: host and network files including auditd, syslog and Sysmon for Log4Shell exploitation, plus Azure VM Insights / Log Analytics-style files — [securitydatasets.com Log4Shell (search snippet)](https://securitydatasets.com/notebooks/compound/Log4Shell.html)
- BOTSv3 source types include `osquery:info`, `osquery:results`, `osquery:warning`, `linux_audit` and `linux_secure`, plus Microsoft 365 and Azure AD types (`ms:aad:audit`, `ms:aad:signin`, `ms:o365:management`). A CloudTrail source type was not seen in the visible part of the list — [GitHub splunk/botsv3](https://github.com/splunk/botsv3)

**Kubernetes / container**
- Sever & Dogan: flows generated from PCAPs with a CICFlowMeter fork (`benign.csv`, `malicious.csv`). No syscalls or audit logs — [GitHub](https://github.com/yigitsever/kubernetes-dataset)
- Kube-IDS0 (Kaggle): DVWA and Google Bank of Anthos on K8s. Contains packet captures, TCP flows, container metrics and cluster metrics. No syscalls — [Kaggle](https://www.kaggle.com/datasets/redamorsli/kube-ids0)
- IEEE DataPort pod-level set: CPU, memory and disk I/O traces collected with Prometheus exporters — [IEEE DataPort](https://ieee-dataport.org/documents/pod-level-labelled-resource-utilization-dataset-intrusion-detection-kubernetes)
- Falco/Tetragon/Tracee: a 2025 comparison study tested container escape, DoS and cryptomining. Kubernetes Goat has a Tetragon nsenter-escape lab. No released labelled recording corpus was found — [SciTePress 2025](https://www.scitepress.org/Papers/2025/142727/142727.pdf); [Kubernetes Goat scenario 21](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-21/ebpf-runtime-security-monitoring-and-detection-in-kubernetes-cluster-using-cilium-tetragon/welcome/)

**Cloud**
- flaws.cloud: default multi-region CloudTrail management events, without S3 data-event or Lambda logging. Entities are IAM principal, source IP, user agent, API eventName and resources — [Summit Route blog](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/); [Medium analysis](https://medium.com/@george.fekkas/quick-and-dirty-cloudtrail-threat-hunting-log-analysis-b64af10ef923)
- OTRF atomic AWS: two datasets, an S3 honeybucket log set (2022) and abuse of a misconfigured EC2 reverse proxy to reach S3 (2020) — [securitydatasets.com AWS (search snippet)](https://securitydatasets.com/notebooks/atomic/aws/intro.html)

**Honeypot**
- Cowrie logs capture attempted usernames and passwords, commands run by bots or users, and file uploads and downloads — [ISC diary 30024](https://isc.sans.edu/diary/DShield%20Honeypot%20Maintenance%20and%20Data%20Retention/30024)
- Zenodo 21260400 has JSON/JSONL events plus a session-level aggregation file and 1,770 captured files. **These are live malware payloads** — [Zenodo](https://zenodo.org/records/21260400) (via search snippet)
- shell-attack-evolution-dataset contains command-to-response pairs with session data — [GitHub](https://github.com/zyw-286/shell-attack-evolution-dataset)

**macOS**
- sbousseaden JSON from Elastic Endpoint Security for macOS, organised by tactic (Execution, Persistence, Defense Evasion, ...) — [GitHub](https://github.com/sbousseaden/macOS-ATTACK-DATASET)

### Inferences
**Entity/relation availability.** Y = yes, P = partial, N = no.

| Dataset | Process + parent | Command line | Files | Network connection tied to process | Users |
|---|---|---|---|---|---|
| LANL cyber1 | name only, no parent (N) | N | N | flows are host-level only (N) | Y |
| LANL Unified | 4688 events, very likely with parent | unknown | N | NetFlow is device-level, not process-level | Y |
| CSE-CIC-IDS2018 Ubuntu logs | very limited (syslog/auth-style, not auditd) | N | N | N | partial |
| TON_IoT Linux | PID/command name with resource counters, no parent | N | N | N | partial |
| LID-DS | syscalls with thread/process | from execve args | Y (file descriptors / paths) | Y | Y |
| AIT-LDSv2 | auditd: Y | Y | Y | Y (plus app logs) | Y |
| OTRF Log4Shell | Y (Sysmon for Linux / auditd) | Y | Y | Y | Y |
| BOTSv3 | osquery / linux_audit: partial | partial | partial | partial | Y |
| CICAPT-IIoT2024 | SPADE provenance: Y | Y | Y | Y | Y (likely single node) |

- Cloud datasets give principal → API call → resource graphs, not process graphs.
- Honeypot datasets give source IP → session → login → command → downloaded file chains.
- Every row of LANL cyber1 is about Windows or AD (computer accounts such as `C553$`), so it would not exercise Linux reasoning. Its auth graph is still useful as an enterprise lateral-movement background.

### Gaps
- Exact column names were not verified for LANL Unified host events, TON_IoT Linux CSVs, the LID-DS 2021 recording format (the wiki was not fetched) or the AIT-LDSv2 auditd label layout.
- It was not confirmed whether CSE-CIC-IDS2018 Ubuntu logs include auditd. No source described their content beyond "Ubuntu event logs".
- The full BOTSv3 source-type list (cut off in the source) and the full Splunk attack_data source list (e.g. Sysmon for Linux, auditd, Kubernetes audit) could not be read because the page timed out.
- The OTRF Linux atomic dataset contents were only hinted at in GitHub issues.

## Q3. Size, and whether small subsets can be downloaded

### Takeaway
- **LANL cyber1:** about 12 GB compressed (1.65 B events), but redteam.txt (749 rows) and per-file downloads let you cut a time window around red-team events.
- **LANL Unified:** comes in daily files.
- **Already small:** flaws.cloud (about 240 MB), BOTSv3 (320 MB, Splunk-indexed), Stratus per-technique logs (KB-scale JSON), Invictus and OTRF.
- **Largest:** the 160-instance Cowrie set (211 M events).

### Cited Findings
- LANL cyber1: about 12 GB compressed and 1,648,275,307 events in total. Row counts are auth 1,051,430,459, proc 426,045,096, flows 129,977,412, dns 40,821,591 and redteam 749. Flows have 6,569,939 duplicates and redteam has 12. Flow collection stops on day 29 because of a router misconfiguration — [Arizona readme](https://dibbs.ai.arizona.edu/dibbs/comprehensive-multi-source-cybersecurity-events/readme.txt); [G-Research](https://github.com/G-Research/dgraph-lanl-csr)
- An arXiv paper reports "62,947" process events for LANL. That is far below 426 M rows, so it is probably a subset or distinct-process count — [arXiv 2208.13524](https://arxiv.org/pdf/2208.13524) (conflicts with [G-Research](https://github.com/G-Research/dgraph-lanl-csr) row count)
- LANL Unified: daily files of host (wls_day-N.bz2) and netflow, about 90 days — [LANL 2017 snippet](https://csr.lanl.gov/data/2017/)
- UNSW-NB15: 100 GB of raw PCAP — [UNSW-NB15 page](https://research.unsw.edu.au/node/134656)
- flaws.cloud: 1,939,207 events from 12 Feb 2017 to 7 Oct 2020, about 240 MB, 20 files. The original announcement says "nearly 2M log events from nearly 10K 'attackers'" — [Medium](https://medium.com/@george.fekkas/quick-and-dirty-cloudtrail-threat-hunting-log-analysis-b64af10ef923); [Summit Route on X](https://x.com/summitroute/status/1314675462182903808?lang=en); [cloudtrail-security-lakehouse](https://github.com/Pranjalmann10/cloudtrail-security-lakehouse)
- BOTSv3: 320.1 MB pre-indexed. It needs Splunk Enterprise; the free trial suffices — [GitHub splunk/botsv3](https://github.com/splunk/botsv3); [Splunk blog](https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html)
- Cowrie 160-instance set: more than 211 M events, 38 M SSH sessions and more than 214,000 source IPs. The CyberLab honeynet set had 34,772 events, 7,077 login attempts and 180 IPs on a single sample day (2019-05-18) — [Zenodo 21260400](https://zenodo.org/records/21260400); [OpenAIRE CyberLab](https://explore.openaire.eu/search/dataset?pid=10.5281%2Fzenodo.3687527)
- Stratus detonation logs are per-technique JSON snippets on documentation pages — [Stratus](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/)

### Inferences
- For LANL cyber1, a practical subset is: filter redteam.txt to (user, src, dst, time), then pull ±N minutes of auth/proc rows for those computers. This requires streaming the 12 GB of gzip once.
- LID-DS is organised per scenario and per recording, so single-scenario downloads are likely small. This is unverified.

### Gaps
- Sizes were not found for LID-DS 2021, AIT-LDSv2, CICAPT-IIoT2024, TON_IoT Linux, the Sever & Dogan K8s set, Kube-IDS0, the Invictus set, the OTRF Log4Shell set or the macOS JSON.

## Q4. Attacks included and type of ground truth

### Takeaway
**Event-level labels exist for:** LANL cyber1 (a red-team auth-event list only), TON_IoT (row label/type), UNSW-NB15 (flow label), the K8s flow sets (scenario label 0–10), LID-DS (per-recording exploit labels) and AIT-LDSv2 (line-level labels).

**Scenario-level ground truth only:** Stratus, Invictus and OTRF (each recording is one known technique) and BOTSv3 (CTF questions and answers).

**Effectively unlabelled:** LANL Unified, the CSE-CIC-IDS2018 host logs, flaws.cloud (mostly attacker traffic but no per-event labels) and honeypots (everything is hostile; the benign class is missing).

### Cited Findings
- LANL cyber1 redteam.txt: 749 authentication events performed by the red team using stolen credentials. It is the only ground truth, and it labels authentication events, not processes — [Arizona readme](https://dibbs.ai.arizona.edu/dibbs/comprehensive-multi-source-cybersecurity-events/readme.txt)
- CSE-CIC-IDS2018: the FKIE catalogue marks the host data as unlabelled — [FKIE COMIDDS](https://fkie-cad.github.io/COMIDDS/content/datasets/cse_cic_ids2018/)
- CICAPT-IIoT2024: emulates APT29, run from a Kali VM with MITRE Caldera, covering more than 20 techniques across 8 tactics — [UNB IIoT 2024](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html); [CLIProv arXiv 2507.09133](https://arxiv.org/pdf/2507.09133)
- TON_IoT: `label` (normal/attack) and `type` columns. Types: backdoor, DDoS, DoS, injection, MITM, password, ransomware, scanning, XSS and normal — [arXiv 2010.08521](https://arxiv.org/pdf/2010.08521); [ResearchGate TON_IoT Linux](https://www.researchgate.net/publication/344734866_Data_Analytics-enabled_Intrusion_Detection_Evaluations_of_ToN_IoT_Linux_Datasets)
- LID-DS 2021: benign and malicious labels across 15 CVE- or CWE-linked scenarios — [LID-DS 2021 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- AIT-LDSv2 is "fully labeled" with attack phases tied to log events and line-level ground-truth annotations. In the predecessor (Kyoushi), only log files from affected servers are labelled — [ACM](https://dl.acm.org/doi/fullHtml/10.1145/3675741.3675748); [Kyoushi Zenodo](https://zenodo.org/records/5779411)
- Sever & Dogan K8s attack labels:

  | Label | Scenario |
  |---|---|
  | 0 | Benign |
  | 1 | CVE-2020-13379 |
  | 2 | Node-RED reconnaissance |
  | 3 | Node-RED RCE |
  | 4 | Node-RED container escape |
  | 5 | CVE-2021-43798 |
  | 6 | CVE-2019-20933 |
  | 7 | CVE-2021-30465 |
  | 8 | CVE-2021-25741 |
  | 9 | CVE-2022-23648 |
  | 10 | CVE-2019-5736 (runc) |

  — [GitHub](https://github.com/yigitsever/kubernetes-dataset)
- Kube-IDS0: labelled DoS, brute force and SQL injection — [Kaggle](https://www.kaggle.com/datasets/redamorsli/kube-ids0)
- Stratus: one CloudTrail detonation per ATT&CK-mapped technique (e.g. stopping a CloudTrail trail, `cloudtrail:PutEventSelectors`) — [Stratus](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-event-selectors/)
- flaws.cloud: "largely attacks within a simple AWS environment". No per-event labels are described — [Summit Route](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/)
- Splunk attack_data: entries carry metadata. One aws:cloudtrail entry says "no MITRE techniques are specified" — [Splunk research entry](https://research.splunk.com/attack_data/09f580b9-cbc0-4d90-8e26-7dd4584a5650/)
- BOTSv3 ships with questions and a scoring app (CC0) — [Splunk blog](https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html)
- shell-attack-evolution: ATT&CK annotations and "Vi severity labels" on Cowrie commands — [GitHub](https://github.com/zyw-286/shell-attack-evolution-dataset)
- macOS dataset: organised by ATT&CK technique and tactic, one file per technique — [GitHub](https://github.com/sbousseaden/macOS-ATTACK-DATASET)

### Inferences
- **Label granularity mismatch.** Flow- and row-labelled sets (UNSW-NB15, TON_IoT, the K8s flows) label records, not entities. An entity graph would need labels propagated, e.g. "a process or IP is malicious if any of its rows are attack". That is noisy for TON_IoT, where atop rows are resource snapshots.
- Honeypot data has no benign class. It can only supply malicious Linux command chains to inject into or contrast with benign host baselines.

### Gaps
- The scenario list (exploit names) for LID-DS 2021 and the attack-step list for AIT-LDSv2 (believed to include scans, WordPress exploitation, password cracking, privilege escalation, reverse shell and exfiltration, but unverified here) were not retrieved.
- The ground truth for LANL Unified was not verified. Secondary memory suggests it contains no red-team labels, but this is unconfirmed; check csr.lanl.gov/data/2017.
- Whether the Invictus AWS README describes the specific Stratus techniques and timing was not checked.

## Q5. How practical is each one to turn into an investigation graph with a malicious/benign answer?

### Takeaway
**Best fit for a Linux entity-graph benchmark:**
1. LID-DS 2021: container process/syscall graphs, per-recording exploit labels, permissive access.
2. AIT-LDSv2: multi-host Linux enterprise with auditd and line-level labels.
3. OTRF Log4Shell: a Linux auditd/Sysmon-for-Linux compound scenario.
4. CICAPT-IIoT2024: a ready-made provenance graph with an APT29 campaign.
5. BOTSv3: osquery/linux_audit plus a cloud identity side, with CTF answers.

**Secondary uses:**
- LANL cyber1: an enterprise auth graph with 749 red-team edges, good for lateral-movement or credential cases but Windows/AD and no process tree.
- Cloud CloudTrail sets: principal → API → resource subgraphs with technique-level truth.
- Cowrie: malicious SSH session chains to graft onto Linux hosts.

**Poor fit (no host entities, or no labels):** UNSW-NB15, CIC-IDS2017, the K8s flow/metric sets and TON_IoT Linux (resource counters only). The macOS dataset is old and small but is the only public ESF-style option found.

### Cited Findings
- LANL cyber1 has already been loaded into a graph database: 1.63 B nodes and 11.0 B triples in Dgraph, with User, Computer and ComputerUser entities and CompromiseEvent edges from redteam.txt. This shows it is graph-ready, but it also means the full set is extremely large — [G-Research dgraph-lanl-csr](https://github.com/G-Research/dgraph-lanl-csr)
- LANL cyber1 is widely used for lateral-movement and user-behaviour detection — [arXiv 2208.13524](https://arxiv.org/pdf/2208.13524)
- AIT-LDSv2 has already been converted into an alert dataset (AIT-ADS) for multi-step attack analysis. Its line-level labels propagate to alerts — [ACM](https://dl.acm.org/doi/fullHtml/10.1145/3675741.3675748); [ait-aecid/alert-data-set](https://github.com/ait-aecid/alert-data-set)
- AIT-style heterogeneous logs are being used for LLM-based cyberattack detection (2026) — [arXiv 2602.06777](https://arxiv.org/pdf/2602.06777)
- LID-DS comes with an open-source loader and evaluation library (62 building blocks) that reads LID-DS 2019 and 2021, ADFA-LD and CB-DS scap — [LID-DS GitHub](https://github.com/LID-DS/LID-DS)
- An AI-agent study on Cowrie log analysis exists, so Cowrie is already in use as LLM-agent investigation material — [arXiv 2509.05306](https://arxiv.org/html/2509.05306v1)
- Stratus logs are anonymised with LogLicker after Grimoire capture, so identities are consistent but fake — [Stratus](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/)
- One paper reports that CICAPT-IIoT provenance comes from only a single node — [ProvICS](https://arxiv.org/html/2607.05989)

### Inferences
**Practicality ranking for "agent walks entity graph → malicious/benign" (Linux focus):**

| Dataset | Practicality | Notes |
|---|---|---|
| LID-DS 2021 | High | Each recording is one container run, labelled normal or with an exploit start time. Syscalls give process, thread, file and socket entities. Graphs per recording are small. **Caveat:** single-container scope, no enterprise context. |
| AIT-LDSv2 | High | auditd covers processes, files and users. Apache, DNS and VPN logs connect hosts. Line labels give per-event truth. **Caveat:** it is heavy to parse, and auditd needs reconstruction into process trees. |
| OTRF Log4Shell (compound) | High for one scenario | Gives auditd, Sysmon for Linux and syslog on a known exploit chain. Ground truth is the scenario narrative, not per-event labels. |
| CICAPT-IIoT2024 | Medium-high | Provenance is already a graph (SPADE). It is an APT29 Caldera campaign. Check per-node labels and the single-node limitation. |
| BOTSv3 | Medium | Rich multi-source data. The answers are Q&A, not entity labels. Needs Splunk to export. |
| LANL cyber1 | Medium for enterprise authentication | 749 red-team edges give clean malicious authentication edges. Process data is too thin (name and start/end only). It is Windows/AD. |
| Cloud (Stratus, Invictus, flaws, OTRF AWS, Splunk attack_data) | Medium for cloud cases | Entities are principal, IP, user agent, API action and resource. Truth is "this recording is technique X". flaws.cloud has almost no benign baseline. |
| Cowrie/honeypot | Medium as malicious-only material | Commands and downloads can be grafted into Linux host timelines. There are no process trees and no benign data. |
| TON_IoT Linux | Low | atop resource snapshots with row labels. No parent/child, command line or file paths. |
| CSE-CIC-IDS2018 Ubuntu logs | Low | Unlabelled host logs. Labels exist only for flows. |
| UNSW-NB15, CIC-IDS2017, Sever & Dogan K8s, Kube-IDS0, pod-metrics | Low | Network flows or metrics only. |
| macOS (sbousseaden) | Low-medium | Per-technique Elastic Endpoint JSON (process/file events likely) but small, old, and attack-only. |

- **Gap in the public ecosystem.** No public, labelled Kubernetes dataset was found with host-level runtime telemetry (Falco, Tetragon or Tracee events, or K8s audit logs with process context). Generating one, e.g. Kubernetes Goat scenarios recorded with Tetragon, is likely necessary for a K8s investigation track.

### Gaps
- None of the datasets was downloaded or parsed. The "Practicality" ratings are judgements based on documented schemas.
- No public Falco/Tetragon/Tracee attack recording corpus, K8s audit-log attack corpus or CNCF security dataset was found in two searches. Absence is not proven.
- No public Azure or GCP attack telemetry beyond OTRF's Azure tooling was characterised.
- DShield has no public bulk dataset, and terms for researcher access were not found.
- Current link health of Proton Drive (LID-DS), csr.lanl.gov, research.unsw.edu.au and summitroute.com could not be tested from this environment.
