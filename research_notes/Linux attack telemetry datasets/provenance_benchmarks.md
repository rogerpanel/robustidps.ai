# Host-provenance attack benchmark datasets (DARPA TC E3/E5, OpTC, StreamSpot, Unicorn, ATLAS/ATLASv2, NodLink) and research ground-truth label sets

Research date: 2026-10-10. Method: primary GitHub READMEs and label files fetched directly (raw.githubusercontent.com), plus web search. arXiv and the GitHub REST API were unreachable from this environment (proxy policy). As a result, the paper PDFs (Kairos, Unicorn, ATLASv2, the 2026 benchmark-protocol paper) could not be read in full, and some figures come from search snippets. Those are flagged below.

## Q1. Publisher, year, download location, registration and licence

### Takeaway
DARPA TC (E3 2018, E5 2019) and OpTC (2019) are released into the public domain ("Distribution A") with no registration. They are hosted on Five Directions' Google Drive folders, linked from GitHub. Research systems such as ThreaTrace, Orthrus and PIDSMaker add permissively licensed node-level label files on GitHub. PIDSMaker also re-hosts preprocessed Postgres dumps on Google Drive. The academic datasets (StreamSpot, Unicorn, ATLAS, NodLink) are on GitHub or Harvard Dataverse and ask for citation. Their explicit licences were mostly not verified.

### Cited Findings
**DARPA TC Engagement 3 (E3)**
- E3 ran in April 2018, the third of five planned engagements. Data release date: August 30, 2018. Signed by PM Angelos Keromytis, DARPA/I2O. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)
- Licence: "DARPA is releasing these files in the public domain to stimulate further research … The data is released as-is … since the data was produced by research prototypes, it is practically guaranteed to be imperfect." No registration is mentioned. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)
- Hosting: Five Directions' Google Drive, `https://drive.google.com/open?id=1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK`. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)
- Research repos point to a different Drive folder that holds the JSON tarballs: `https://drive.google.com/drive/folders/1fOCY3ERsEmXmvDekG-LUUSjfWs6TRdp-`. Files named there include `cadets/ta1-cadets-e3-official.json.tar.gz` and `theia/ta1-theia-e3-official-6r.json.tar.gz`. — [ThreaTrace README](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/README.md); [Flash README](https://raw.githubusercontent.com/DART-Laboratory/Flash-IDS/main/README.md)
- TA1 performers in E3: cadets, clearscope, fivedirections, theia, trace. MARPLE is not in E3. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)

**DARPA TC Engagement 5 (E5)**
- E5 ran in May 2019, the last of five engagements. TA1 performers: cadets, clearscope, fivedirections, marple, theia, trace. Each performer was planned to run three instances on separate hosts. — [Transparent-Computing README](https://github.com/darpa-i2o/Transparent-Computing)
- Hosting: Google Drive `https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf`. The same public-domain, as-is terms apply. — [Transparent-Computing README](https://github.com/darpa-i2o/Transparent-Computing)

**DARPA OpTC**
- OpTC was funded by DARPA CHASE (Cyber Hunting at Scale). Five Directions collected and post-processed the data under Boston Fusion's CASES project. BAE was TA2 and Provatek was red team and test coordinator. Tests ran in fall 2019. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data)
- Released "in the public domain"; marked "Distribution A: Approved for public release: distribution unlimited". The repository lists no licence file. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data); [ecar.md](https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/ecar.md)
- Hosting: Google Drive `https://drive.google.com/drive/u/0/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa`. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data)

**PIDSMaker / Orthrus (UBC provenance group) re-distribution**
- PIDSMaker provides preprocessed Postgres dumps of E3/E5/OpTC on Google Drive (`https://drive.google.com/drive/folders/1hqfz8__zVqb3QzBuOI2SxrW4lLIdYqFr`). CLI download needs a Google OAuth token. — [PIDSMaker ten-minute-install](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/settings/ten-minute-install.md)
- PIDSMaker is Apache-2.0. Its README lists release notes v1.0.1 (Oct 2025, "REAPr labels") and v2.2.0 (Jul 2026, "ThreaTrace ground truth"), so it is actively maintained in 2026. — [PIDSMaker GitHub](https://github.com/ubc-provenance/PIDSMaker)
- Orthrus (USENIX Security 2025) has a Zenodo DOI, 10.5281/zenodo.14641605. — [Orthrus README](https://raw.githubusercontent.com/ubc-provenance/orthrus/main/README.md)

**StreamSpot**
- Hosted at `github.com/sbustreamspot/sbustreamspot-data` (Stony Brook; raw data from UIC, Venkatakrishnan's group). — [StreamSpot data README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)

**Unicorn (CamFlow) datasets**
- SC-1/SC-2 (shellshock-style supply-chain APT on a CI platform) are on GitHub at `margoseltzer/shellshock-apt` (files `camflow-benign-*`, `camflow-attack-*`). — [ThreaTrace README](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/README.md)
- "Unicorn Wget" is on Harvard Dataverse, doi:10.7910/DVN/IA8UOS (`attack_baseline.tar.gz`, `benign.tar.gz`). — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)

**ATLAS (USENIX Security 2021)**
- ATLAS artifacts, including raw audit logs in the `raw_logs` folder, are at `github.com/purseclab/ATLAS`. The README asks users to cite the paper. — [ATLAS README](https://raw.githubusercontent.com/purseclab/ATLAS/main/README.md)

**ATLASv2**
- ATLASv2 is by Riddle, Westfall and Bates (UIUC), on arXiv 2401.01341 (submitted Oct 2023). — [arXiv 2401.01341 via search](https://arxiv.org/pdf/2401.01341)

**NodLink simulated data (NDSS 2024)**
- The NodLink simulated data is at `github.com/Nodlink/Simulated-Data`. The README asks for citation. — [NodLink README](https://github.com/Nodlink/Simulated-Data)

**Code licences**
- ThreaTrace is MIT. — [ThreaTrace README](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/README.md)
- Flash and Kairos landing pages show no licence. — [Flash-IDS](https://github.com/DART-Laboratory/Flash-IDS); [Kairos](https://github.com/ProvenanceAnalytics/kairos)

### Inferences
- DARPA TC and OpTC raw data, and the official ground-truth PDFs, are the safest choice for demos and publications because they are public domain. Label files from the research repos are code-repo artifacts (MIT/Apache-2.0 where stated) and should be credited.
- All DARPA data sits on Google Drive with no checksums or mirror. Large downloads hit Drive quota limits, and PIDSMaker documents an OAuth-token curl workaround. Keeping a local copy is advisable.

### Gaps
- No live check of the Google Drive links was possible: Drive needs a browser or OAuth, and there was no network path to drive.google.com. Link breakage is not verified either way. The fact that the E3 Drive ID differs between the DARPA README and the research repos suggests the folder was reorganised at some point.
- Explicit licences for StreamSpot, the Unicorn datasets, the ATLAS logs, ATLASv2 and the NodLink data were not found. Only citation requests were seen.
- The ATLASv2 download location (believed to be a lab-hosted repository) could not be confirmed because arXiv was blocked and search did not surface it.

## Q2. Data format and entity/relation vocabulary

### Takeaway
DARPA TC uses CDM: Avro binary with a JSON conversion. The schema is CDM18 for E3 and CDM20 for E5. It has typed nodes (Subject/process, FileObject, NetFlowObject, and others) and typed Events. OpTC uses eCAR JSON, an object/action/actorID model (CAR-derived) where process, file and flow objects carry UUIDs. StreamSpot is a 6-column TSV edge list with one-character type codes. Unicorn uses CamFlow (W3C PROV-JSON-style). ATLAS uses Windows Security Auditing, Firefox and DNS logs; ATLASv2 adds Sysmon and Carbon Black. All of these map cleanly onto a process, file and network graph, except that StreamSpot carries only types and anonymous IDs.

### Cited Findings
**DARPA TC CDM**
- Data files are Avro binary. The schema ships as `TCCDMDatum.avsc` plus `CDM18.avdl` (E3) or `CDM20.avdl` (E5), with `cdm.pdf` as documentation.
- A Java consumer (`ta3-java-consumer.tar.gz`, Java 1.8, Maven) parses the Avro, includes an Avro-to-JSON script, and runs semantic checks.
- Sources: [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md); [TC README (E5)](https://github.com/darpa-i2o/Transparent-Computing)

**Kairos and ThreaTrace parsing of CDM**
- Kairos loads CDM into Postgres tables `event_table`, `file_node_table`, `netflow_node_table`, `subject_node_table` and `node2id`. It has database recipes for CADETS/THEIA/ClearScope E3, CADETS/THEIA/ClearScope E5, and OpTC. — [Kairos database.md](https://raw.githubusercontent.com/ProvenanceAnalytics/kairos/main/DARPA/settings/database.md)
- The ThreaTrace ground-truth files are lists of CDM UUIDs, for example `9EF37E2E-3E80-11E8-A5CB-3FA3753A265A`, one per line. This shows that node identity in CDM is a UUID. — [ThreaTrace cadets.txt](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/groundtruth/cadets.txt)

**OpTC eCAR**
- Each record has `timestamp`, `id`, `hostname`, `objectID`, `object` (for example PROCESS), `action` (for example CREATE), `actorID` (UUID of the acting process), `pid`, `ppid`, `tid`, `principal` and a `properties` map (for example `image_path`, `parent_image_path`, `command_line`, `user`, `sid`).
- PID -1 or the all-zero process UUID means the information is not available.
- Source: [ecar.md](https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/ecar.md)
- The release has three folders: `ecar` (endpoint), `ecar-bro` (FLOW-START events annotated with a Bro/Zeek id) and `bro` (network sensor). Each has subfolders `short`, `evaluation` and `benign`. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data)

**StreamSpot**
- Format is a TSV of `source-id, source-type, destination-id, destination-type, edge-type, graph-id`. Each node and edge type is mapped to a single character.
- Consecutive block-reads between the same pair of nodes are collapsed, and timestamps are removed (edges stay in time order).
- Source: [StreamSpot data README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)

**ATLAS**
- ATLAS ships raw audit logs plus preprocessed logs. Its graph entities include domains, IPs, file paths and `process_pid` nodes, for example `"c:/users/aalsahee/payload.exe_892"`. These show the Windows host OS. — [ATLAS README](https://raw.githubusercontent.com/purseclab/ATLAS/main/README.md)

**ATLASv2**
- ATLASv2 has Windows Security Auditing, Firefox and DNS logs (as in ATLAS), plus Sysmon and VMware Carbon Black Cloud.
- Victims are two Windows 7 32-bit hosts (Carbon Black sensor 3.8.0.627); the attacker is a Kali Linux machine.
- Logs are split by host and logging framework, and Carbon Black is further split by event type.
- Source: [ATLASv2 arXiv 2401.01341 (via search summary)](https://arxiv.org/pdf/2401.01341)

**NodLink**
- The data comes as `benign.json` and `anomaly.json` per host (hw17 on Ubuntu 20.04, hw20 on Windows Server 2012, win10 on Windows 10). — [NodLink README](https://github.com/Nodlink/Simulated-Data)

**ShadeWatcher**
- ShadeWatcher targets Linux auditd on Ubuntu 16.04.3. It ships two example audit datasets under `data/examples` and points to the DARPA TC Drive folder. — [ShadeWatcher README](https://raw.githubusercontent.com/jun-zeng/ShadeWatcher/main/README.md)

### Inferences
- CDM event types such as EVENT_EXECUTE, EVENT_READ/WRITE, EVENT_CONNECT, EVENT_CLONE/FORK and EVENT_SENDTO/RECVFROM are defined in `cdm.pdf`/`CDM18.avdl`. They were not re-read during this research, so take exact names from the shipped schema.
- For an agent-walkable graph, CDM and eCAR are the best fit. Both have stable UUIDs for processes, files and flows, explicit actor-to-object edges, and process names and command lines (with gaps, see Q6).
- StreamSpot is a poor fit for SOC tasks. It has no names, paths or IPs, and its labels are graph-level only.

### Gaps
- The exact CamFlow version and fields for the Unicorn datasets were not verified. A search summary said CamFlow v0.5.0 for SC-1/SC-2 ([Unicorn arXiv 2001.01525, via search](https://arxiv.org/pdf/2001.01525)), but the paper could not be opened.
- The full OpTC object/action list (for example PROCESS, FILE, FLOW, MODULE, REGISTRY, THREAD with their actions) is in the Drive documentation, not the GitHub README, so it was not verified here.

## Q3. Total size and whether small subsets can be downloaded

### Takeaway
The raw DARPA data is very large: OpTC is about 1 TB of compressed JSON, and the E5 hosts are hundreds of GB once loaded. E3 is distributed as per-topic JSON tarballs, so you can download one performer or topic. The smallest practical slices are PIDSMaker's dumps (0.6–2 GB compressed per E3 host or OpTC host) and the purpose-built academic sets: StreamSpot, ATLAS raw_logs and NodLink zips. No DARPA slice under 100 MB was confirmed.

### Cited Findings
**OpTC**
- About 1 TB of compressed JSON. Of 1,000 hosts in the environment, data was collected from 500. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data)

**PIDSMaker Postgres dumps (compressed / loaded)**
- CLEARSCOPE_E3: 0.6 / 4.8 GB
- CADETS_E3: 1.4 / 10.1 GB
- THEIA_E3: 1.1 / 12 GB
- CLEARSCOPE_E5: 6.2 / 49 GB
- CADETS_E5: 36 / 276 GB
- THEIA_E5: 5.8 / 36 GB
- OPTC_H051: 1.7 / 7.7 GB
- OPTC_H501: 1.5 / 6.7 GB
- OPTC_H201: 2 / 9.1 GB
- All datasets loaded together take 135 GB.
- Source: [PIDSMaker ten-minute-install](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/settings/ten-minute-install.md)

**PIDSMaker main README size column (GB)**
- TRACE_E3: 100
- FIVEDIRECTIONS_E3: 22
- FIVEDIRECTIONS_E5: 280
- TRACE_E5: 710
- ATLASV2_EDR: 1
- CARBANAKV2_EDR (Windows + Linux): 6.6
- Source: [PIDSMaker GitHub](https://github.com/ubc-provenance/PIDSMaker)

**Per-topic granularity in E3**
- E3 data is split by "topic" (Kafka run). The "good" topics are:
  - ta1-cadets-e3-official, -1, -2
  - ta1-clearscope-e3-official, -1, -2
  - ta1-fivedirections-e3-official, -2, -3
  - ta1-theia-e3-official-1r, -3, -5m, -6r
  - ta1-trace-e3-official, -1
- Source: [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)
- MAGIC uses only `ta1-trace-e3-official-1.json.tar.gz`, `ta1-theia-e3-official-6r.json.tar.gz` and the two CADETS tarballs. It warns that the split JSON chunks must all be kept, because later chunks hold entity definitions for malicious entities. — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)

**Academic datasets**
- Unicorn SC-1: 64 GiB benign + 12 GiB attack. SC-2: 59 GiB benign + 12 GiB attack. Each scenario ran for three days. — [Unicorn arXiv 2001.01525 (search snippet)](https://arxiv.org/pdf/2001.01525)
- ATLASv2's full engagement is about 154 GB (search summary of the paper). PIDSMaker's processed ATLASV2_EDR is about 1 GB. — [ATLASv2 arXiv](https://arxiv.org/pdf/2401.01341); [PIDSMaker](https://github.com/ubc-provenance/PIDSMaker)
- StreamSpot is a single `all.tar.gz` holding `all.tsv` with 600 graphs. — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md); [StreamSpot README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)
- MAGIC ships its preprocessed graphs (`graphs.pkl` zips) for StreamSpot, Wget and E3 TRACE/THEIA/CADETS inside the GitHub repo's `data/` folder. — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)

### Inferences
- For a demo under about 100 MB, the realistic options are:
  - ATLAS `raw_logs` (Windows, in a GitHub repo, so small by necessity)
  - NodLink `SimulatedUbuntu.zip` (Linux)
  - MAGIC's in-repo preprocessed pickles (labelled, but stripped of names)
  - A self-made extract: load PIDSMaker's CADETS_E3 dump (1.4 GB compressed) and export only the 2018-04-06 attack day plus the labelled nodes' neighbourhood.
- E3 CADETS (FreeBSD) and E3 THEIA (Linux) are the best-trodden Unix options for size versus label quality.

### Gaps
- Per-file sizes of the E3/E5 tarballs on Google Drive could not be verified (no Drive access).
- The StreamSpot `all.tar.gz` size, the ATLAS raw_logs size and the NodLink zip sizes were not verified.

## Q4. Attacks included (scenario names, dates, ATT&CK)

### Takeaway
The E3/E5 attacks are APT-style campaigns run by the TA5.1 red team, mostly using the "Drakon" implant and a "micro APT". They include an Nginx backdoor on FreeBSD (CADETS), Firefox backdoors and browser-extension droppers (THEIA, TRACE, FiveDirections), pine and phishing-executable attacks (TRACE), and copykatz/BITS/DNS attacks (FiveDirections E5, Windows). Many were only partially successful. ATLAS/ATLASv2 replay 10 Windows exploit scenarios (s1–s4, m1–m6). StreamSpot has one drive-by-download attack class. No dataset ships an official ATT&CK mapping.

### Cited Findings
**Orthrus/PIDSMaker relabelled attack inventory ("Ground Truth darpa_v4")**

Source for this whole inventory: [PIDSMaker Ground_Truth/orthrus/readme.md](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/main/Ground_Truth/orthrus/readme.md).

*THEIA E3 (Linux)*
- Firefox_Backdoor_Drakon_In_Memory (04-10): succeeded; 58 true-positive nodes.
- Browser_Extension_Drakon_Dropper (04-12): partially succeeded; 61 TPs. The drakon loading failed but the micro APT succeeded.
- Removed: Phishing E-mail w/ Link (04-10, non-host) and Phishing E-mail w/ Executable Attachment (04-13, failed).

*CADETS E3 (FreeBSD)*
- Nginx_Backdoor_06: partial; 8 TPs.
- Nginx_Backdoor_12: partial; 43 TPs.
- Nginx_Backdoor_13: partial; 24 TPs.
- Removed: Nginx_Backdoor_11 and E_mail_Server (non-host).
- Steps that succeeded:
  - On the 6th: loaderDrakon connected to the shell, netrecon was downloaded and run, and libdrakon was injected. Injecting into sshd PID 809 failed.
  - On the 12th: drakon ran in memory, privileges were elevated and micro ran without root. Elevating the micro APT failed.
  - On the 13th: a shell was obtained and files were downloaded. Elevating with a new module failed.
- All four Nginx rows in the table carry the date "0406", but the notes describe attacks on the 6th, 11th, 12th and 13th. The date column looks like a typo.

*TRACE E3 (Linux)*
- trace_e3_firefox_0410: succeeded; 11 TPs.
- trace_e3_phishing_executable_0413: partial; 11 TPs. The pine exploit failed, but the user ran the attached micro APT, which port-scanned.
- trace_e3_pine_0413: succeeded; 14 TPs.
- Removed: browser_extension_0412 (failed) and phishing_link_0410 (non-host).

*FiveDirections E3 (Windows)*
- excel_0409: auto-execution failed, but the user manually ran the malicious command; 63 TPs. The labellers note it is ambiguous.
- firefox_0411: succeeded; 56 TPs.

*THEIA E5*
- THEIA_1_Firefox_Drakon_APT_BinFmt_Elevate_Inject (05-15): succeeded; 70 TPs.
- Removed: Firefox_Drakon_APT on 05-14 (failed).

*CADETS E5*
- Nginx_Drakon_APT (05-16): 19 TPs.
- Nginx_Drakon_APT_17 (05-17): 107 TPs.
- In both, the attacker succeeded on the second try.

*TRACE E5*
- Trace_Firefox_Drakon (05-14): 71 TPs.
- Removed: Azazel APT on 05-17 (failed).

*FiveDirections E5 (Windows)*
- copykatz_0509: partial (WMI failed); 87 TPs.
- bits_0515: 54 TPs.
- dns_0517: 11 TPs.
- drakon_0517: 6 TPs.

**Other sources on E3/E5 attacks**
- PIDSMaker's dataset table gives attack counts per dataset:
  - CADETS_E3: 3; THEIA_E3: 2; CLEARSCOPE_E3: 1; FIVEDIRECTIONS_E3: 2; TRACE_E3: 3
  - CADETS_E5: 2; THEIA_E5: 1; CLEARSCOPE_E5: 2; FIVEDIRECTIONS_E5: 4; TRACE_E5: 1
  - Each OpTC host: 1; ATLASV2_EDR: 10; CARBANAKV2_EDR: 1
  - Source: [PIDSMaker GitHub](https://github.com/ubc-provenance/PIDSMaker)
- Kairos describes E3-CADETS as FreeBSD with an Nginx attack surface and E3-THEIA as Ubuntu 12.04 x64 with Firefox. Its test splits use 2018-04-06 (CADETS) and 2018-04-10/12 (THEIA) as attack days. — [Kairos arXiv 2308.05034 (search summary)](https://arxiv.org/pdf/2308.05034)
- In the CADETS Nginx scenario, the attacker gets a shell through vulnerable Nginx, runs a payload as root, and attempts lateral movement to two addresses, of which one succeeds. — [Kairos arXiv (search summary)](https://arxiv.org/pdf/2308.05034)
- The official narratives are in `tc_ground_truth_report_e3_update.pdf` and `operational_event_log.md` for E3, and `tc_ground_truth_report_e5_update.pdf` for E5. PIDSMaker mirrors them as `TC_Ground_Truth_Report_E3_Update.pdf` and `TA51_Final_report_E5.pdf`. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md); [TC README](https://github.com/darpa-i2o/Transparent-Computing); [PIDSMaker Ground_Truth](https://github.com/ubc-provenance/PIDSMaker/tree/main/Ground_Truth)

**OpTC**
- A 2-week evaluation: a benign period, then red-team malware injection with benign traffic continuing. The scenarios are in `OpTCRedTeamGroundTruth.pdf`. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data)
- PIDSMaker uses 3 hosts (h051, h201, h501) with 1 attack each. — [PIDSMaker](https://github.com/ubc-provenance/PIDSMaker)

**StreamSpot**
- Six scenarios of 100 graphs each: YouTube (0–99), GMail (100–199), VGame (200–299), Drive-by-download attack (300–399), Download (400–499), CNN (500–599). — [StreamSpot README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)

**Unicorn**
- Unicorn SC-1/SC-2 are two APT supply-chain attacks on a CI platform, captured with CamFlow over 3 days each. — [Unicorn arXiv (search snippet)](https://arxiv.org/pdf/2001.01525)
- Unicorn Wget yields 150 graphs. — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)

**ATLAS / ATLASv2**
- 10 scenarios: s1–s4 single-host and m1–m6 multi-host. They use Adobe Flash and MS Word CVEs such as CVE-2015-5122 and CVE-2017-11882. — [ATLASv2 arXiv (search summary)](https://arxiv.org/pdf/2401.01341)
- ATLASv2 adds 4 benign days before the attack day, using real researcher workstations rather than scripts. — [ATLASv2 arXiv (search summary)](https://arxiv.org/pdf/2401.01341)

**NodLink**
- 5 attacks on 3 hosts: one Ubuntu 20.04 attack, one Windows Server 2012 attack, and APT29, Sidewinder and FIN6 emulations on Windows 10. — [NodLink README](https://github.com/Nodlink/Simulated-Data)

### Inferences
- Drakon is the TA5.1 implant family. The "micro APT" is its follow-on stage, and netrecon is the discovery tool.
- ATT&CK mapping would have to be done by hand from the GT PDFs. Plausible techniques are:
  - T1190 (Nginx exploit)
  - T1189 or T1203 (Firefox exploit)
  - T1566 (phishing)
  - T1055 (injecting libdrakon into sshd)
  - T1068 (privilege elevation)
  - T1046 (port scan or netrecon)
  - T1197 (BITS, FiveDirections E5)
  - T1003 (copykatz, a mimikatz clone)
  - T1071.004 (DNS)
- Several attacks are partial or failed, so SOC tasks should state "attempted vs succeeded" in the expected answer.

### Gaps
- The official GT PDFs and the OpTC red-team PDF were not read (binary PDFs on Drive and GitHub). Exact attack timestamps and IOC lists come from those documents and are not reproduced here.
- No official ATT&CK mapping was found for any dataset.
- Attack details for ClearScope E3/E5 (Android) and MARPLE E5 are not in the Orthrus readme section that was retrieved.

## Q5. Ground-truth type and where the label files live

### Takeaway
The official DARPA/OpTC ground truth is prose only: PDF reports with IOCs and timelines, plus event logs. Usable labels come from research repos.
- **ThreaTrace:** node-UUID lists for E3 cadets, theia, trace and fivedirections. These have become the de facto label set (used by MAGIC and Flash-family work).
- **Orthrus/PIDSMaker:** per-attack node labels for E3, E5, OpTC h051/h201/h501, ATLASv2 and CarbanakV2, plus REAPr and ThreaTrace label sets.
- **Kairos:** time-window labels.
- **StreamSpot / Unicorn:** graph-level labels only.
- **ATLAS:** a small set of attack entity names per scenario.

### Cited Findings
**Official ground truth**
- DARPA E3 ships `ground truth/tc_ground_truth_report_e3_update.pdf` ("constructed by TA5.1") with Indicators of Compromise that "should be (but are not always) present in the data". IPs and domains are fictional. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)
- OpTC ships `OpTCRedTeamGroundTruth.pdf`, again with fictional IPs and domains. — [OpTC-data README](https://github.com/FiveDirections/OpTC-data)

**ThreaTrace (MIT)**
- Label files under `groundtruth/`: `cadets.txt`, `theia.txt`, `trace.txt` and `fivedirections.txt`. No ClearScope file exists (404).
- Each file is one CDM UUID per line. Line counts and unique UUIDs (my own count with `sort -u` on the downloaded files):

  | File | Lines | Unique UUIDs |
  |---|---|---|
  | cadets.txt | 12,858 | 12,858 |
  | theia.txt | 25,363 | 25,358 |
  | trace.txt | 68,265 | 68,172 |
  | fivedirections.txt | 18,420 | 762 |

- The E3 topics it pairs with: cadets official and official-2, fivedirections official-2, theia official-1r and 6r, trace official-1.
- Sources: [ThreaTrace README](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/README.md); [cadets.txt](https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/groundtruth/cadets.txt)

**MAGIC**
- MAGIC evaluates E3 on the ThreaTrace labels. It also gives an alternative labelling in its paper's Appendix G for E3 Trace, THEIA and CADETS. — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)

**PIDSMaker / Orthrus**
- `Ground_Truth/` has subfolders `orthrus`, `reapr` and `threatrace`, plus the two official PDFs.
- `Ground_Truth/orthrus/` has per-dataset folders: E3-CADETS, E3-CLEARSCOPE, E3-FIVEDIRECTIONS, E3-THEIA, E3-TRACE, E5-CADETS, E5-CLEARSCOPE, E5-FIVEDIRECTIONS, E5-THEIA, E5-TRACE, atlasv2_edr, atlasv2_h1, carbanakv2_edr, h051, h201 and h501.
- Sources: [PIDSMaker Ground_Truth](https://github.com/ubc-provenance/PIDSMaker/tree/main/Ground_Truth); [orthrus folder](https://github.com/ubc-provenance/PIDSMaker/tree/main/Ground_Truth/orthrus)
- The Orthrus labels are per attack and node level, with true-positive node counts per attack (for example 58 and 61 for the two THEIA E3 attacks, 70 for THEIA E5). — [orthrus readme](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/main/Ground_Truth/orthrus/readme.md)
- Orthrus results confirm the label granularity is nodes: CADETS_E3 shows TP 22 + FN 46 = 68 malicious nodes against about 268k benign nodes, and THEIA_E3 shows 118 malicious against about 699k benign. — [Orthrus README](https://raw.githubusercontent.com/ubc-provenance/orthrus/main/README.md)

**Kairos**
- Kairos labels by time window (15-minute windows by default, `time_window_size = 60000000000 * 15` ns). It writes `anomalous_queue.log` of flagged windows and an `evaluation.log`. — [Kairos CADETS_E3 config.py](https://raw.githubusercontent.com/ProvenanceAnalytics/kairos/main/DARPA/CADETS_E3/config.py); [Kairos DARPA README](https://raw.githubusercontent.com/ProvenanceAnalytics/kairos/main/DARPA/README.md)
- Kairos's supplementary material links its datasets. — [Kairos GitHub](https://github.com/ProvenanceAnalytics/kairos)

**Graph-level and entity-name labels**
- StreamSpot labels are implicit in the graph ID range (300–399 are attacks), so they are graph-level. — [StreamSpot README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)
- ATLAS evaluates against a cleaned attack-entity list per scenario, for example `["0xalsaheel.com", "aalsahee/index.html", "192.168.223.3", "payload.exe"]`, recorded in JSON `eval_*` files and `paper_experiments/docs/atlas.xlsx`. — [ATLAS README](https://raw.githubusercontent.com/purseclab/ATLAS/main/README.md)
- The original ATLAS labelled only a few entities as malicious per chain. ATLASv2 assumes days 1–4 are benign. Later work uses REAPr labels (UUID-based) for ATLASv2. — [ATLASv2/other papers (search summary)](https://arxiv.org/pdf/2408.13347)

**NodLink**
- NodLink provides `anomaly.json` vs `benign.json` per host, with "attack description and annotation" in its `doc` folder. — [NodLink README](https://github.com/Nodlink/Simulated-Data)

**Other systems**
- Flash evaluates on E3 (CADETS, THEIA, TRACE, FiveDirections notebooks), OpTC, StreamSpot and Unicorn. Its notebooks handle download and parsing. Its README does not document a separate label file. — [Flash README](https://raw.githubusercontent.com/DART-Laboratory/Flash-IDS/main/README.md)
- PIDSMaker reimplements velox, orthrus, nodlink, threatrace, kairos, rcaid (R-CAID) and flash, all on the same datasets and labels. — [PIDSMaker velox README](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/README.md)

### Inferences
- The best label sources for an agent "malicious vs benign node" task are:
  - **Orthrus labels:** small, curated, per attack, with failed or non-host attacks removed. Best as the "key malicious entities" answer.
  - **ThreaTrace labels:** large node sets of 12k–68k UUIDs per host. These include many descendants and artifacts, so they work as a lenient or "any related" answer.
- The two label sets differ by two to three orders of magnitude in size, so the task design must pick one explicitly.
- Kairos time-window labels suit a "which 15-minute window is malicious" triage task, not node classification.

### Gaps
- The file format inside the Orthrus per-dataset folders (for example CSV columns: UUID, type, name) could not be listed (GitHub tree is JS-rendered and the API was blocked).
- The REAPr label folder's contents and provenance were not verified.
- No published node labels for MARPLE E5, and none from ShadeWatcher or ProvDetector, were found. NodLink's repo contains a ProvDetector reimplementation but no separate labels. — [NodLink README](https://github.com/Nodlink/Simulated-Data)
- The R-CAID paper and repo were not located independently; it was seen only as a system name inside PIDSMaker.

## Q6. Data-quality caveats and how practical conversion to a process/file/network graph is

### Takeaway
Every TC dataset is "practically guaranteed to be imperfect" (DARPA's own words). The specific problems:
- **E3:** some topics are invalid.
- **ClearScope E3:** all netflow nodes are null.
- **OpTC:** duplicate process objects and inconsistent paths.
- **Attacks:** many partially failed, and official IOCs are not always present in the data.
- **E5:** volumes are huge (CADETS_E5 is 276 GB loaded, TRACE_E5 710 GB).
- **Labels:** the label sets disagree.

Conversion itself is practical. Kairos, PIDSMaker, MAGIC and ThreaTrace all ship CDM-to-graph parsers, and PIDSMaker offers ready-made Postgres dumps with subject, file and netflow node tables.

### Cited Findings
**DARPA E3**
- Only listed "good" topics should be used; others have missing records or no useful activity. `ta1-fivedirections-e3-official` contains one syntactically invalid FileObject record (offset 13696), which was removed in the archived files. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)
- IOCs "should be (but are not always) present in the data". Network identifiers in the GT reports are fictional. — [README-E3.md](https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md)

**ClearScope E3**
- PIDSMaker does not recommend `CLEARSCOPE_E3`: "all netflow nodes are null … contains redundant events and is of poor quality". — [PIDSMaker velox README](https://raw.githubusercontent.com/ubc-provenance/PIDSMaker/velox/README.md)

**OpTC errata**
- Duplicate process objects are not de-conflicted.
- Executable hashes are missing from module (DLL) loads.
- `acuity_level` is 0 for FLOW OPEN events.
- File paths mix `C:` with `\Device\HardDisk...` notation.
- PID -1 or 0 means unknown.
- Sources: [errata.md](https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/errata.md); [ecar.md](https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/ecar.md)

**StreamSpot**
- No timestamps, collapsed read edges, and only single-character types. — [StreamSpot README](https://raw.githubusercontent.com/sbustreamspot/sbustreamspot-data/master/README.md)

**Detector benchmark results (Orthrus)**
- Even state-of-the-art detectors struggle on some sets. CADETS_E5 (full) gives TP 3 / FP 1,318, and CLEARSCOPE_E3 gives precision 0.00. — [Orthrus README](https://raw.githubusercontent.com/ubc-provenance/orthrus/main/README.md)
- Orthrus results are not exactly reproducible because of a missing PYTHONHASHSEED for Word2Vec. — [Orthrus README](https://raw.githubusercontent.com/ubc-provenance/orthrus/main/README.md)

**MAGIC's parsing warning**
- Parsing must keep every JSON chunk, because entity definitions for malicious entities can appear in later chunks. — [MAGIC README](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/README.md)

**ATLAS**
- The ATLAS evaluation requires manual cleaning of redundant entities (for example a file and its process_pid twin). — [ATLAS README](https://raw.githubusercontent.com/purseclab/ATLAS/main/README.md)

**Label-quality concerns raised by others**
- One secondary paper calls the official DARPA GT document "practically unreadable" and labels by matching key entities and expanding through neighbourhoods. — [search summary citing arXiv 2503.19370 and related](https://arxiv.org/pdf/2503.19370)
- A 2026 arXiv paper, "How Benchmarks and Evaluation Protocols Shape Conclusions in Provenance-Based Intrusion Detection" (arXiv 2608.01454), addresses benchmark and label protocol effects. Only the title and a snippet were seen. — [arXiv 2608.01454](https://arxiv.org/pdf/2608.01454)

### Inferences
- **Recommended conversion path:** use PIDSMaker's E3 dumps (CADETS_E3 FreeBSD at 1.4 GB, THEIA_E3 Linux at 1.1 GB, both compressed) together with the Orthrus per-attack labels as "key malicious nodes" and the ThreaTrace UUID lists as the broader malicious set. Then cut per-attack subgraphs, for example a 2-hop neighbourhood of labelled nodes plus sampled benign processes from the same window, to get investigation tasks well under 100 MB.
- **E5 THEIA** (5.8 GB compressed, 1 clean attack, 70 TP nodes) is the best Linux E5 option. CADETS_E5 is too large for casual use.
- **TRACE E3 and E5:** 100 and 710 GB uncompressed respectively.
- **OpTC is Windows-only;** use it only if a Windows contrast is wanted.
- **ATLAS, ATLASv2 and FiveDirections are Windows.** NodLink provides one small Ubuntu host (hw17). CarbanakV2 (in PIDSMaker) mixes Windows and Linux, but its origin was not researched here.
- **ClearScope (Android)** should be avoided given the null-netflow issue in E3. E5 ClearScope is usable but weak: Orthrus precision 0.33.

### Gaps
- Field-level completeness was not independently measured, for example missing process command lines or file paths in CADETS, or THEIA's anonymised or hashed paths.
- MARPLE E5 data quality and usage in the literature were not found.
- The contents of the 2026 benchmark-protocol paper could not be read because arXiv was blocked from this environment.
