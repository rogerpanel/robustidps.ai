# Reference verification log

Companion to `references.bib` (59 entries). Built 2026-10-11.

## How verification was done

This environment blocks direct HTTP access to publisher sites, DBLP, arXiv, Crossref, Semantic Scholar and OpenReview. Only GitHub could be read directly (raw.githubusercontent.com, plus github.com pages through the fetch tool). Two channels were used:

1. **Web search (indexed snippets) restricted to authoritative domains** (usenix.org, ieeexplore.ieee.org, computer.org, dl.acm.org, ndss-symposium.org, proceedings.neurips.cc, proceedings.iclr.cc, openreview.net, proceedings.mlr.press, link.springer.com, dblp.org, arxiv.org, official project pages). A field was kept only when it showed up in such a hit, or on an author or institutional page when a publisher hit was missing.
2. **Direct reads of official GitHub repositories** for datasets and tools, and for author-provided BibTeX in project READMEs (cross-checked against the venue page).

Rules applied:
- **DOI** is included only when a hit on the publisher's site or DBLP showed that DOI attached to that exact title. A DOI that appeared only in a citing paper or an aggregator was dropped, and the entry gets a `url` to the publisher page instead.
- **Pages** are included only when the official BibTeX (USENIX), DBLP, the proceedings table of contents, or two independent consistent sources gave them.
- Long author lists come from the official proceedings or project page. If only part of the list could be confirmed, the confirmed names are followed by `and others`; no names were filled in from memory.

"Verified" means title, authors, venue and year were all confirmed, along with every other field present. "Partially verified" means the entry is correct as written, but some normally expected fields (usually DOI or pages) were left out because they could not be confirmed.

## Verified entries

### (1) Provenance-based intrusion detection and investigation

| Key | Title | Venue / year | Source used | Status |
|---|---|---|---|---|
| hossain2017sleuth | SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data | USENIX Security 2017 | https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/hossain (pages 487-504 and ISBN from the USENIX listing and paper front page) | Verified |
| milajerdi2019holmes | HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows | IEEE S&P 2019 | https://ieeexplore.ieee.org/document/8835390/ ; arXiv 1810.01594 | Partially verified: DOI omitted. Pages 1137-1152 match DBLP and several citing papers, but a UIC lab page lists 430-445; re-check against IEEE Xplore before camera-ready. |
| milajerdi2019poirot | POIROT: Aligning Attack Behavior with Kernel Audit Records for Cyber Threat Hunting | ACM CCS 2019 | Consistent bibliographic records (CCS '19, pp. 1795-1812); arXiv 1910.00056 | Partially verified: DOI omitted (could not confirm it on dl.acm.org) |
| hassan2019nodoze | NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage | NDSS 2019 | https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage/ | Partially verified: DOI omitted (NDSS gives no page numbers) |
| hassan2020rapsheet | Tactical Provenance Analysis for Endpoint Detection and Response Systems | IEEE S&P 2020 | https://ieeexplore.ieee.org/document/9152771/ ; pages from a bibliography listing | Partially verified: DOI omitted. Pages come from a single bibliography source; re-check. |
| wang2020provdetector | You Are What You Do: Hunting Stealthy Malware via Data Provenance Analysis | NDSS 2020 | https://www.ndss-symposium.org/ndss-paper/you-are-what-you-do-hunting-stealthy-malware-via-data-provenance-analysis/ ; NDSS PDF 24167 | Partially verified: DOI omitted |
| han2020unicorn | UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats | NDSS 2020 | https://www.ndss-symposium.org/ndss-paper/unicorn-runtime-provenance-based-detector-for-advanced-persistent-threats/ ; arXiv 2001.01525 | Partially verified: DOI omitted |
| manzoor2016streamspot | Fast Memory-efficient Anomaly Detection in Streaming Heterogeneous Graphs | ACM KDD 2016 | KDD-format PDF (data.bus.wisc.edu/papers/16-kdd-streamspot.pdf); arXiv 1602.04844 | Partially verified: DOI and pages omitted. Pages 1035-1044 appeared only in a secondary record. |
| alsaheel2021atlas | ATLAS: A Sequence-based Learning Approach for Attack Investigation | USENIX Security 2021 | https://www.usenix.org/conference/usenixsecurity21/presentation/alsaheel ; USENIX BibTeX; github.com/purseclab/ATLAS README | Verified |
| zeng2022shadewatcher | SHADEWATCHER: Recommendation-guided Cyber Threat Analysis using System Audit Records | IEEE S&P 2022 | https://ieeexplore.ieee.org/document/9833669/ ; https://dblp.org/rec/conf/sp/ZengWLCLCC22.html | Verified (DOI 10.1109/SP46214.2022.9833669 matches the IEEE document number) |
| wang2022threatrace | THREATRACE: Detecting and Tracing Host-Based Threats in Node Level Through Provenance Graph Learning | IEEE TIFS 2022 | https://ieeexplore.ieee.org/document/9899459/ ; arXiv 2111.04333 | Partially verified: volume, pages and DOI omitted. "vol. 17, pp. 3972-3987" and DOI 10.1109/TIFS.2022.3208815 each appeared only in secondary sources. |
| fang2022depimpact | Back-Propagating System Dependency Impact for Attack Investigation (DepImpact) | USENIX Security 2022 | https://www.usenix.org/conference/usenixsecurity22/presentation/fang ; NSF PAR 10463730 | Verified |
| inam2023sok | SoK: History is a Vast Early Warning System: Auditing the Provenance of System Intrusions | IEEE S&P 2023 | https://ieeexplore.ieee.org/document/10179405/ ; DBLP author page for W. U. Hassan | Partially verified: DOI omitted |
| dong2023arewethereyet | Are we there yet? An Industrial Viewpoint on Provenance-based Endpoint Detection and Response Tools | ACM CCS 2023 | https://dl.acm.org/doi/10.1145/3576915.3616580 | Verified |
| cheng2024kairos | KAIROS: Practical Intrusion Detection and Investigation using Whole-system Provenance | IEEE S&P 2024 | https://ieeexplore.ieee.org/document/10646673/ ; S&P 2024 table of contents on computer.org (pp. 3533-3551); arXiv 2308.05034 | Partially verified: DOI omitted. The 4th author is "Yan Wang" per IEEE, DBLP and arXiv; the project README spells it "Yang Wang". |
| rehman2024flash | FLASH: A Comprehensive Approach to Intrusion Detection via Provenance Graph Representation Learning | IEEE S&P 2024 | https://ieeexplore.ieee.org/document/10646725/ ; github.com/DART-Laboratory/Flash-IDS README | Partially verified: DOI omitted. Pages 3552-3570 come from citing papers and follow directly after KAIROS (3533-3551) in the same proceedings. |
| jia2024magic | MAGIC: Detecting Advanced Persistent Threats via Masked Graph Representation Learning | USENIX Security 2024 | https://www.usenix.org/conference/usenixsecurity24/presentation/jia-zian ; USENIX BibTeX; github.com/FDUDSDE/MAGIC README | Verified |
| li2024nodlink | NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation | NDSS 2024 | https://www.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/ | Partially verified: DOI omitted |
| jiang2025orthrus | ORTHRUS: Achieving High Quality of Attribution in Provenance-based Intrusion Detection Systems | USENIX Security 2025 | https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang ; github.com/ubc-provenance/orthrus README | Partially verified: pages omitted |
| bilot2025simpler | Sometimes Simpler is Better: A Comprehensive Analysis of State-of-the-Art Provenance-Based Intrusion Detection Systems | USENIX Security 2025 | https://www.usenix.org/conference/usenixsecurity25/presentation/bilot ; github.com/ubc-provenance/PIDSMaker README | Partially verified: pages omitted |
| aly2025ocrapt | OCR-APT: Reconstructing APT Stories from Audit Logs using Subgraph Anomaly Detection and LLMs | ACM CCS 2025 | https://dl.acm.org/doi/10.1145/3719027.3765219 ; DBLP CCS 2025 index; arXiv 2510.15188 | Verified |

### (2) Datasets and telemetry

| Key | Title | Venue / year | Source used | Status |
|---|---|---|---|---|
| darpa_tc | Transparent Computing: Material from the DARPA Transparent Computing Program (E3/E5 releases) | GitHub repository (@misc) | https://github.com/darpa-i2o/Transparent-Computing (README.md = Engagement 5 release; README-E3.md = Engagement 3) | Verified |
| darpa_optc | Operationally Transparent Cyber (OpTC) Data Release | GitHub repository (@misc) | https://github.com/FiveDirections/OpTC-data (README read directly) | Verified |
| otrf_securitydatasets | Security Datasets: Re-play Security Events | GitHub repository (@misc) | https://github.com/OTRF/Security-Datasets (README "Authors" section read directly) | Verified |
| splunk_attackdata | attack_data: A Repository of Curated Datasets from Various Attacks | GitHub repository (@misc) | https://github.com/splunk/attack_data (page title, description, Apache-2.0 license); https://research.splunk.com/attack_data/ (sysmon_linux datasets listed) | Verified |
| microsoft_sysmon | Sysmon (System Monitor) | Microsoft Sysinternals docs (@misc) | https://learn.microsoft.com/en-gb/sysinternals/downloads/sysmon (authors Russinovich and Garnier) | Verified |
| microsoft_sysmonforlinux | Sysmon for Linux | GitHub repository (@misc) | https://github.com/microsoft/Sysmon-Linux (github.com/microsoft/SysmonForLinux and github.com/Sysinternals/SysmonForLinux both now resolve here) | Verified |
| strom2018attack | MITRE ATT&CK: Design and Philosophy | MITRE technical report, 2018 (revised 2020) | https://www.mitre.org/news-insights/publication/mitre-attck-design-and-philosophy ; DTIC AD1108016 | Partially verified: report number omitted (the 2020 revision is MP180360R1; the 2018 number was not confirmed) |
| grimmer2023lidds | Dataset Report: LID-DS 2021 | CRITIS 2022, LNCS 13723, Springer, 2023 | https://link.springer.com/chapter/10.1007/978-3-031-35190-7_6 ; https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf | Verified |
| landauer2023maintainable | Maintainable Log Datasets for Evaluation of Intrusion Detection Systems (AIT-LDS v2) | IEEE TDSC 20(4), 2023 | IEEE Xplore / DBLP listing (TDSC vol. 20 no. 4, 2023); arXiv 2203.08580; publications.ait.ac.at | Partially verified: pages and DOI omitted |
| creech2013adfa | Generation of a new IDS test dataset: Time to retire the KDD collection (ADFA-LD) | IEEE WCNC 2013 | https://dblp.org/rec/conf/wcnc/CreechH13.html ; https://ieeexplore.ieee.org/document/6555301/ ; https://research.unsw.edu.au/projects/adfa-ids-datasets | Verified. The ADFA page also asks users to cite a related journal article, which was not verified or included. |
| kent2016lanl | Cyber-Security Data Sources for Dynamic Network Research | Chapter in *Dynamic Networks and Cyber-Security*, World Scientific, 2016 | https://worldscientific.com/worldscibooks/10.1142/q0022 (table of contents); dataset page https://csr.lanl.gov/data/cyber1/ | Partially verified: chapter pages and chapter DOI omitted; author given as "A. D. Kent", as on the TOC |
| pidsmaker_repo | PIDSMaker framework, preprocessed datasets and labels | GitHub repository (@misc) | https://github.com/ubc-provenance/PIDSMaker (README); https://spg.cs.ubc.ca/publication/2026-kdd/ | Verified as a repository citation. The paper (arXiv 2601.22983) is listed by the authors as KDD 2026, but proceedings details were not confirmed, so the repository is cited instead. |

### (3) SOC operations, alert triage and analyst workload

| Key | Title | Venue / year | Source used | Status |
|---|---|---|---|---|
| sundaramurthy2015burnout | A Human Capital Model for Mitigating Security Analyst Burnout | SOUPS 2015 | https://www.usenix.org/conference/soups2015/proceedings/presentation/sundaramurthy | Partially verified: pages omitted |
| kokulu2019soc | Matched and Mismatched SOCs: A Qualitative Study on Security Operations Center Issues | ACM CCS 2019 | ASU and Buffalo institutional records; https://adamdoupe.com/publications/matched-and-mismatched-socs-ccs2019.md | Partially verified: DOI omitted. 10.1145/3319535.3354239 appears in institutional records but could not be confirmed on dl.acm.org. |
| alahmadi2022falsepositives | 99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms | USENIX Security 2022 | https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi ; DBLP (pp. 2783-2800) | Verified |
| vermeer2023alertalchemy | Alert Alchemy: SOC Workflows and Decisions in the Management of NIDS Rules | ACM CCS 2023 | https://dl.acm.org/doi/10.1145/3576915.3616581 ; TU Delft repository (pp. 2770-2784) | Verified |
| liu2022rapid | RAPID: Real-Time Alert Investigation with Context-aware Prioritization for Efficient Threat Discovery | ACSAC 2022 | https://dl.acm.org/doi/10.1145/3564625.3567997 ; DBLP (pp. 827-840) | Verified |

### (4) LLM agents, tool use and agent benchmarks

| Key | Title | Venue / year | Source used | Status |
|---|---|---|---|---|
| wei2022cot | Chain-of-Thought Prompting Elicits Reasoning in Large Language Models | NeurIPS 2022 | https://proceedings.neurips.cc/paper/2022/hash/9d5609613524ecf4f15af0f7b31abca4-Abstract-Conference.html | Partially verified: pages omitted (not on the proceedings page) |
| yao2023react | ReAct: Synergizing Reasoning and Acting in Language Models | ICLR 2023 | https://openreview.net/forum?id=WE_vluYUL-X ; https://iclr.cc/virtual/2023/poster/11003 | Verified |
| schick2023toolformer | Toolformer: Language Models Can Teach Themselves to Use Tools | NeurIPS 2023 | https://proceedings.neurips.cc/paper_files/paper/2023/file/d842425e4bf79ba039352da0f658a906-Paper-Conference.pdf | Partially verified: pages omitted |
| shinn2023reflexion | Reflexion: Language Agents with Verbal Reinforcement Learning | NeurIPS 2023 | https://proceedings.neurips.cc/paper_files/paper/2023/hash/1b44b878bb782e6954cd888628510e90-Abstract-Conference.html ; https://dblp.org/rec/conf/nips/ShinnCGNY23.html | Partially verified: pages omitted. The author list follows the NeurIPS version (5 authors); arXiv versions differ. |
| liu2024agentbench | AgentBench: Evaluating LLMs as Agents | ICLR 2024 | https://iclr.cc/virtual/2024/poster/17388 ; ICLR 2024 proceedings PDF; github.com/THUDM/AgentBench README (author list) | Verified |
| jimenez2024swebench | SWE-bench: Can Language Models Resolve Real-world GitHub Issues? | ICLR 2024 | github.com/SWE-bench/SWE-bench README (official BibTeX, OpenReview VTF8yNQM66); swebench.com | Verified |
| yao2025taubench | τ-bench: A Benchmark for Tool-Agent-User Interaction in Real-World Domains | ICLR 2025 | https://proceedings.iclr.cc/paper_files/paper/2025/hash/1b126cc38b8638e07bef37e7b2bb72bf-Abstract-Conference.html | Verified (peer-reviewed ICLR 2025 version replaces arXiv 2406.12045) |
| patil2025bfcl | The Berkeley Function Calling Leaderboard (BFCL): From Tool Use to Agentic Evaluation of Large Language Models | ICML 2025, PMLR 267 | https://proceedings.mlr.press/v267/patil25a.html | Verified |

### (5) LLMs for cybersecurity

| Key | Title | Venue / year | Source used | Status |
|---|---|---|---|---|
| bhatt2023cyberseceval | Purple Llama CyberSecEval: A Secure Coding Benchmark for Language Models | arXiv 2312.04724, 2023 | https://arxiv.org/abs/2312.04724 ; Meta AI publication page | Partially verified: arXiv lists 21 authors, but only the first 7 were confirmed in order, so the rest are written as `and others`. No peer-reviewed version found. |
| bhatt2024cyberseceval2 | CyberSecEval 2: A Wide-Ranging Cybersecurity Evaluation Suite for Large Language Models | arXiv 2404.13161, 2024 | https://arxiv.org/abs/2404.13161 ; DBLP CoRR entry | Verified (arXiv only; no peer-reviewed version found) |
| wan2024cyberseceval3 | CyberSecEval 3: Advancing the Evaluation of Cybersecurity Risks and Capabilities in Large Language Models | arXiv 2408.01605, 2024 | https://arxiv.org/abs/2408.01605 | Verified (arXiv only) |
| alam2024ctibench | CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence | NeurIPS 2024 Datasets and Benchmarks | https://proceedings.neurips.cc/paper_files/paper/2024/hash/5acd3c628aa1819fbf07c39ef73e7285-Abstract.html | Partially verified: pages omitted. The author README gives 50805-50825, but no proceedings source confirmed it. |
| shao2024nyuctf | NYU CTF Bench: A Scalable Open-Source Benchmark Dataset for Evaluating LLMs in Offensive Security | NeurIPS 2024 Datasets and Benchmarks | https://proceedings.neurips.cc/paper_files/paper/2024/hash/69d97a6493fbf016fff0a751f253ad18-Abstract.html | Partially verified: pages omitted |
| deng2024pentestgpt | PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing | USENIX Security 2024 | https://www.usenix.org/conference/usenixsecurity24/presentation/deng ; USENIX BibTeX in github.com/GreyDGL/PentestGPT README | Verified |
| zhang2025cybench | Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models | ICLR 2025 | https://iclr.cc/virtual/2025/poster/28041 ; official project page BibTeX (github.com/cybench/cybench.github.io, index.html) | Verified |
| xu2025llm4security | Large Language Models for Cyber Security: A Systematic Literature Review | ACM TOSEM, 2025 | https://dl.acm.org/doi/10.1145/3769676 ; arXiv 2405.04760 | Partially verified: volume and issue omitted. Year 2025 is based on the ACM page (accepted 22 Sep 2025); check the final issue year. |
| wu2026excytin | ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat Investigation | ICML 2026 | https://icml.cc/virtual/2026/poster/66310 ; arXiv 2507.14201 (author list via papers.cool); github.com/microsoft/SecRL README | Partially verified: authors are from arXiv (12), since the ICML camera-ready list was not checked. PMLR volume and pages omitted. |

### (6) Methodology and online documentation

| Key | Title | Venue / year | Source used | Status |
|---|---|---|---|---|
| arp2022dosdonts | Dos and Don'ts of Machine Learning in Computer Security | USENIX Security 2022 | https://www.usenix.org/conference/usenixsecurity22/presentation/arp ; USENIX BibTeX (pp. 3971-3988) | Verified |
| sainz2023contamination | NLP Evaluation in trouble: On the Need to Measure LLM Data Contamination for each Benchmark | Findings of EMNLP 2023 | ACL Anthology metadata (pp. 10776-10787); EHU research portal; arXiv 2310.18018 | Partially verified: no ACL Anthology URL or DOI (the page itself was not retrieved). The second author is listed as "Jon Campos", as in the ACL Anthology author index. |
| anthropic_promptcaching | Prompt caching | Anthropic Claude Platform docs (@misc) | https://platform.claude.com/docs/en/build-with-claude/prompt-caching | Verified (online documentation) |
| anthropic_tooluse | Tool use with Claude | Anthropic Claude Platform docs (@misc) | https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview | Verified (online documentation) |

## Not included (unverified)

Left out because an essential field could not be confirmed, or because the only available version is a preprint of unconfirmed status that the theme does not need:

- **ADFA-LD journal article** (Creech and Hu, IEEE Transactions on Computers, 2014). The ADFA dataset page asks users to cite it, but its title, volume and pages were not verified. Only the WCNC 2013 paper is included.
- **LID-DS 2019 paper** (Grimmer, Röhling, Kreusel, Ganz, "A modern and sophisticated host based intrusion detection data set", in *IT-Sicherheit als Voraussetzung für eine erfolgreiche Digitalisierung*, pp. 135-145, 2019). Seen only in a secondary summary; the publisher and series were not confirmed. The CRITIS 2022 dataset report is included instead.
- **LANL data set as a standalone record** (DOI 10.17021/1179829, author attribution). An OSTI record exists (osti.gov/biblio/1179829), but neither the DOI nor the dataset author was confirmed. The Kent book chapter is cited instead.
- **Jalalvand et al., "Alert Prioritisation in Security Operations Centres: A Systematic Survey on Criteria and Methods"** (ACM Computing Surveys, DOI 10.1145/3695462). The DOI and title were confirmed via Crossref, but the full author list was not.
- **"Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities"** (ACM, DOI 10.1145/3723158). Title and DOI seen on dl.acm.org, but authors and venue details were not confirmed.
- **Carbon Filter** (Inam, Oliver, Batta, Bates, RAID 2025). Venue and authors were confirmed on the authors' group page; publisher, pages and DOI were not. Add it only after checking the RAID 2025 proceedings.
- **ProvSEEK / "LLM-driven Provenance Forensics for Threat Investigation and Detection"** (Mukherjee and Kantarcioglu, arXiv 2508.21323). arXiv only; no peer-reviewed venue found.
- **LLM attack-investigation preprints**: "An Automated Attack Investigation Approach Leveraging Threat-Knowledge-Augmented Large Language Models" (arXiv 2509.01271), SherAgent (arXiv 2607.09176), OMNISEC (arXiv 2503.03108). None was confirmed as peer-reviewed; not included per the instructions.
- **CyberSOCEval** (Meta and CrowdStrike, arXiv 2509.20166). arXiv only; author list not verified.
- **Field-level omissions** (the entries are included, these fields are not): DOIs for HOLMES, POIROT, RapSheet, SoK (Inam), KAIROS, FLASH, StreamSpot, ThreaTrace, Kokulu, all NDSS papers, and AIT-LDS. Pages for StreamSpot, ORTHRUS, Bilot et al., SOUPS 2015 and all NeurIPS/ICLR entries. Volume and pages for ThreaTrace. Volume and issue for Xu et al. (TOSEM). Report number for MITRE ATT&CK.

## Verified but left out for scope

- **Gorilla: Large Language Model Connected with Massive APIs** (Patil, Zhang, Wang, Gonzalez; NeurIPS 2024; https://proceedings.neurips.cc/paper_files/paper/2024/hash/e4c61f578ff07830f5c37378dd3ecb0d-Abstract-Conference.html). Verified. BFCL (ICML 2025) covers function calling more directly, so Gorilla was not added. It can be added as-is if wanted.

## Items to re-check before camera-ready

1. HOLMES pages (1137-1152 vs. 430-445) on IEEE Xplore.
2. RapSheet pages (1172-1189) and FLASH pages (3552-3570) on IEEE Xplore.
3. ExCyTIn-Bench: the ICML 2026 camera-ready author list and PMLR volume.
4. Xu et al. TOSEM: final volume, issue and year.
5. If DOIs are required by the venue style, add them for the IEEE S&P, NDSS and CCS 2019 entries from the publisher pages; they were left out here only because they could not be confirmed from this environment.
