# Agentic Frameworks in Security Applications & Their Infrastructure Patterns (as of 24 Oct 2026)

> **Method / provenance note.** 19 tool calls. WebSearch worked; **every WebFetch failed with DNS errors** (strobes.co, pipelab.org, arxiv.org, softwarestrategiesblog.com), so nothing below comes from reading a full primary page in this session. Findings marked **[S]** come from search-result summaries of the cited URL, and the summarising model may have paraphrased them. Findings marked **[K]** come from background knowledge up to June 2026. Their URLs are canonical repo or paper links that I did **not** re-check in this session, so the report writer should treat [K] items as "likely correct, unverified as of Oct 2026". Vendor performance numbers are labelled **(vendor claim)** unless an independent measurement exists.

---

## Q1. Offensive / red-team agents: architecture, framework, licence, safety controls

### Takeaway
Offensive agents have moved from research prototypes (PentestGPT, AutoAttacker, Incalmo) to well-starred open-source products (Strix, Shannon, PentAGI, CAI, HexStrike-MCP) and commercial services (XBOW). They share a common design: a planner/executor multi-agent loop, a Docker-sandboxed Kali-style tool layer (often exposed over MCP), and "validate with a working PoC" to cut false positives. Scope enforcement is still mostly target allow-lists plus human review, not formal rules-of-engagement (RoE) policy engines. Measured results are scarce and benchmarks are vendor-run.

### Cited Findings
**Open-source tools (landscape, Oct 2026)**
- **Strix**: Apache-2.0. The most-starred open-source AI pentest agent (one source: ~66k GitHub stars, early Oct 2026). Agents run in a Docker sandbox and try to validate each finding with a PoC. Paid cloud tier; internal-network testing only on Enterprise plan. **[S]** — [Strobes, "10 Best Open Source Agentic Pentesting Tools 2026"](https://strobes.co/blog/open-source-agentic-pentesting-tools/); [Ostorlab, 9 OSS AI pentest tools compared (2026)](https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html). Repo [K]: https://github.com/usestrix/strix
- **Shannon (Keygraph)**: AGPL-3.0 with a commercial licence option. White-box: reads source code and drives a browser. Reports 96.15% (100/104) on a "hint-free" variant of the XBOW benchmark. Keygraph itself says this is **not comparable to black-box results** (vendor claim). One source warns against running it on production. **[S]** — [Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/); [FireCompass guide](https://firecompass.com/blog-open-source-ai-pentesting-tools/). Repo [K]: https://github.com/KeygraphHQ/shannon
- **PentAGI (vxcontrol)**: MIT. Self-hosted multi-agent system in Docker with nmap/metasploit/sqlmap and a Neo4j knowledge graph for memory. One hands-on tester could not get its complex setup running. **[S]** — [Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/); [Ostorlab](https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html). Repo [K]: https://github.com/vxcontrol/pentagi
- **HexStrike AI**: less an autonomous agent than an **MCP server** that lets any LLM client (Claude, GPT, Copilot) drive 150+ security tools via 12+ coordinated agents. **[S]** — [Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/). Repo [K]: https://github.com/0x4m4/hexstrike-ai. [K] In Aug–Sep 2025 Check Point reported threat actors discussing HexStrike to speed up exploitation of Citrix NetScaler CVEs. This is the dual-use signal for MCP tool wrappers (verify: https://blog.checkpoint.com/).
- **CAI (Cybersecurity AI, Alias Robotics)**: a framework for building your own security agents, with broad model support (LiteLLM-style). One 2026 comparison claims the repo was **archived as of Aug 2026**. **Unconfirmed**; verify. **[S]** — [Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/). [K] Paper: "CAI: An Open, Bug Bounty-Ready Cybersecurity AI", arXiv 2504.06017 (https://arxiv.org/abs/2504.06017). Repo https://github.com/aliasrobotics/cai. Its agent abstractions (Agents, Tools, Handoffs, Guardrails) derive from the OpenAI Agents SDK. Licence was a research/non-commercial-use licence, not OSI (verify).
- **Benchmark caveat**: Escape's benchmark ran Strix and PentAGI on DeepSeek v3.2, with PentAGI in a prompt-only configuration. Ostorlab's single hands-on test (a deliberately vulnerable banking app) found Strix and RedAmon strongest. Star counts and benchmark numbers differ across sources, and most come from vendors. **[S]** — [Escape, Benchmarking agentic AI pentesting tools](https://escape.tech/blog/benchmarking-agentic-ai-pentesting-tools/); [Ostorlab](https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html)
- Curated lists track 39+ tools; the field is crowded. **[S]** — [AppSecSanta, AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026); [awesome-ai-pentesting](https://github.com/skyvanguard/awesome-ai-pentesting)

**Research prototypes [K]**
- **PentestGPT** (Deng et al., USENIX Security 2024): three modules (Reasoning / Generation / Parsing) built around a "Pentesting Task Tree". Human-in-the-loop by design: the operator runs the commands. MIT. — https://arxiv.org/abs/2308.06782 ; https://github.com/GreyDGL/PentestGPT
- **AutoAttacker** (Xu et al., 2024): LLM-guided post-breach "hands-on-keyboard" attacks with summariser/planner/navigator modules and an experience-RAG store; evaluated in a lab against Windows/Linux targets. — https://arxiv.org/abs/2403.01038
- **Incalmo** (Singer et al., CMU/Anthropic, 2025): LLMs issue **high-level intents** (scan, lateral-move, exfiltrate). A task-specific action layer and an environment-state service translate them into tool calls. Reported success in multi-host network ranges where raw-shell LLMs failed. This is an important architectural pattern: an abstraction layer between the LLM and the tools. — https://arxiv.org/abs/2501.16466
- **Nebula** (Beryllium Security): open-source AI-assisted pentest CLI that keeps the human at the terminal. — https://github.com/berylliumsec/nebula

**Commercial / frontier**
- **XBOW** reached #1 on HackerOne's US leaderboard in **June 2025**, reported as the first autonomous system to do so. One source: ~1,060 submissions in ~90 days; 132 confirmed/resolved, 303 triaged, 125 pending, ~25% informative/N/A. Humans reviewed reports before submission to comply with HackerOne AI policy. A Black Hat talk credited the low false-positive rate to **deterministic validators** (non-LLM checkers that confirm exploitation), not LLM judgment. **[S]** — [TechRepublic](https://www.techrepublic.com/article/news-ai-xbow-tops-hackerone-us-leaderboad/); [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/ai-based-pen-tester-top-bug-hunter-hackerone); [HN thread](https://news.ycombinator.com/item?id=44367548). Counts conflict (one source says 285 total, likely an earlier snapshot). — [Uproot Security](https://www.uprootsecurity.com/blog/xbow-hackerone-ai-penetration-testing)
- XBOW later disclosed CVSS 9.8 RCEs in Bing Image Search (CVE-2026-32194, CVE-2026-32191). **[S]**, secondary source only — [tech-insider.org](https://tech-insider.org/xbow-ai-hacker-bing-rce-2026/)
- **Google Big Sleep** (Project Zero + DeepMind): first real-world bug Oct 2024 (SQLite stack buffer underflow). Reported as pre-empting an in-the-wild exploit by July 2025, and 20 OSS vulnerabilities (mostly FFmpeg, ImageMagick) by Aug 2025. **[S]** — summarised in [AppSecSanta](https://appsecsanta.com/research/ai-pentesting-agents-2026). [K] Primary: https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html

**DARPA AIxCC (finals, Aug 2025)**
- 1st **Team Atlanta** (Georgia Tech, Samsung Research, KAIST, POSTECH), "Atlantis", $4M. 2nd **Trail of Bits**, "Buttercup", $3M. 3rd **Theori**, "RoboDuck", $1.5M (heavily LLM-based, less dependent on fuzzing). In the final scored round, systems found 54 synthetic vulnerabilities and patched 43, found 18 real (unplanted) bugs and produced 11 viable patches. Average cost ~$152 per task. Finalist systems were released open source. **[S]** — [DARPA, AIxCC results](https://www.darpa.mil/news/2025/aixcc-results); [Virtualization Review](https://virtualizationreview.com/Articles/2025/09/02/AIxCC-Find-and-Fix-Flaws-in-Software-Automatically.aspx)
- Buttercup is open source, with a standalone version that runs on a laptop. **[S]** — [Trail of Bits Buttercup page](https://www.trailofbits.com/buttercup/). [K] Architecture: orchestrator + fuzzing (libFuzzer/Jazzer via OSS-Fuzz harnesses) + LLM "seed-gen" and patcher agents; hybrid fuzzing+LLM rather than LLM-only. Repo https://github.com/trailofbits/buttercup

### Inferences
- **Common architecture**: (1) planner/orchestrator LLM; (2) specialised sub-agents (recon, exploit, validate, report); (3) tools in a Docker/Kali container, increasingly exposed as MCP; (4) knowledge/memory store (Neo4j, vector RAG); (5) **deterministic validation** of findings (PoC execution, oracle checks), the main lever against false positives (XBOW, Strix, AIxCC sanitizer oracles).
- **Safety controls are thin and ad hoc.** Public docs describe target allow-lists, Docker isolation and human review before submission. None of the sources found describe a declarative RoE/scope policy engine (CIDR/domain/time-window/technique allow-lists, enforced outside the LLM) as a first-class component. This is a gap robustidps.ai could fill.
- Incalmo's intent→action abstraction is a natural place to enforce scope: policy checks sit at the action-translation layer, not in prompts.
- AGPL (Shannon) and non-OSI licences (likely CAI) limit embedding in a commercial platform. Apache-2.0 (Strix) and MIT (PentAGI, PentestGPT) are safer to integrate.

### Gaps
- Could not fetch the repos to confirm current licences, stars, the CAI archive status, or the framework used by each tool (LangGraph vs OpenAI Agents SDK vs custom).
- No independent, cross-tool, same-model benchmark found. All comparisons are vendor-run or single-target.
- Team Atlanta's exact model/agent stack, and whether the AIxCC CRSs are actively maintained in 2026, are unverified.

---

## Q2. Defensive / SOC agents (commercial, open-source, academic)

### Takeaway
"Agentic SOC" is now a standard product category. Microsoft, Google, CrowdStrike, Palo Alto and Cisco/Splunk all ship production triage agents, alongside many startups (Dropzone, Prophet, Torq and others; one analyst counts ~220 "AI SOC" products). Big platforms report large speed-ups (vendor claims). Academic work (ProvSEEK, HunterAgent, OCR-APT, and the Oct 2026 "investigation failures" study) points to grounding, verifier loops and evidence chains as the hard problems, which lines up with robustidps.ai's provenance-graph triage agent.

### Cited Findings
**Platform vendors**
- **Google SecOps Triage & Investigation agent**: announced public preview Nov 2025, now **GA**. Google claims 5M+ alerts investigated, cutting a ~30-minute manual analysis to ~60 s (vendor claim). The agent decides true vs false positive. "Agentic automation", which mixes dynamic AI agents with **deterministic playbooks**, was still in preview at the time of the post. **[S]** — [TechInformed](https://techinformed.com/googles-soc-agent-cuts-alert-review-from-30-minutes-to-60-seconds/); [Google SecOps Gemini docs](https://docs.cloud.google.com/chronicle/docs/secops/gemini-secops); [Google Cloud community preview announcement](https://security.googlecloudcommunity.com/news-announcements-9/be-one-step-ahead-with-the-google-secops-alert-triage-and-investigation-agent-now-in-public-preview-6244)
- [K] Google also published **Sec-Gemini v1** (experimental security model, Apr 2025) — https://security.googleblog.com/2025/04/google-launches-sec-gemini-v1-new.html
- **Microsoft Security Copilot agents**: announced 24–25 Mar 2025 (Phishing Triage, Alert Triage for DLP/IRM, Conditional Access Optimization, Vulnerability Remediation, Threat Intelligence Briefing, plus partner agents). **[S]** — [Microsoft news (ES)](https://news.microsoft.com/es-es/2025/03/25/microsoft-presenta-agentes-de-security-copilot-y-nuevas-soluciones-para-proteger-la-ia); [Directions on Microsoft](https://www.directionsonmicrosoft.com/blog/microsoft-readies-new-security-copilot-agents/)
- Phishing Triage Agent: public preview Aug 2025 → **GA announced at Ignite**. Microsoft claims 6.5× more malicious alerts identified and 77% better verdict accuracy (vendor claim). It is being extended to identity and cloud alerts as a "Security Alert Triage Agent". **[S]** — [Redmond Mag](https://redmondmag.com/articles/2025/08/06/microsoft-rolls-out-phishing-triage-agent-in-security-copilot-public-preview.aspx); [Microsoft Adoption – Security Copilot](https://www.adoption.microsoft.com/en-gb/security-copilot/)
- Security Copilot was reportedly bundled with **E5 from Jan 2026**; the most advanced agents remain in preview. **[S]**, secondary — [D3 Security, AI SOC platforms 2026](https://d3security.com/blog/ai-soc-platforms-2026/)
- **CrowdStrike Charlotte AI** has grown into an "agentic workforce", with seven specialised agents announced May 2026 (secondary source). At RSAC 2026, CrowdStrike, Cisco/Splunk and Palo Alto all shipped production agentic SOC tooling. **[S]** — [D3 Security, agentic SOC for CrowdStrike](https://d3security.com/blog/agentic-soc-for-crowdstrike/); [CostNimbus, RSAC 2026 agentic SOC](https://costnimbus.com/article/rsac-2026-agentic-soc-budget-impact/)

**Startups**
- **Dropzone AI**: autonomous "AI SOC analyst" that investigates end to end and shows evidence, plus an AI Threat Hunter. $37M Series B per one source. **[S]** — [D3 Security](https://d3security.com/blog/ai-soc-platforms-2026/); [CB Insights compare](https://www.cbinsights.com/compare/cognna-vs-dropzone-ai)
- **Prophet Security**: AI SOC Analyst, Threat Hunter and Detection Engineer agents. Strategic investment from Amex Ventures and Citi Ventures (amounts undisclosed). Other sources cite a $30M Series A (July 2025); the funding timeline is inconsistent across sources. **[S]** — [PR Newswire](https://www.prnewswire.com/news-releases/prophet-security-accelerates-the-agentic-ai-soc-movement-with-strategic-investments-from-amex-ventures-and-citi-ventures-302696588.html)
- **Torq**: $140M Series D, Jan 2026 (secondary source). Hyperautomation/SOAR vendor turned "agentic SOC". **[S]** — [D3 Security](https://d3security.com/blog/ai-soc-platforms-2026/)
- One analyst counts **~220 AI SOC products, 16 pricing models, and "no scoreboard"**, i.e. no common benchmark. **[S]** — [Cyril Simonnet, Substack](https://cyrilsimonnet.substack.com/p/220-ai-socs-sixteen-prices-and-no)

**Open-source SOC agents / MCP-based [K]**
- Wazuh, TheHive/Cortex, MISP, Splunk, Elastic and Sentinel all have MCP servers (official or community), letting generic agents (Claude Desktop, LangGraph agents) query SIEM/case data. See Q3 for URLs. No dominant open-source "agentic SOC" framework emerged in the search results.

**Academic: provenance and triage agents**
- **ProvSEEK** (arXiv 2508.21323, Aug 2025): agentic LLM framework for provenance forensics. LLM agents plan investigations and issue **bounded provenance queries** plus CTI retrieval, then synthesise narratives rather than decide alone. Evaluated on seven public provenance datasets. **[S]** — [arXiv 2508.21323](https://arxiv.org/pdf/2508.21323)
- **OMNISEC** (arXiv 2503.03108): LLM-driven provenance-based IDS that targets rule-based false negatives and the scarcity of attack samples. **[S]** — [arXiv 2503.03108](https://arxiv.org/pdf/2503.03108)
- **OCR-APT** (arXiv 2510.15188): subgraph anomaly detection plus LLMs to reconstruct APT "stories" from audit logs. **[S]** — [arXiv 2510.15188](https://arxiv.org/pdf/2510.15188)
- Semantic-augmented provenance APT detection using LLM knowledge transfer (arXiv 2503.18316). **[S]** — [arXiv 2503.18316](https://arxiv.org/html/2503.18316v1)
- LLM-aided host-based IDS alert-to-intelligence framework (arXiv 2507.10873). **[S]** — [arXiv 2507.10873](https://arxiv.org/pdf/2507.10873)
- **HunterAgent** (arXiv 2605.29269, ~May 2026): neuro-symbolic attack-trace reconstruction under **anti-forensics** (PPID spoofing, log wiping). Asymmetric **generator–verifier** design: the LLM only proposes hypotheses and symbolic checks verify them. It distinguishes triage (is this an attack?) from hunting (rebuild the chain). **[S]** — [arXiv 2605.29269](https://arxiv.org/abs/2605.29269)
- **"From Investigation Failures to Reliable SOC Agents: Understanding and Improving LLM-Based Alert Triage"** (arXiv 2610.10608, **Oct 2026**): studies tier-1 triage failure modes. Notes that provenance methods need causal graphs, which standard source telemetry usually lacks. **[S]** (abstract-level only; fetch failed) — [arXiv 2610.10608](https://arxiv.org/html/2610.10608v1)
- Survey: "A Survey on Agentic Security: Applications, Threats and Defenses" (arXiv 2510.06445). **[S]** — [arXiv 2510.06445](https://arxiv.org/pdf/2510.06445)

### Inferences
- The design convergence is **LLM proposes, deterministic system verifies or executes**. Examples: Google's agents plus deterministic playbooks, HunterAgent's generator–verifier, ProvSEEK's bounded queries, XBOW's validators. A robustidps.ai framework should make the "verifier" a pluggable first-class component.
- Vendor metrics (30 min → 60 s; 6.5×; 77%) are not independently measured, and with ~220 products and no scoreboard, a neutral **evaluation harness for SOC agents** (ground-truth alert sets, cue-controlled variants, cost/latency/accuracy) is an open niche.
- robustidps.ai's provenance-graph triage agent maps directly onto the ProvSEEK/HunterAgent line. The 2610.10608 point about missing causal graphs suggests offering "provenance construction from standard telemetry" (Sysmon/auditd → graph) as a platform service.

### Gaps
- Could not read 2610.10608's specific failure taxonomy or numbers.
- No independent accuracy evaluations of Charlotte AI, Dropzone, Prophet or Torq were found.
- Exact GA date of Microsoft's Phishing Triage Agent (Ignite, Nov 2025 presumed) unconfirmed.
- Open-source incident-response *playbook* agents (e.g. CACAO-playbook-driven LLM agents) were not covered by any search result.

---

## Q3. MCP in security: servers, risks, scanners/gateways

### Takeaway
MCP has become the default tool layer for security agents: SIEM, threat intel, reverse-engineering and offensive tools all ship MCP servers. It has also become a major attack surface. Documented incidents (GitHub MCP exfiltration, the malicious postmark-mcp server, mcp-remote RCE CVE-2025-6514) and a 2026 CVE wave have produced two classes of defence: **pre-install scanners** (Snyk Agent Scan / ex-Invariant mcp-scan, Cisco MCP Scanner) and **runtime gateways** (Docker MCP Gateway, Lasso, Cloudflare, Pomerium). Practitioners recommend using both.

### Cited Findings
**Security MCP servers [K, URLs unverified this session]**
- Splunk MCP server (Splunk/Cisco official app plus community servers); Elastic "Agent Builder"/MCP for Elasticsearch — https://github.com/elastic/mcp-server-elasticsearch ; Microsoft Sentinel MCP server (preview announced 2025) ; VirusTotal MCP (community) ; Shodan MCP (community) ; **GhidraMCP** (LaurieWired) — https://github.com/LaurieWired/GhidraMCP ; **ida-pro-mcp** (mrexodia) — https://github.com/mrexodia/ida-pro-mcp ; HexStrike-AI as an offensive tool bundle (see Q1). Google released an official SecOps/GTI MCP server set — https://github.com/google/mcp-security

**Incidents / CVEs**
- **CVE-2025-6514 (mcp-remote)**: critical OS command injection when a client connects to an untrusted MCP server. Affects 0.0.5–0.1.15, fixed in 0.1.16. CVSS 9.6, disclosed by JFrog July 2025. ~437k downloads (download count, not confirmed affected installs). **[S]** — [GitHub Advisory GHSA-6xpm-ggf7-wc3p](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p)
- **postmark-mcp**: first malicious MCP server caught in the wild (reported by Snyk, 25 Sep 2025). A later version silently BCC'd all processed emails to an attacker domain. Reportedly benign for 15 versions before the malicious change: a **rug pull via the supply chain**. **[S]** — [AuthZed, timeline of MCP breaches](https://authzed.com/blog/timeline-mcp-breaches)
- **GitHub MCP prompt injection (May 2025, Invariant Labs)**: a malicious public issue steered an agent into leaking private-repo data into a public PR. Root cause was over-broad PAT scope combined with untrusted content in context (the "toxic flow" pattern). **[S]** — [AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
- Other items: CVE-2025-49596 (MCP Inspector, unauthenticated RCE); CVE-2025-54135 "CurXecute" (Cursor, RCE via MCP auto-start plus prompt injection, Aim Labs, Aug 2025); CVE-2025-58357 (5ire client); CVE-2026-13341 (Kong Konnect MCP server, indirect prompt injection → unintended API calls). **[S]** — [heyuan110, "30 CVEs in 60 days"](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/); [Practical DevSecOps MCP stats](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)
- One blog counts **30+ MCP-related CVEs in Jan–Feb 2026**, but its tally methodology is unclear; treat with caution. **[S]** — [heyuan110](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/)
- New attack research: **Unicode TAG-block concealment** of tool-metadata payloads, i.e. an "approval-view fidelity gap" where the user approves text that differs from what the model sees, shown across three server implementations. **[S]** — [arXiv 2607.05744](https://arxiv.org/pdf/2607.05744)
- [K] Attack taxonomy origin: Invariant Labs "Tool Poisoning Attacks" (Apr 2025) defined **tool poisoning** (hidden instructions in tool descriptions), **rug pulls** (description changes after approval) and **cross-server shadowing** (a malicious server's description alters how the agent uses another server's trusted tool) — https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- **OWASP MCP Top 10** now exists as a separate OWASP list. **[S]** — [Cycode, OWASP MCP Top 10](https://cycode.com/blog/owasp-mcp-top-10/). CSA published "Agentic MCP Security Best Practices v1". **[S]** — [CSA](https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/)

**Scanners and gateways**
- **Invariant mcp-scan → Snyk**: Invariant Labs was acquired by Snyk. mcp-scan checks for tool poisoning, rug pulls, cross-origin escalation and prompt injection, and shipped as **"Snyk Agent Scan" v0.5.12 (June 2026)**, the renamed successor. **[S]** — [Practical DevSecOps, Top MCP security tools](https://www.practical-devsecops.com/top-mcp-security-tools/); [Maxim, Best MCP security tools 2026](https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026/)
- **Cisco MCP Scanner**: free, open-source pre-install vetting (YARA + LLM-judge + Cisco AI Defense API, the last licensed separately). **[S]** — [Maxim](https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026/). Repo [K]: https://github.com/cisco-ai-defense/mcp-scanner
- **Docker MCP Gateway**, Cloudflare and Pomerium are grouped as runtime isolation / access-control layers. **[S]** — [Practical DevSecOps](https://www.practical-devsecops.com/top-mcp-security-tools/). [K] Docker's gateway runs each MCP server in its own container with secrets injection, an allow-listed catalogue and call interceptors — https://github.com/docker/mcp-gateway
- [K] **Lasso Security MCP Gateway** (open source, plugin-based PII/secret masking and prompt-injection guardrails) — https://github.com/lasso-security/mcp-gateway
- Recommended rug-pull mitigation: **hash-pin tool descriptions**, re-scan on change, curated tool bundles at the gateway. Scanners cannot stop malicious *tool results* at call time, so a runtime gateway is also needed. **[S]** — [Maxim](https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026/); [Practical DevSecOps](https://www.practical-devsecops.com/top-mcp-security-tools/)

### Inferences
- For robustidps.ai: a "security agent framework" should ship an **MCP gateway layer**, not just MCP clients. Needed features: description hashing and pinning, per-tool scope and credential binding, content filtering on tool *results* (the indirect-injection channel), and full call logging.
- Security MCP servers are high-value for "lethal trifecta" flows (private data + untrusted content + exfiltration channel). SIEM/EDR MCP servers can carry attacker-controlled log content straight into the model.
- The Unicode-tag paper implies the approval UI must render a canonicalised or normalised view of tool metadata. This is a concrete HITL-integrity feature.

### Gaps
- Could not verify which security MCP servers are official vs community as of Oct 2026 (Sentinel/Splunk GA status).
- No independent detection-rate comparison of mcp-scan vs Cisco scanner vs others was found.
- The pipelab "State of MCP Security 2026" report could not be fetched.

---

## Q4. Infrastructure patterns: scope/RoE, approval gates, credential isolation, sandboxing, audit, OTel, multi-tenancy

### Takeaway
The patterns are converging but not standardised. Common building blocks: microVM sandboxes (Firecracker/E2B) for untrusted execution, with gVisor as the middle tier; brokered short-lived credentials at a gateway; HITL approval for destructive actions; deterministic playbooks for execution; and OpenTelemetry GenAI spans (`invoke_agent`, `execute_tool`) for traces. The OTel conventions are **still "Development" status** in 2026, and declarative RoE enforcement is mostly missing from open-source tools.

### Cited Findings
- **Sandbox tiers**: microVMs (Firecracker, Kata) give each workload its own guest kernel behind hardware virtualisation and are seen as the gold standard (cold boot <125 ms, <5 MiB overhead, Firecracker's own figures; others measure >150 ms). gVisor is a user-space kernel, "medium" security, with some syscall gaps and ~sub-second cold starts (default for Modal, Daytona). Docker alone shares the host kernel. **[S]** — [SoftwareSeni comparison](https://www.softwareseni.com/firecracker-gvisor-containers-and-webassembly-comparing-isolation-technologies-for-ai-agents/); [Spheron, E2B/Daytona/Firecracker](https://www.spheron.network/blog/ai-agent-code-execution-sandbox-e2b-daytona-firecracker/); [Morph, AI agent sandbox](https://www.morphllm.com/ai-agent-sandbox)
- **E2B** is built on Firecracker (claimed cold starts 125–500 ms depending on source). Vercel Sandbox and AWS AgentCore Code Interpreter are also reported to be microVM-based. Numbers vary; benchmark yourself. **[S]** — [Morph, E2B vs Modal](https://www.morphllm.com/comparisons/e2b-vs-modal); [Spheron](https://www.spheron.network/blog/ai-agent-code-execution-sandbox-e2b-daytona-firecracker/)
- Open-source pentest agents (Strix, PentAGI) use **Docker** containers, i.e. the weakest isolation tier, for running offensive tooling. **[S]** — [Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/)
- **OpenTelemetry GenAI semantic conventions**: define `invoke_agent {gen_ai.agent.name}` spans (CLIENT kind, or INTERNAL for in-process agents, split in semconv v1.41) and `execute_tool` spans (tool name required in span name from v1.41). GenAI and **MCP** semantic conventions remain in **Development** status as of May 2026, with no public timeline for stability. Prompt, completion and tool-argument content is **not captured by default** (PII). **[S]** — [OpenTelemetry spec, GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans); [Greptime, May 2026](https://greptime.com/blogs/2026-05-09-opentelemetry-genai-semantic-conventions); [Honeycomb guide](https://www.honeycomb.io/blog/instrumenting-ai-agents-agent-timeline-opentelemetry-guide)
- **Deterministic playbooks + AI agents**: Google's "agentic automation" explicitly combines dynamic agents with deterministic enterprise playbooks (preview). **[S]** — [TechInformed](https://techinformed.com/googles-soc-agent-cuts-alert-review-from-30-minutes-to-60-seconds/)
- **Human review before external action**: XBOW kept human review of reports before HackerOne submission. **[S]** — [TechRepublic](https://www.techrepublic.com/article/news-ai-xbow-tops-hackerone-us-leaderboad/)
- **HITL overrides and real-time guardrails** are now marketed features of agent-security vendors (e.g. Akto's July 2026 release). **[S]**, vendor — [Akto](https://www.akto.io/blog/mitre-atlas-agentic-ai)
- **Credential scoping**: the GitHub MCP incident was attributed to broad PAT scopes, so least-privilege per-tool tokens is the stated lesson. **[S]** — [AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
- Runtime gateways enforce identity, tool access and content policy per tool call (Docker MCP Gateway, Cloudflare, Pomerium). **[S]** — [Practical DevSecOps](https://www.practical-devsecops.com/top-mcp-security-tools/)
- [K] Policy-as-code for agents: Invariant "Guardrails" (rule language over agent traces, now Snyk); OPA/Rego and Cedar are used in agent gateways for tool-call authorisation. Microsoft Security Copilot agents run under per-agent identities with admin-defined scope. **Unverified this session.**

### Inferences
- **Reference stack for robustidps.ai**:
  - (1) Tool layer = MCP servers behind an internal **MCP gateway** that does pinning, auth and result filtering.
  - (2) A **policy decision point** outside the LLM, e.g. OPA/Cedar, or a learned "predictive safety filter". It evaluates each proposed `execute_tool` against scope (targets/CIDRs/time windows/technique allow-list for offensive work; asset criticality for containment) and returns allow/deny/require-approval.
  - (3) **Approval gates** for destructive or containment actions (isolate host, disable account, block IP, exploit attempt) with a normalised view of the action.
  - (4) **Sandbox per run**: Docker for low-risk analysis, gVisor or Firecracker for executing exploits or unknown samples.
  - (5) **Credential broker**: short-lived, per-tool, per-tenant tokens, never exposed to the LLM context.
  - (6) **Audit** = OTel GenAI spans plus an append-only or hash-chained decision log linking prompt → plan → policy decision → approval → tool result. The provenance-graph expertise transfers here: an agent-action provenance graph.
- Because OTel GenAI is still in Development, building on it is sensible but needs a version pin and an adapter layer.
- Multi-tenant isolation (separate sandboxes, credential vaults and memory stores per tenant) is assumed by vendors, but no source in this session documented how it's done.

### Gaps
- No source found that documents a standard RoE/scope schema for offensive agents.
- No primary documentation retrieved on multi-tenant memory isolation for agent platforms.
- Could not verify the OTel `execute_tool` attribute list beyond span naming.

---

## Q5. Standards and guidance (OWASP, NIST, MITRE ATLAS, EU AI Act)

### Takeaway
There is now a stable reference set for agent-security products: OWASP LLM Top 10 2025, the **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10, released Dec 2025)**, the OWASP Agentic Threats & Mitigations guide, and the OWASP MCP Top 10. NIST/CAISI work on **agent hijacking** evaluation (AgentDojo-based) shows hijack success of 81% with adaptive attacks. **MITRE ATLAS** added many agent-tagged techniques through 2026 (counts disputed). The **EU AI Act** high-risk deadlines were pushed back by the Digital Omnibus (Annex III → 2 Dec 2027) via a provisional deal that was not yet formally adopted as of the latest source (June 2026).

### Cited Findings
- **OWASP Top 10 for Agentic Applications 2026**: ASI01 Agent Goal Hijack; ASI02 Tool Misuse; ASI03 Identity & Privilege Abuse; ASI04 (Agentic) Supply Chain; ASI05 Unexpected Code Execution; ASI06 Memory & Context Poisoning; ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures; ASI09 Human-Agent Trust Exploitation; ASI10 Rogue Agents. Published **9 Dec 2025** per the more detailed guide (another source says Feb 2026). It excludes classic web vulnerabilities and governance, which it defers to NIST AI RMF, ISO/IEC 42001 and the EU AI Act. A common practice maps each ASI to a NIST AI RMF "Manage" control and an ISO 42001 Annex A control. **[S]** — [Giskard](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026); [Modulos guide](https://docs.modulos.ai/frameworks/owasp-top-10-agentic); [Teleport](https://goteleport.com/blog/owasp-top-10-agentic-applications/); [Auth0](https://auth0.com/blog/owasp-top-10-agentic-applications-lessons/)
- ASI01 mitigation: treat retrieved content (emails, docs, tickets) as untrusted; constrain objectives. **[S]** — [Giskard](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026)
- Tooling already maps to ASI (e.g. DeepTeam red-teaming framework). **[S]** — [DeepTeam docs](https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications)
- [K] **OWASP Top 10 for LLM Applications 2025** (released Nov 2024): LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data & Model Poisoning, LLM05 Improper Output Handling, LLM06 **Excessive Agency**, LLM07 System Prompt Leakage, LLM08 Vector & Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption — https://genai.owasp.org/llm-top-10/
- [K] **OWASP ASI "Agentic AI – Threats and Mitigations"** v1.0 (Feb 2025), threat model T1–T15 (memory poisoning, tool misuse, privilege compromise, resource overload, cascading hallucination, intent breaking/goal manipulation, misaligned behaviour, repudiation/untraceability, identity spoofing, overwhelming HITL, unexpected RCE, agent communication poisoning, rogue agents, human attacks on multi-agent systems, human manipulation) — https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- **NIST/CAISI agent hijacking**: Jan 2025 technical blog using **AgentDojo** (ETH Zurich; Workspace/Travel/Slack/Banking environments). Existing attacks reached 11% success; novel agent-specific attacks reached **81%** in a single attempt (80% averaged over 25 attempts), against upgraded Claude 3.5 Sonnet. Lessons: evaluations must be adaptive, and multi-attempt testing gives more realistic estimates. **[S]** — [NIST technical blog (Jan 2025)](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations); [NIST node](https://www.nist.gov/node/1872381); [data.gov AgentDojo-Inspect dataset](https://catalog.data.gov/dataset/agentdojo-inspect)
- **CAISI + Gray Swan + UK AISI large-scale red-teaming competition**: per a CSA note (AI-assisted, not officially reviewed), 13 frontier models, 250k+ attacks, at least one successful hijack against **every** model. **[S]** — [NIST CAISI blog](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition); [CSA research note on CAISI agent security agenda, Apr 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-caisi-ai-agent-security-agenda-2026-2/); [CSA on NIST agent red-teaming, Mar 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-red-teaming-standards-202603/)
- **MITRE ATLAS**: the first 2026 update expanded agentic coverage (e.g. AI Service API technique AML.T0096; SesameOp case study AML.CS0042, a backdoor using the OpenAI Assistants API as C2). **[S]**, vendor contributor — [Zenity](https://zenity.io/blog/current-events/zenitys-contributions-to-mitre-atlas-first-2026-update). Version and count claims **conflict**: v5.1.0 (Nov 2025) with 16 tactics/84 techniques, and v5.4.0 (Feb 2026) adding agent techniques ([Vectra](https://vectra.ai/topics/mitre-atlas)), vs "v2026.09" with 16 tactics/120 techniques/208 entries, 139 tagged Agentic AI ([Speakeasy, Sep 2026](https://www.speakeasy.com/blog/mitre-atlas-explained)). Verify on https://atlas.mitre.org. [K] Oct 2025 ATLAS additions (with Zenity) included agent-specific techniques such as AI agent context poisoning, memory manipulation, and exfiltration via agent tool invocation. **Unverified IDs.**
- **EU AI Act timeline**: Digital Omnibus proposed **19 Nov 2025**. Provisional agreement **7 May 2026**; EP vote to adopt **16 June 2026**; Council approval and OJ publication still pending at that time. Annex III stand-alone high-risk obligations deferred **2 Aug 2026 → 2 Dec 2027**; Annex I (embedded in products) → 2 Aug 2028. If not published before 2 Aug 2026, the original dates technically apply. Also adds a new Art. 5 prohibition on non-consensual intimate imagery and CSAM generators. **[S]** — [Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/); [Sidley Data Matters, 22 Jun 2026](https://datamatters.sidley.com/2026/06/22/eu-lawmakers-reach-provisional-agreement-to-delay-key-eu-ai-act-obligations/); [CMS](https://cms.law/en/gbr/publication/The-EU-s-Digital-Omnibus-on-AI-What-the-Provisional-Agreement-Really-Changes); [OneTrust](https://www.onetrust.com/blog/eu-digital-omnibus-proposes-delay-of-ai-compliance-deadlines/)
- [K] AI Act relevance for security agent tooling: GPAI obligations (Art. 53/55) have applied since 2 Aug 2025 to model providers, not to platforms that call them. Security tools are generally **not** Annex III high-risk unless used e.g. as safety components of critical infrastructure (Annex III §2). Art. 15 requires accuracy, robustness and cybersecurity for high-risk systems, explicitly including resilience against data poisoning and adversarial examples. Art. 50 transparency duties apply from Aug 2026. Interpretation unverified; legal review needed.

### Inferences
- A robustidps.ai framework could ship **mappings as metadata**: each guardrail or test labelled with ASI-xx, LLM-xx, ATLAS AML.Txxxx and NIST AI RMF function. Compliance-minded users would value this and it is cheap to do.
- The NIST finding (11% → 81% with adaptive attacks; multi-attempt matters) argues the evaluation harness should use **adaptive, multi-trial attacks** and report pass@k-style hijack rates, not single-shot static prompt-injection suites.
- With EU high-risk obligations likely pushed to Dec 2027, compliance pressure for security agents in 2026–27 comes mainly from customer procurement (OWASP/NIST mappings) rather than regulation.

### Gaps
- Primary ATLAS changelog not retrieved; technique IDs and counts unverified.
- Formal adoption and OJ publication status of the AI Omnibus after June 2026 not confirmed.
- No NIST SP or official CAISI agent-security guidance document (as opposed to blogs and RFI) confirmed; the CSA notes reference a CAISI 2026 "AI Agent Security agenda", whose contents were not read.

---

## Q6. Market and adoption signals

### Takeaway
Adoption is strong and well funded but noisy. Every major SOC platform shipped agents at RSAC 2026; startups raised large rounds (Torq $140M Series D; Dropzone $37M Series B; Prophet strategic rounds from bank VCs); one analyst counts ~220 AI-SOC products. Most figures come from vendor-adjacent sources and conflict. Offensive AI agents became mainstream after XBOW's HackerOne result and AIxCC.

### Cited Findings
- RSAC 2026: CrowdStrike, Cisco/Splunk and Palo Alto all shipped production agentic SOC tools. **[S]** — [CostNimbus](https://costnimbus.com/article/rsac-2026-agentic-soc-budget-impact/)
- A headline of "$3.6B in Crunchbase funding, $96B in M&A, and 10 agentic AI security startups" for 2026 (page could not be fetched; figures unverified, and the $96B M&A figure likely includes large non-agentic deals such as Google–Wiz, $32B, announced Mar 2025 [K]). **[S]** — [Software Strategies Blog, 28 Mar 2026](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/)
- MarketsandMarkets publishes an "Agentic AI SOC market" forecast to 2032 (paywalled; numbers not retrieved). **[S]** — [MarketsandMarkets](https://www.marketsandmarkets.com/Market-Reports/agentic-ai-security-operations-center-soc-market-236140836.html)
- ~220 AI-SOC products, 16 pricing models, no common scoreboard. **[S]** — [Simonnet](https://cyrilsimonnet.substack.com/p/220-ai-socs-sixteen-prices-and-no)
- Vectra's 2026 predictions frame AI as scaling offence and push defence to automate. **[S]**, vendor opinion — [Vectra](https://www.vectra.ai/blog/security-predictions-for-2026-when-ai-scales-the-offense-defense-must-evolve)
- Consolidation in AI-agent security: Snyk acquired Invariant Labs (mcp-scan → Snyk Agent Scan). **[S]** — [Practical DevSecOps](https://www.practical-devsecops.com/top-mcp-security-tools/). [K] Other 2025 deals: Palo Alto–Protect AI, Check Point–Lakera, SentinelOne–Prompt Security, F5–CalypsoAI, Cato–Aim Security; verify dates and amounts.
- [K] Gartner placed "AI agents" / "agentic AI" at or near the Peak of Inflated Expectations in its 2025 hype cycles and warned (June 2025) that >40% of agentic AI projects will be cancelled by end-2027. Gartner's 2025 SecOps hype cycle included "AI SOC agents" as an innovation trigger. **Unverified this session** — https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027

### Inferences
- Buyers face a crowded, unbenchmarked market. A neutral research platform that offers **transparent, reproducible evaluation** fits that need better than another closed agent product would.
- Offence/defence symmetry (XBOW, HexStrike misuse, AIxCC) creates demand for dual-use controls (scope enforcement, audit). That supports positioning robustidps.ai as a "safe-by-construction" framework.

### Gaps
- Primary funding press releases for Dropzone, Torq and Prophet were not retrieved; amounts and dates conflict across sources.
- No 2026 Gartner hype-cycle placement retrieved.

---

## Q7. Gaps and opportunities for a research platform (robustidps.ai)

### Takeaway
What practitioners lack is not another agent loop. They lack (1) a **reusable, LLM-external safety and policy layer** (scope/RoE, approval gates, predictive action-risk filtering) that works across frameworks; (2) a **neutral evaluation harness** with adaptive, cue-controlled benchmarks for both SOC and offensive agents; and (3) **auditable provenance of agent actions**. robustidps.ai's existing agent studio, agent-security plugins and provenance-graph triage agent map closely onto these gaps.

### Cited Findings
- No common scoreboard across ~220 AI-SOC products. — [Simonnet](https://cyrilsimonnet.substack.com/p/220-ai-socs-sixteen-prices-and-no)
- Open-source pentest benchmarks are vendor-run, model-confounded (DeepSeek v3.2), or white-box vs black-box incomparable (Shannon caveat). — [Escape](https://escape.tech/blog/benchmarking-agentic-ai-pentesting-tools/); [Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/)
- Adaptive, multi-attempt attacks raise hijack success from 11% to 81%, so static evaluations underestimate risk. — [NIST CAISI](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- Scanners alone cannot stop malicious tool results at runtime; gateways are needed. — [Maxim](https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026/)
- Approval-view fidelity gaps (Unicode-tag payloads) undermine naive HITL. — [arXiv 2607.05744](https://arxiv.org/pdf/2607.05744)
- Verifier-based designs (HunterAgent, XBOW validators, ProvSEEK bounded queries) are where reliability gains come from. — [arXiv 2605.29269](https://arxiv.org/abs/2605.29269); [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/ai-based-pen-tester-top-bug-hunter-hackerone); [arXiv 2508.21323](https://arxiv.org/pdf/2508.21323)
- Provenance methods require causal graphs that standard telemetry lacks. — [arXiv 2610.10608](https://arxiv.org/html/2610.10608v1)
- OTel GenAI conventions are not yet stable, so audit and trace formats are fragmented. — [OpenTelemetry](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans)

### Inferences (opportunity list for robustidps.ai)
1. **Framework-agnostic safety filter layer** ("predictive safety filter"): a policy decision point between planner and tools. It scores each proposed tool call (risk, reversibility, scope match, taint from untrusted inputs) and returns allow / deny / modify / require-approval. Implement it as an MCP-gateway middleware so it works with LangGraph, OpenAI Agents SDK, CAI, Claude Agent SDK, etc. Map rules to ASI02/03/05 and LLM06.
2. **Declarative scope/RoE spec**: YAML/JSON schema (targets, CIDRs, domains, time windows, permitted ATT&CK techniques, max intensity, data-handling rules) compiled into gateway policy. None of the open-source offensive agents reviewed exposes this as a first-class object.
3. **Containment approval gates for SOC agents**: risk-tiered actions (enrich → annotate → ticket → block IOC → isolate host → disable identity), with dual approval and blast-radius preview for tiers ≥ isolate. Approvals rendered from a canonicalised action (defends against the 2607.05744 fidelity gap).
4. **Evaluation harness with cue-controlled benchmarks**: the same scenario with/without injected cues (prompt injections in logs/tickets, misleading IOCs, anti-forensic artefacts à la HunterAgent). Adaptive multi-trial attacks (NIST lesson); metrics: verdict accuracy, evidence-grounding, hijack rate@k, unsafe-action rate, cost/latency. Fills the "no scoreboard" gap.
5. **Agent-action provenance graph**: reuse robustidps.ai's provenance expertise to log agent runs as a causal graph (input → retrieved artefact → model step → policy decision → approval → tool effect), exported as OTel GenAI spans with a version-pinned adapter, plus a hash-chained audit store. Doubles as a forensics tool for ASI08/ASI10 incidents.
6. **Pluggable verifiers**: first-class "verifier" interface (PoC replayer, Sigma/YARA rule check, provenance-path check, sandbox detonation) so users get the reliability gains seen in XBOW, HunterAgent and Google's playbooks.
7. **Sandbox profiles**: tiered (Docker → gVisor → Firecracker/E2B) selectable per tool and per tenant. Offensive tooling and sample detonation default to microVMs, which is stronger than Strix/PentAGI's Docker default.
8. **Curated, pinned MCP catalogue** for security servers (SIEM, TI, RE) with description hashing and re-scan on change (rug-pull defence). Optionally integrate Cisco MCP Scanner / Snyk Agent Scan in CI.
9. **Standards mapping metadata** on every control and test (OWASP ASI/LLM, MITRE ATLAS, NIST AI RMF, EU AI Act Art. 15), for procurement-driven users.

### Gaps
- No public evidence was found of an existing open-source product that offers items 1–4 together. That absence is a negative search result, not a confirmed market gap; a targeted check of e.g. Invariant/Snyk Guardrails, NVIDIA NeMo Guardrails, Microsoft Agent Governance tooling and Lakera/Check Point features is recommended before claiming novelty.
- Practitioner demand evidence (surveys of SOC/red-team users wanting customisable frameworks) was not found.
