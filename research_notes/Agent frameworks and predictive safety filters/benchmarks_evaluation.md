# Benchmarks, datasets and evaluation methodology for tool-using LLM agent safety/security and for guards on agent actions (as of Oct 2026)

**How this was checked (read first).** arXiv full text and the GitHub API could not be reached from the research sandbox (DNS failure or proxy 403). Items marked **[V]** were confirmed this session through search-engine snippets of primary pages: arXiv abstracts, NeurIPS/ICML/ICLR listings, and vendor blogs. Items marked **[PK]** come from prior knowledge, with training data up to about mid-2026. They are cited to their canonical arXiv/GitHub page but were *not re-fetched*. Check every [PK] number before putting it in a paper. Numbers that secondary sources reported inconsistently are flagged **(conflict)**.

---

## 1. Prompt-injection / agent-hijacking benchmarks (incl. MCP-specific)

### Takeaway
AgentDojo is the default executable suite for indirect prompt injection. It is the only one with a first-class "defense as pipeline element" hook, plus utility / utility-under-attack / targeted-ASR metrics and a public leaderboard. InjecAgent, BIPIA and Tensor Trust are static (no live tool execution). ASB and the 2025–26 MCP benchmarks (MCPSecBench, MCPTox, MSB, MCP-SafetyBench) widen the attack surface to tool poisoning and protocol attacks. None of them is about security operations or telemetry.

### Cited Findings
**AgentDojo** [PK] (Debenedetti et al., NeurIPS 2024 D&B; ETH SPY Lab).
- 4 suites (workspace, Slack, travel, banking), 97 user tasks, 629 security test cases. Stateful, executable Python tool environments.
- Metrics: benign utility, utility under attack, targeted ASR.
- Defenses plug in as pipeline elements, e.g. tool filter, PI detector, spotlighting, sandwiching.
- MIT licence; leaderboard at agentdojo.spylab.ai.
- Sources: [arXiv 2406.13352](https://arxiv.org/abs/2406.13352), [GitHub ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)

**AgentDojo-Inspect** [V]. The US AISI (now CAISI) fork of AgentDojo, with a bridge to the UK AISI Inspect framework, used for its agent-hijacking evaluations. Published as a NIST data publication. — [data.gov listing](https://catalog.data.gov/dataset/agentdojo-inspect); [NIST PDR mds2-3690](https://data.nist.gov/od/id/mds2-3690)

**InjecAgent** [PK] (Zhan et al., ACL Findings 2024).
- 1,054 test cases, 17 user tools, 62 attacker tools. Two attack intentions: direct harm and data stealing. Base and "enhanced" (hacking-prompt) settings.
- Tool outputs are pre-written, not executed, so it is an offline/static benchmark.
- Reported ReAct GPT-4 ASR was about 24% in the base setting (verify).
- Source: [arXiv 2403.02691](https://arxiv.org/abs/2403.02691)

**ASB – Agent Security Bench** [PK] (Zhang et al., ICLR 2025).
- 10 scenarios, 10 agents, 400+ tools.
- Attacks: direct and indirect PI, memory poisoning, Plan-of-Thought backdoor, mixed. 27 attack/defense methods in total.
- Highest average ASR reported was about 84.3%. Introduces a "Net Resilient Performance" metric.
- Source: [arXiv 2410.02644](https://arxiv.org/abs/2410.02644)

**WASP** [PK] (Evtimov et al., Meta, 2025). Web-agent prompt injection in sandboxed web environments (VisualWebArena-style). Reported finding: agents often *start* following injected instructions (about 16–86%) but rarely *complete* attacker goals (about 0–17%), which the authors call "security by incompetence" (verify numbers). — [arXiv 2504.18575](https://arxiv.org/abs/2504.18575)

**AgentDAM** [PK] (Zharmagambetov et al., Meta, 2025). Tests data minimization / privacy leakage by web agents on realistic web tasks. Not an injection benchmark as such. Task count not verified. — [arXiv 2503.09780](https://arxiv.org/abs/2503.09780)

**BIPIA** [PK] (Yi et al., KDD 2025). Indirect prompt injection against LLM-integrated apps: email QA, web QA, table QA, summarization, code QA. Not agentic; there is no tool execution. — [arXiv 2312.14197](https://arxiv.org/abs/2312.14197)

**Tensor Trust** [PK] (Toyer et al., ICLR 2024). An online game dataset of about 126k prompt-injection attacks and 46k defenses. It derives prompt-hijacking and prompt-extraction robustness benchmarks. Single-turn, no tools. — [arXiv 2311.01011](https://arxiv.org/abs/2311.01011)

**MCPSecBench** [V] (Yang et al., arXiv Aug 2025).
- 17 attack types across 4 attack surfaces.
- Tested against deployed MCP products (Claude Desktop, OpenAI, Cursor).
- COPEX points out that because it tests whole products, results mix the model with each product's system prompt, guardrails and orchestration.
- Sources: [arXiv 2508.13220](https://arxiv.org/abs/2508.13220); critique in [COPEX arXiv 2610.04378](https://arxiv.org/html/2610.04378)

**MCPTox** [V] (Wang et al., arXiv Aug 2025). Tool-poisoning attacks (malicious tool descriptions) against 45+ real-world MCP servers. The highest refusal rate (Claude-3.7-Sonnet) was below 3%. — [arXiv 2508.14925](https://arxiv.org/abs/2508.14925)

**MSB – MCP Security Bench** [V] (Zhang et al., arXiv Oct 2025). 12 MCP-specific attack types, evaluated end-to-end over the tool-use pipeline. — [arXiv 2510.15994](https://arxiv.org/abs/2510.15994) (seen only via search snippet)

**MCP-SafetyBench** [V] (Zong et al., ICLR 2026). Built on MCP-Universe with real MCP servers across 5 domains: browser automation, financial analysis, location navigation, repository management, web search. Reports large safety differences between open and closed models. — [arXiv 2512.15163](https://arxiv.org/abs/2512.15163)

**Other MCP/agent-injection benchmarks from 2026** [V] (titles only; details not checked):
- COPEX: adversarial context across MCP layers — [arXiv 2610.04378](https://arxiv.org/html/2610.04378)
- MCPHunt: cross-server data propagation — [arXiv 2604.27819](https://arxiv.org/pdf/2604.27819)
- ShieldNet: network-level guardrail against supply-chain injections. It argues that existing MCP benchmarks are mostly semantic manipulations or assume access to tool-side artifacts — [arXiv 2604.04426](https://arxiv.org/pdf/2604.04426)
- A3S-Bench (Ma et al., May 2026, Ant Group): 2,254 multi-turn dialogues (1,512 adversarial covering 34 techniques; 742 benign). Covers *temporal* (payload split across turns), *spatial* (payload hidden in complex artifacts) and *semantic* (malicious intent buried in benign context) evasions. Reports that average risk-trigger rate rises from 28.3% to 52.6% across 10 backbones — [arXiv 2605.22321](https://arxiv.org/html/2605.22321v1)
- "Adaptive Adversaries" multi-turn, multi-LLM benchmark — [arXiv 2607.18063](https://arxiv.org/pdf/2607.18063)
- AgentLAB: long-horizon attacks — [ResearchGate](https://www.researchgate.net/publication/400970840_AgentLAB_Benchmarking_LLM_Agents_against_Long-Horizon_Attacks)

### Inferences
- For a pre-execution filter, AgentDojo (plus the Inspect fork) is the most comparable public suite. Guard papers (MELON, CaMeL, Progent, LlamaFirewall, DRIFT, Task Shield) commonly report on it, so results line up with prior work.
- MCPTox's very low refusal rate suggests that the model's own refusals give almost no protection against poisoned tool metadata. An external filter is the relevant layer there.
- A3S-Bench's "semantic evasion" is the nearest general-purpose analogue to "benign-looking cover" in telemetry. But it targets the agent, not a separate monitor.

### Gaps
- Licences for ASB, MCPSecBench, MCPTox, MSB, MCP-SafetyBench and A3S-Bench were not checked (GitHub was unreachable).
- Exact current AgentDojo version (v1.2.x?) and task counts after its updates were not checked.
- "MCP-AttackBench" and similar names did not appear in search, so they are not confirmed to exist.

---

## 2. Harmful-action / risky-action benchmarks

### Takeaway
Two kinds of benchmark exist. Misuse benchmarks test whether the agent carries out a harmful user request: AgentHarm, SafeArena, CUAHarm, RedCode, OS-Harm's misuse split. Risk-of-accident / environment-risk benchmarks test unsafe side effects of benign requests: ToolEmu, Agent-SafetyBench, RiOSWorld, ST-WebAgentBench. SHADE-Arena and CUAHarm are the only ones that explicitly evaluate *monitors*. CUAHarm reports that monitoring computer-use agents is much harder than monitoring chat.

### Cited Findings
**AgentHarm** [PK] (Andriushchenko et al., Gray Swan / UK AISI, ICLR 2025).
- 110 malicious tasks (440 with augmentations), 11 harm categories, 104 synthetic tools. Includes a benign twin set for measuring over-refusal.
- Scored on harm score and refusal rate. Available in inspect_evals; dataset on Hugging Face (ai-safety-institute/AgentHarm) with a canary string.
- Key finding: simple jailbreak templates transfer to agentic settings.
- Source: [arXiv 2410.09024](https://arxiv.org/abs/2410.09024)

**ToolEmu** [PK] (Ruan et al., ICLR 2024 spotlight).
- An LM-emulated sandbox: 36 toolkits, 311 tools, 144 test cases. An LM safety evaluator flags risky actions caused by underspecified instructions.
- The authors report that most flagged failures (about 68.8%) would be valid real-world failures (verify).
- Source: [arXiv 2309.15817](https://arxiv.org/abs/2309.15817)

**R-Judge** [PK] (Yuan et al., EMNLP Findings 2024). 569 multi-turn agent interaction records, 27 scenarios, 5 application categories, 10 risk types. Each record is labelled safe/unsafe with a risk description, and the task is judging, not acting. Reported best was GPT-4 at about 72.5% F1 vs about 89% for humans (verify). — [arXiv 2401.10019](https://arxiv.org/abs/2401.10019)

**Agent-SafetyBench** [PK] (Zhang et al., Tsinghua, Dec 2024). 349 interaction environments, 2,000 test cases, 8 risk categories, 10 failure modes. No tested agent exceeded a 60% safety score. — [arXiv 2412.14470](https://arxiv.org/abs/2412.14470)

**SafeArena** [PK] (Tur et al., 2025). 250 safe and 250 harmful web tasks on 4 websites across 5 harm categories. — [arXiv 2503.04957](https://arxiv.org/abs/2503.04957)

**ST-WebAgentBench** [PK] (Levy et al., IBM, 2024/25). Enterprise web tasks with safety and trust policies. Introduces Completion-under-Policy (CuP) and risk ratio metrics. Task count has changed between versions, so verify it. — [arXiv 2410.06703](https://arxiv.org/abs/2410.06703)

**OS-Harm** [V] (Kuntz et al., EPFL/CMU, NeurIPS 2025 D&B).
- Built on OSWorld: 150 tasks in 3 categories (deliberate misuse, prompt injection, model misbehaviour).
- Uses an LLM judge for both task completion and safety, with F1 agreement with humans of 0.76 / 0.79.
- Frontier models often complied with misuse and were vulnerable to static injections.
- Sources: [arXiv 2506.14866](https://arxiv.org/pdf/2506.14866), [NeurIPS page](https://neurips.cc/virtual/2025/poster/121772), [GitHub tml-epfl/os-harm](https://github.com/tml-epfl/os-harm)

**RiOSWorld** [V] (NeurIPS 2025). 492 risky computer-use tasks across web, social media, multimedia, OS, email and office apps. Risk sources are user-originated or environmental. Scored on two axes: risk-goal intention and risk-goal completion. — [NeurIPS page](https://neurips.cc/virtual/2025/poster/117273)

**CUAHarm** [V] (Tian et al., 2025; the name is real).
- 104 expert-written misuse tasks run in a sandbox, e.g. disabling firewalls, leaking data, DoS, installing backdoors.
- Success is scored by rule-based checks on the final environment state, not by refusal.
- Models executed over 40% of harmful tasks (e.g. Gemini 2.5 Pro about 90%, Claude 4 Sonnet about 54%).
- LM monitors were tested and found to catch CUA misuse far less reliably than chatbot misuse, even with chain-of-thought inputs.
- Code at github.com/db-ol/CUAHarm.
- Source: [arXiv 2508.00935](https://arxiv.org/abs/2508.00935)

**RedCode** [PK] (Guo et al., NeurIPS 2024 D&B). RedCode-Exec contains about 4,050 risky code-execution test cases in Docker (Python/Bash); RedCode-Gen contains 160 malicious-software generation prompts. — [arXiv 2411.07781](https://arxiv.org/abs/2411.07781)

**SHADE-Arena** [PK] (Kutasov et al., Anthropic et al., 2025).
- 17 task pairs: a benign main task plus a covert harmful side task, in large tool environments. Measures both sabotage success and *monitor* detection.
- Reported best monitor was Gemini 2.5 Pro at AUC about 0.87 (verify).
- Source: [arXiv 2506.15740](https://arxiv.org/abs/2506.15740)

### Inferences
- CUAHarm and SHADE-Arena show that evaluating a monitor separately from the agent is accepted practice. Both report monitor detection performance (AUC, or TPR at an FPR threshold) as distinct from agent refusal. A SOC filter paper should follow that framing.
- CUAHarm's misuse tasks (disable firewall, backdoor) overlap with the actions a hijacked SOC/IR agent might take. It is the best existing proxy for security-relevant harmful actions on a host.

### Gaps
- Licences for SafeArena, ST-WebAgentBench, RiOSWorld and CUAHarm were not checked.
- SHADE-Arena: whether all task pairs are public was not checked (some were reportedly held out). The AUC number is unverified.

---

## 3. Cybersecurity-capability and security-operations agent benchmarks

### Takeaway
Offensive-capability benchmarks are mature: Cybench, NYU CTF Bench, CVE-Bench, BountyBench, CyberGym, and CyberSecEval 3's offensive components. Defensive/SOC benchmarks appeared in 2025–26:
- ExCyTIn-Bench: Microsoft, ICML 2026, Sentinel log tables.
- CyberSOCEval: Meta + CrowdStrike, part of CyberSecEval 4.
- AuditBench: audit logs, 2026.
- DiagChain: attack-chain reconstruction, Aug 2026.
- Static knowledge suites: CTIBench, SecBench.

None of them pairs SOC investigation with an *action-safety filter*, and none controls lexical cues.

### Cited Findings
**CyberSecEval 1–4** [PK, with CSE4 V] (Meta PurpleLlama; MIT).
- CSE1 (Dec 2023): insecure-code generation and cyberattack helpfulness — [arXiv 2312.04724](https://arxiv.org/abs/2312.04724)
- CSE2 (Apr 2024): adds prompt injection, code-interpreter abuse and false-refusal rate — [arXiv 2404.13161](https://arxiv.org/abs/2404.13161)
- CSE3 (Aug 2024): adds visual PI, spear-phishing and autonomous offensive operations — [arXiv 2408.01605](https://arxiv.org/abs/2408.01605)
- CSE4 (2025): adds AutoPatchBench and CyberSOCEval — [PurpleLlama GitHub](https://github.com/meta-llama/PurpleLlama)

**CyberSOCEval** [V] (Meta with CrowdStrike, Sep 2025, part of CSE4).
- Two parts: malware analysis over real sandbox detonation outputs (process trees, network traffic), and threat-intel reasoning over CTI reports, including multimodal ones.
- Secondary reports give accuracy of about 15–28% on malware analysis and 43–53% on TI reasoning (**unverified against the paper**).
- Sources: [arXiv 2509.20166](https://arxiv.org/abs/2509.20166v1), [Meta AI page](https://ai.meta.com/research/publications/cybersoceval-benchmarking-llms-capabilities-for-malware-analysis-and-threat-intelligence-reasoning/)

**ExCyTIn-Bench** [V] (Microsoft; ICML 2026 poster).
- A simulated SOC in an Azure tenant, queried through a SQL environment over Microsoft Sentinel and related log tables.
- Questions are generated from investigation graphs built from alerts produced by expert-written detection logic: start node = context, end node = answer.
- Reward-based scoring; best model reward about 0.606. Open source.
- **(conflict):** 57 vs 59 log tables, and 589 (v1) vs 7,542 questions, depending on version.
- Sources: [arXiv 2507.14201](https://arxiv.org/pdf/2507.14201), [ICML 2026 page](https://icml.cc/virtual/2026/poster/66310), [Microsoft Security blog, 14 Oct 2025](https://microsoft.com/en-us/security/blog/2025/10/14/microsoft-raises-the-bar-a-smarter-way-to-measure-ai-for-cybersecurity/)

**AuditBench** [V] ("Benchmarking and Exploring the Capabilities of LLMs for Attack Investigations", Anand et al., 2026).
- Audit-log scenarios (50+ malicious/benign; 26 drawn from DARPA OpTC), 5 LLMs, 4 investigation tasks.
- Finding: LLMs treat audit logs as overly suspicious, producing many false positives. The authors suggest combining provenance-graph and information-flow methods with LLMs.
- Sources: [arXiv 2606.10281](https://arxiv.org/pdf/2606.10281); the summary is via [pith.science](https://pith.science/citations/1cb65cb0-801c-4e2c-97f5-123d40cb654e), so details are secondary.

**DiagChain** [V] (Aug 2026). A diagnostic benchmark for LLM agents reconstructing evidence-grounded attack chains from telemetry. Evaluation is stage-wise, with controlled evidence noise and chain length. — [arXiv 2608.03591](https://arxiv.org/html/2608.03591v1)

**Provenance-agent systems** [V] (systems, not benchmarks; useful baselines):
- ProvAgent: multi-agent investigation, evaluated against *mimicry attacks* (tampered audit data / injected benign structure, citing Goyal et al.) — [arXiv 2603.09358](https://arxiv.org/html/2603.09358v1)
- ProvSEEK: DARPA datasets — [arXiv 2508.21323](https://arxiv.org/html/2508.21323v2)
- SherAgent: 10k+ real SOC alerts — [arXiv 2607.09176](https://arxiv.org/pdf/2607.09176)
- Minos — [arXiv 2607.00440](https://arxiv.org/pdf/2607.00440)
- TrackAgent: DARPA TC, OpTC — [NDSS PRISM 2026](https://dev.ndss-symposium.org/wp-content/uploads/prism2026-22.pdf)

**Cybench** [PK] (Zhang et al., ICLR 2025). 40 professional CTF tasks from 4 competitions, with subtasks for partial credit. Apache-2.0; included in inspect_evals and used in UK/US AISI pre-deployment testing. — [arXiv 2408.08926](https://arxiv.org/abs/2408.08926); AISI use confirmed [V] in [arXiv 2601.15679](https://arxiv.org/pdf/2601.15679)

**NYU CTF Bench** [PK] (Shao et al., NeurIPS 2024 D&B). 200 CSAW CTF challenges. — [arXiv 2406.05590](https://arxiv.org/abs/2406.05590)

**CVE-Bench** [PK] (Zhu et al., ICML 2025). 40 critical-severity web-app CVEs in a sandbox; best agents exploited up to about 13% (zero-day setting) / about 25% (one-day) (verify). — [arXiv 2503.17332](https://arxiv.org/abs/2503.17332)

**BountyBench** [PK] (Zhang et al., Stanford, 2025). 25 real systems, 40 bug bounties; Detect / Exploit / Patch tasks with dollar values attached. — [arXiv 2505.15216](https://arxiv.org/abs/2505.15216)

**CyberGym** [PK] (Wang et al., UC Berkeley, 2025). About 1,507 real vulnerabilities across 188 OSS-Fuzz projects, with PoC-reproduction tasks; best success was low (about 11.9%) and new zero-days were found (count unverified). — [arXiv 2506.02548](https://arxiv.org/abs/2506.02548)

**CTIBench** [PK] (Alam et al., NeurIPS 2024 D&B). CTI-MCQ, CTI-RCM (CVE→CWE), CTI-VSP (CVSS prediction), CTI-ATE (ATT&CK technique extraction), CTI-TAA (threat-actor attribution). — [arXiv 2406.07599](https://arxiv.org/abs/2406.07599)

**SecBench** [PK] (Jing et al., Dec 2024). Large bilingual MCQ and short-answer cybersecurity knowledge benchmark (about 44.8k MCQ / 3.1k SAQ; verify). — [arXiv 2412.20787](https://arxiv.org/abs/2412.20787)

### Inferences
- ExCyTIn-Bench is the closest public analogue to SOCGraph-21: a graph-derived investigation over logs with an agentic SQL tool. But it measures *capability*, not *safety-filter behaviour*, and its entity names are realistic, not controlled.
- AuditBench's false-positive finding is a ready-made counterpoint for a filter paper. LLM over-suspicion of logs means a filter's FPR on benign SOC actions must be reported, not just its catch rate.

### Gaps
- No public SOC benchmark found where the agent takes *response actions* (isolate host, kill process, block IP) and those actions are labelled safe/unsafe for a filter to judge.
- Licences for ExCyTIn-Bench (likely MIT; unverified), AuditBench and DiagChain were not checked.

---

## 4. Guard/monitor evaluation datasets and metrics; adaptive-attack protocols

### Takeaway
Labelled-trajectory datasets for judges exist: R-Judge (569), ASSEBench (2,293), ShieldAgent-Bench (about 2–3k), GuardAgent's EICU-AC / Mind2Web-SC, and the OS-Harm and SHADE-Arena judge labels. Reporting conventions are converging on:
- Detection: TPR at low fixed FPR, or AUC.
- Utility: utility without attack and utility under attack.
- Attack: ASR, under *adaptive* attacks.
- Cost: overhead in latency and tokens.

"The Attacker Moves Second" (Oct 2025) made adaptive evaluation effectively mandatory. Static-attack ASR around 1% became over 95% under adaptive search.

### Cited Findings
**ASSEBench / AgentAuditor** [V] (Luo et al., NeurIPS 2025).
- 2,293 annotated interaction records, 15 risk types, 29 scenarios, with "Strict" and "Lenient" labels for ambiguous cases.
- AgentAuditor is a training-free, memory-augmented LLM judge (experiential memory plus multi-stage retrieval). The authors claim human-level accuracy.
- Repo given as github.com/Astarojth/AgentAuditor-ASSEBench.
- Sources: [arXiv 2506.00641](https://arxiv.org/abs/2506.00641), [NeurIPS page](https://neurips.cc/virtual/2025/poster/120154)

**ShieldAgent-Bench** [V] (Chen et al., ICML 2025).
- Instruction–trajectory pairs from attacks (AgentPoison, AdvWeb per a secondary source) across 6 web environments and 7 risk categories.
- **(conflict)** on size: about 3K pairs (abstract) vs 2K (arXiv v1 intro) vs 960 instructions / 3,110 unsafe trajectories (secondary).
- ShieldAgent reports +11.3% over prior guards and 90.1% recall.
- Sources: [arXiv 2503.22738](https://arxiv.org/html/2503.22738v2), [PMLR v267](https://proceedings.mlr.press/v267/chen25ae.html), [project page](https://shieldagent-aiguard.github.io/)

**GuardAgent** [PK] (Xiang et al., ICML 2025). Introduces EICU-AC (access control for an EHR agent) and Mind2Web-SC (safety-control policies for a web agent). Reported guard accuracy was about 98.7% and 90.0% (verify). — [arXiv 2406.09187](https://arxiv.org/abs/2406.09187)

**The Attacker Moves Second** [V] (Nasr, Carlini et al., Oct 2025).
- Spotlighting and Prompt Sandwiching on AgentDojo: about 1% ASR under static attacks became over 95% under search-based adaptive attacks.
- Human red-teamers found 265 and 178 successful attacks respectively.
- The claim that "over 90% of 12 defenses broken" comes from a secondary source and is **unverified**.
- Sources: [arXiv 2510.09023](https://arxiv.org/abs/2510.09023), [Simon Willison commentary](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)

**Monitor evasion via injection** [V] (arXiv 2510.09462). An untrusted model that knows the monitor's protocol can embed prompt injections in its outputs and consistently evade diverse monitors on two AI-control benchmarks. Defer-to-Resample can even *amplify* the injection. — [arXiv 2510.09462](https://arxiv.org/html/2510.09462v1)

**Guard results on AgentDojo** [PK]:
- CaMeL: about 77% task completion with provable security vs about 84% undefended — [arXiv 2503.18813](https://arxiv.org/abs/2503.18813)
- LlamaFirewall: PromptGuard 2 + AlignmentCheck reported to cut ASR from about 17.6% to about 1.75% (verify) — [arXiv 2505.03962](https://arxiv.org/abs/2505.03962)
- Progent: privilege control — [arXiv 2504.11703](https://arxiv.org/abs/2504.11703)
- MELON (ICML 2025): masked re-execution — [arXiv 2502.05174](https://arxiv.org/abs/2502.05174)

**Agentic evaluation methodology from AISI networks** [V]: a joint report on agentic evaluation methods covering leakage, fraud and cyber, including Cybench. — [arXiv 2601.15679](https://arxiv.org/pdf/2601.15679)

### Inferences
Recommended fair-evaluation protocol for a predictive pre-execution filter, synthesised from the above:
1. Report TPR at FPR = 1% and 5%, plus AUROC, at the *action* level and the *episode* level.
2. Report benign utility and utility under attack with the filter on and off, including over-blocking on benign SOC actions.
3. Report ASR under (a) static benchmark attacks and (b) an adaptive attacker who knows the filter. The adaptive attacker should search over names, field values and injection text against the filter's score.
4. Report p50/p95 added latency and tokens/$ per action.
5. Compare against standard baselines: PromptGuard-2 / LlamaFirewall AlignmentCheck, an LLM-judge (AgentAuditor-style), and a rule/allowlist baseline.
6. Give confidence intervals. With only 21 tasks, use per-task bootstrap or exact binomial intervals.

### Gaps
- Licences for ASSEBench and ShieldAgent-Bench were not checked.
- No guard dataset found with SOC/IR trajectories.
- No agreed standard FPR operating point for agent action filters was found. Papers vary (AUC, recall, F1).

---

## 5. Which benchmarks support plugging in an external pre-execution filter, and which give per-step traces?

### Takeaway
Native interception hooks:
- AgentDojo: defense pipeline elements that sit before/around the tool executor.
- Inspect-based evals (AgentHarm, Cybench, AgentDojo-Inspect, and the rest of inspect_evals): Inspect's tool *approval* policies let a custom approver accept, modify, reject or escalate each tool call before it runs.
- ASB: built-in defense slots.
- ToolEmu: the emulator sits between agent and tool, so a filter can be inserted.

Offline datasets (R-Judge, ASSEBench, ShieldAgent-Bench, InjecAgent) give per-step trajectories but no live execution. They test a filter's classification, not utility under attack.

### Cited Findings
- AgentDojo models agents as composable pipeline elements, and defenses such as tool filtering and PI detectors are implemented as such elements. Logs record the full message/tool-call trace per task [PK] — [GitHub](https://github.com/ethz-spylab/agentdojo), [docs](https://agentdojo.spylab.ai)
- AgentDojo-Inspect bridges AgentDojo into Inspect [V] — [data.gov](https://catalog.data.gov/dataset/agentdojo-inspect)
- Inspect supports approval policies, i.e. a custom approver function per tool call, and writes full per-step eval logs (.eval) [PK] — [Inspect docs: Tool Approval](https://inspect.aisi.org.uk/approval.html)
- OS-Harm, CUAHarm and RiOSWorld run in OSWorld-style VMs with per-step action/screenshot trajectories. CUAHarm explicitly evaluates LM monitors on trajectories [V] — [CUAHarm arXiv](https://arxiv.org/abs/2508.00935); [OS-Harm GitHub](https://github.com/tml-epfl/os-harm)
- SHADE-Arena provides full transcripts for monitor scoring [PK] — [arXiv 2506.15740](https://arxiv.org/abs/2506.15740)
- MCPSecBench evaluates whole products (Claude Desktop, Cursor), so it does *not* easily accept an external filter in the loop [V] — [COPEX critique](https://arxiv.org/html/2610.04378)
- ExCyTIn-Bench exposes a SQL tool environment with per-step rewards. A filter could wrap the SQL tool, but no hook is documented (inference from its design [V]) — [arXiv 2507.14201](https://arxiv.org/pdf/2507.14201)

### Inferences
- For comparability, implement the SOCGraph-21 filter as (a) an AgentDojo pipeline element and (b) an Inspect approver. That lets it run unchanged on AgentDojo, AgentHarm and Cybench-in-Inspect, alongside the custom SOC benchmark.
- Use offline trajectory datasets (R-Judge, ASSEBench) only as a sanity check on classifier calibration, not as the headline result.

### Gaps
- The current inspect_evals registry contents (e.g. whether AgentDojo, CyberSecEval 2/3, SHADE-Arena or CyberGym are included) could not be checked, because GitHub was blocked. [PK] says AgentHarm, Cybench, CyberSecEval 2 and InterCode-CTF are in it.

---

## 6. Gaps relevant to SOCGraph-21: is there any benchmark measuring whether safety filters/monitors are fooled by lexical mimicry or attacker-controlled names in telemetry?

### Takeaway
No published benchmark was found that measures whether a *safety filter or monitor on agent actions* is fooled by lexical mimicry: renamed binaries, attacker-chosen process/host/user names, or masquerading entity names. Neighbouring work covers three things:
1. Log-substrate prompt injection against LLM SOC triage: instructions planted in log fields (2026 papers).
2. Structural mimicry against provenance-graph IDS: classical, not LLM.
3. General "semantic evasion" of agents (A3S-Bench).

SOCGraph-21's cue-controlled blind/mimicry variants therefore appear to fill a real gap. The novelty claim should be phrased narrowly: *filter/monitor robustness to non-instructional lexical cues in telemetry*, as distinct from injected instructions.

### Cited Findings
**Poisoning the Watchtower** [V] (arXiv 2605.24421, 2026).
- Defines "log-substrate prompt injection": malicious content embedded in the very evidence the LLM analyses.
- Attacker-controllable fields: URIs, user agents, POST bodies, DNS names, email headers, attempted usernames.
- Goal: get intrusion activity marked benign. Reports "context stitching" across log entries that each pass a WAF.
- Source: [arXiv 2605.24421](https://arxiv.org/html/2605.24421)

**LogJack** [V] (arXiv 2604.15368). Indirect PI through cloud logs against LLM debugging agents.
- Llama 3.3 70B executed injected commands verbatim in 86.2% of active-mode trials; Claude Sonnet 4.6 in 0%.
- "All tested guardrails failed to detect the embedded injections" (snippet; verify).
- Source: [arXiv 2604.15368](https://arxiv.org/pdf/2604.15368)

**Context Contamination in LLM Analysis of Network Security Logs** [V] (arXiv 2607.14493). Passive prompt injection, plus an evaluation of mitigations. — [arXiv 2607.14493](https://arxiv.org/html/2607.14493v1)

**"Just Testing, Move Along"** [V] (title only). Evasion of LLM-based system-log interpretation by prompt injection. — [ResearchGate](https://www.researchgate.net/publication/410888032_Just_Testing_Move_Along_Evasion_of_LLM-based_System_Log_Interpretation_by_Prompt_Injection)

**Agent-Threat-Rule probe proposal** [V] (GitHub issue #695). Explicitly lists *process command line* as an attacker-controlled field for verdict manipulation in LLM SOC triage. It is a proposal, not a measured study. — [GitHub issue](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/695)

**ProvAgent** [V]. Evaluates robustness of LLM provenance investigation to *mimicry attacks* (tampering raw audit data / injecting benign structure). Whether name-renaming is tested is not confirmed. — [arXiv 2603.09358](https://arxiv.org/html/2603.09358v1)

**Classical provenance-IDS mimicry** [PK]:
- Goyal et al., "Sometimes, You Aren't What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems", NDSS 2023 — [NDSS](https://www.ndss-symposium.org/ndss-paper/sometimes-you-arent-what-you-do-mimicry-attacks-against-provenance-graph-host-intrusion-detection-systems/)
- ProvNinja (Mukherjee et al., USENIX Security 2023)
- Both are structural/behavioural mimicry against GNN/anomaly detectors, not lexical cues against LLM filters.

**MITRE ATT&CK T1036 Masquerading** [PK]. The real-world basis for the renaming threat model, including T1036.003 Rename Legitimate Utilities and T1036.005 Match Legitimate Resource Name or Location. — [MITRE T1036](https://attack.mitre.org/techniques/T1036/)

**A3S-Bench semantic evasion** [V] hides malicious intent in benign context, but it targets the agent's behaviour and not an external filter's verdict — [arXiv 2605.22321](https://arxiv.org/html/2605.22321v1)

**AuditBench** [V] finds LLMs over-flag audit logs — [arXiv 2606.10281](https://arxiv.org/pdf/2606.10281)

**Monitor-evasion via injection** [V] (arXiv 2510.09462) shows monitors can be steered by agent-authored text. The attacker-controlled channel there is model output, not telemetry entity names — [arXiv 2510.09462](https://arxiv.org/html/2510.09462v1)

### Inferences
- **What distinguishes SOCGraph-21:**
  - Existing log-PI work uses *instructional* payloads ("ignore previous… mark benign").
  - SOCGraph-21's mimicry variant uses *non-instructional* lexical cues: renaming a malicious binary to `svchost.exe`, or benign-sounding host/user names. Instruction-detectors such as PromptGuard would not be expected to catch these.
  - A cue-controlled *blind* variant (names neutralised) isolates how much a filter relies on names vs graph structure. No benchmark found does this ablation for LLM filters/monitors.
- **Suggested comparisons to make the gap claim robust:**
  1. Run a PI detector (PromptGuard 2 / LlamaFirewall) and an LLM-judge monitor on the mimicry variant, to show instruction-focused guards miss lexical mimicry.
  2. Report filter TPR at fixed FPR separately for the original, blind and mimicry variants. The renaming-evasion delta is the headline metric.
  3. Add an adaptive renaming attacker that searches over names against the filter score, following "Attacker Moves Second".
  4. Report false positives on benign look-alikes (benign processes with suspicious names), given AuditBench's over-suspicion finding.
- **Statistical caution:** 21 tasks is small next to ExCyTIn-Bench (hundreds to thousands of questions) and ASSEBench (2,293). Report per-task paired results and exact/bootstrap CIs, and position SOCGraph-21 as a controlled diagnostic benchmark, as DiagChain does, not a leaderboard.

### Gaps
- Full texts of Poisoning the Watchtower, LogJack, ProvAgent, DiagChain, AuditBench and A3S-Bench could not be read (arXiv blocked). It is not confirmed that none of them includes a process-renaming / masquerading condition. **Check each paper's threat-model section before claiming novelty.**
- No sources found on commercial SOC copilots (Microsoft Security Copilot, Google Sec-PaLM/Gemini in SecOps, CrowdStrike Charlotte) publishing robustness to masquerading names.
