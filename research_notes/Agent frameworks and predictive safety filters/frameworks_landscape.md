# Open, adaptable LLM agent frameworks and agent infrastructure (as of Oct 2026) — suitability as a base for security agents with a pluggable pre-execution safety filter

> Method note: Live fetches covered the GitHub pages for OpenHands, the OpenHands software-agent-sdk (including `security/analyzer.py`) and Hermes Agent (README and hooks doc), plus web searches. docs.openhands.dev, hermes-agent.nousresearch.com, arxiv.org and developers.openai.com failed DNS resolution from this sandbox, so material from them comes from search-result snippets or the GitHub mirrors. Claims marked **[PK]** come from the researcher's prior knowledge (training cutoff about June 2026). They were not re-fetched in October 2026 and should be checked before publication. The URL given with a [PK] claim is the canonical page where it can be checked.

## OpenHands (All-Hands-AI → now the `OpenHands` GitHub org): architecture, licence, SDK, security hook, benchmarks, deployment, maturity

### Takeaway
OpenHands now has two parts. The first is the **V1 Software Agent SDK** (MIT, Python, with a REST/WebSocket Agent Server). The second is an MIT-licensed self-hosted UI that has been rebranded **"Agent Canvas"**. The SDK has a first-class, pluggable **`SecurityAnalyzerBase`** that scores each proposed `ActionEvent` before it runs. A **confirmation policy** turns that score into a pause for human approval. This is the closest off-the-shelf match to a "predictive safety filter" seam among the open frameworks. Its main limitation is that the analyzer returns a *risk level*, not allow/deny/modify, and it does not receive the conversation history as a parameter.

### Cited Findings
**Identity / repo / licence / size**
- The main repo is now `OpenHands/OpenHands` (the old `All-Hands-AI/OpenHands` path redirects there). The README is titled **"Agent Canvas — The self-hosted developer control center for coding agents and automations"**. The sidebar shows the licence as MIT. At fetch time it had **~91.7k stars, 12.2k forks, 8,732 commits on main, 551 open issues, 544 PRs**. The fetched page showed no separate enterprise or source-available directory. — [GitHub OpenHands/OpenHands](https://github.com/OpenHands/OpenHands)
- "OpenHands Cloud (our commercial offering)" and "OpenHands Enterprise infrastructure" are mentioned without detail. — [GitHub OpenHands/OpenHands](https://github.com/OpenHands/OpenHands)
- **[PK] / possibly outdated:** Earlier (2025) versions of the repo had an `enterprise/` directory under a separate source-available licence, while the core stayed MIT. The October 2026 fetch did not show this. Whether that directory was moved, renamed or simply not rendered was **not verified**. — [GitHub OpenHands/OpenHands](https://github.com/OpenHands/OpenHands)
- **SDK repo:** `OpenHands/software-agent-sdk` describes itself as "A clean, modular SDK for building AI agents with OpenHands V1". It provides Python, TypeScript and REST APIs, is MIT-licensed, and powers the OpenHands CLI and OpenHands Cloud. At fetch time it had about 1.3k stars, 697 forks and 2,716 commits. It has four packages: `openhands-sdk`, `openhands-tools`, `openhands-workspace` and `openhands-agent-server`. — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)
- The SDK paper is arXiv **2511.03690**, "The OpenHands Software Agent SDK: A Composable and Extensible Foundation for Production Agents" (2025). — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)
- The original platform paper is arXiv 2407.16741 ("OpenHands: An Open Platform for AI Software Developers as Generalist Agents", ICLR 2025). **[PK]** — [arXiv 2407.16741](https://arxiv.org/abs/2407.16741)

**Architecture**
- The SDK and Agent Server own "agents, tools, conversations, workspaces, events, and the canonical server API". Agent Canvas is "powered by the OpenHands Agent Server". Automation and scheduling live in a separate repo. — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk); [GitHub OpenHands/OpenHands](https://github.com/OpenHands/OpenHands)
- **[PK]** The design is event-sourced. A conversation is an append-only **event stream** of `ActionEvent`s (proposed tool calls) and `ObservationEvent`s (results). An agent `step()` reads the event history and emits actions, and the conversation or controller executes them in a **workspace**. A **condenser** summarises or truncates history to manage context length. **Microagents** were renamed **skills** in V1 and are triggered by keywords or files. — [OpenHands SDK docs](https://docs.openhands.dev/sdk); [arXiv 2511.03690](https://arxiv.org/abs/2511.03690)
- Skills: `AgentContext(load_public_skills=True)` loads public skills from the `OpenHands/extensions` marketplace (for example `uv` and `deno` skills, triggered by `uv.lock` or `deno.json`). These follow the AgentSkills format. — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)
- **Workspaces/sandbox:** The agent can use the local machine, or ephemeral **Docker or Kubernetes** workspaces through the Agent Server. — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)
- Canvas runtime modes: (a) no sandbox ("the agent will have full access to your filesystem!"); (b) a single Docker sandbox with `PROJECTS_PATH` mounted; (c) `OH_CONVERSATION_RUNTIME=docker`, which gives each conversation its own container and Agent Server. The README notes this "isolates conversation execution; it does not move the entire Canvas or automation service into a sandbox". Listeners bind to 127.0.0.1 by default. — [GitHub OpenHands/OpenHands](https://github.com/OpenHands/OpenHands)
- Deployment: `npm install -g @openhands/agent-canvas`, Docker (`ghcr.io/openhands/agent-canvas:1.33.0` pinned in the quickstart), from source, self-hosted on a VM or Mac Mini, and OpenHands Cloud / Enterprise. — [GitHub OpenHands/OpenHands](https://github.com/OpenHands/OpenHands)
- **Multi-LLM:** The quickstart builds `LLM(model="gpt-5.5", api_key=...)`. **[PK]** The SDK routes calls through **LiteLLM**, so it supports essentially any provider (Anthropic, OpenAI, Gemini, local vLLM or Ollama). — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk); [OpenHands LLM docs](https://docs.openhands.dev/sdk)
- **MCP:** "MCP" appears in the SDK's guide list. **[PK]** OpenHands has supported MCP tools (stdio, SSE and streamable HTTP servers configured per agent) since 2025. — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)

**Security analyzer hook (key for this project)**
- `SecurityAnalyzerBase` (`openhands/sdk/security/analyzer.py`) has one abstract method, `def security_risk(self, action: ActionEvent) -> SecurityRisk`. Helper methods are `analyze_action(action) -> SecurityAnalysis` (risk plus an optional `details` dict), `analyze_actions(pending_actions: list[ActionEvent]) -> list[tuple[ActionEvent, SecurityAnalysis]]`, `analyze_pending_actions(...)`, `analyze_event(event)`, and `should_require_confirmation(risk, confirmation_mode=False) -> bool`. — [analyzer.py (raw)](https://raw.githubusercontent.com/OpenHands/software-agent-sdk/main/openhands-sdk/openhands/sdk/security/analyzer.py)
- Default policy: **HIGH** always needs confirmation. **UNKNOWN** needs confirmation when confirmation mode is off. Confirmation mode on means everything needs confirmation. LOW and MEDIUM do not. **If the analyzer raises an error, the action defaults to HIGH** (fails closed) and the error is stored in `details`. — [analyzer.py (raw)](https://raw.githubusercontent.com/OpenHands/software-agent-sdk/main/openhands-sdk/openhands/sdk/security/analyzer.py)
- The methods take a single `ActionEvent` or a list of pending actions. **Conversation history is not a parameter**, so a context-aware filter must capture the conversation or state separately. — [analyzer.py (raw)](https://raw.githubusercontent.com/OpenHands/software-agent-sdk/main/openhands-sdk/openhands/sdk/security/analyzer.py)
- The security module contains `analyzer.py`, `confirmation_policy.py`, `ensemble.py`, `llm_analyzer.py`, `risk.py`, `shell_parser.py`, `_shell_ast.py`, `toolshield_helpers.py`, `toolshield_llm_analyzer.py`, and the subdirectories `defense_in_depth/` and `grayswan/`. — [GitHub security dir](https://github.com/OpenHands/software-agent-sdk/tree/main/openhands-sdk/openhands/sdk/security)
- **LLMSecurityAnalyzer:** This adds a required `security_risk` field to the schema of each non-read-only tool, so the acting LLM rates its own action. It makes no extra LLM call, and the risk defaults to UNKNOWN if the field is missing. The levels are LOW (read-only), MEDIUM (modifies user data), HIGH (dangerous) and UNKNOWN. — [OpenHands docs: security arch](https://docs.openhands.dev/sdk/arch/security); [OpenHands security guide](https://docs.openhands.dev/sdk/guides/security) (via search snippet)
- Confirmation policies are objects: `AlwaysConfirm`, `NeverConfirm` and `ConfirmRisky`. Other analyzers include a **GraySwan** analyzer (sends history and pending actions to an external API), pattern and policy-rail analyzers, and an **ensemble** analyzer that combines verdicts worst-case-wins and fails closed to HIGH if a child analyzer breaks. The V0 **Invariant** analyzer is gone. — [arXiv 2609.00006 "Harness Engineering… Source-Code Study of Eleven Systems"](https://arxiv.org/pdf/2609.00006) (third-party study; seen only as a search snippet); [Gray Swan Cygnal OpenHands integration](https://docs.grayswan.ai/cygnal/integrations/openhands-integration)
- The Agent Server API has a "set conversation security analyzer" endpoint, so the analyzer can be set per conversation at runtime. — [OpenHands agent-server API ref](https://docs.openhands.dev/sdk/guides/agent-server/api-reference/conversations/set-conversation-security-analyzer.md) (search result)

**Benchmarks / maturity**
- The SDK README badge reads "**SWEBench-77.6**" and links to a spreadsheet, with no methodology stated (model, Verified vs. full, and date are all unknown). — [GitHub software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)
- **[PK]** OpenHands has a separate evaluation harness and an "OpenHands Index" leaderboard. In 2025 it reported Claude-based CodeAct runs at roughly 65–72% on SWE-bench Verified. — [OpenHands blog](https://www.all-hands.dev/blog)

### Inferences
- For a security platform, the SDK (not the Canvas UI) is the useful layer. A custom `SecurityAnalyzerBase` subclass can host a predictive filter: return `SecurityAnalysis(risk=HIGH, details={...})` and pair it with `ConfirmRisky`, which pauses the action for approval. True **deny** or **modify** is not built in. A pause plus rejection approximates deny. Modify would need a custom tool wrapper or a change to the agent step.
- The event stream is effectively a ready-made per-call trace (`ActionEvent` → `ObservationEvent`) that can be serialised as training or evaluation data for filters.
- The project is coding-centric. SOC triage or provenance-graph investigation would need custom tools (MCP servers or SDK tools), and most of the coding toolset would go unused.

### Gaps
- No exact SDK release version or date, and the enterprise-licence status of the October 2026 tree is unverified.
- Methodology behind the 77.6 SWE-bench badge (model, split) is unknown.
- Whether OpenTelemetry export is native in the SDK (Laminar integration existed in V0 per [PK]) was not confirmed.
- I could not read the docs site directly (DNS failure).

## Nous Research Hermes Agent: what it is, architecture, tool calling, memory/skills, sandboxing, licence, MCP, release, maturity

### Takeaway
"Hermes Agent" is a **separate open-source agent runtime/harness from Nous Research**. It is MIT-licensed, written in Python with Node/TS UI parts, and was first released around **February 2026**. It is distinct from the **Hermes LLM family** (Hermes 2/3/4 models). It is a long-running, personal-assistant-style agent with persistent memory, self-authored skills, a multi-messenger gateway, cron jobs, MCP, and six or more terminal backends. Crucially, its plugin **`pre_tool_call` hook can return block / approve(escalate to human) / modify**, and it fails closed. That makes it the cleanest allow/deny/modify/ask seam of any framework checked, though it is aimed at personal automation rather than security operations.

### Cited Findings
- Repo `NousResearch/hermes-agent`: "The self-improving AI agent built by Nous Research". The licence is **MIT**. At fetch time it had **~256.6k stars, 56.1k forks, 993 watchers and ~58k commits on main**. The fetched page showed no GitHub Releases. The top-level directories are `agent`, `tools`, `gateway`, `cron`, `plugins`, `skills` and `tui_gateway`. The installer references Python 3.14 and Node.js. — [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent)
- **Caution on the star count:** Third-party sources report 8.8k (March 2026), ~57k (April) and 140k+ (June), and a September newsletter reports ~230k. The growth curve is extreme, and the count should be treated as indicative only. — [search aggregate: getcoai](https://getcoai.com/article/hermes-ai/); [allclaw.org](https://allclaw.org/blog/what-is-hermes-agent)
- **Release:** One source gives **25 February 2026** for the MIT release. Others give v0.1.0 in February 2026, v0.3.0 on 17 March 2026, v0.9.0 on 13 April 2026 and v0.17.0 on 19 June 2026 (background subagents, iMessage). These are secondary or blog sources and are **unverified**. A "Hermes 2.0 / Mixture of Agents" label in one source does not fit the v0.x numbering. — [agentic-ai.readthedocs](https://agentic-ai.readthedocs.io/en/latest/AgentPlatforms/hermes-agent/); [noqta.tn](https://noqta.tn/en/news/nous-hermes-mixture-of-agents-2-virtual-models-2026); [petronellatech](https://petronellatech.com/blog/hermes-agent-ai-guide-2026/)
- **Distinguishing the model family:** The Hermes models (Hermes 3 in 2024, Hermes 4 in 2025) are open-weight fine-tunes from Nous Research. They use a ChatML format with `<tool_call>{json}</tool_call>` XML-tagged function calls. **[PK]** The agent is model-agnostic and does not require the Hermes models. — [Nous Research](https://nousresearch.com/); [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent)
- **Providers:** Nous Portal (300+ models), OpenRouter, OpenAI, custom endpoints and others, switched with `hermes model`. Secondary sources also list Xiaomi MiMo, z.ai, Kimi and MiniMax. — [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent); [i-scoop](https://www.i-scoop.eu/hermes-agent-from-nous-research/)
- **Memory/skills:** Curated memory with periodic nudges to save knowledge, and **autonomous skill creation after complex tasks** that improve with use. Session search uses SQLite FTS5 plus LLM summarisation. User modelling uses Honcho. Skills are "compatible with the agentskills.io open standard". Agents can also write Python scripts that call tools over RPC, keeping multi-step pipelines out of the context window. — [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent)
- **Sandboxing/terminal backends:** local, Docker, SSH, Modal, Daytona and Vercel Sandbox, plus plugin backends such as Singularity/Apptainer. Modal and Daytona offer "serverless persistence" where the sandbox sleeps when idle. Security docs cover command approval, DM pairing and container isolation. — [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent). The official site, quoted in a snippet, lists five backends (local, Docker, SSH, Singularity, Modal) "with container hardening and namespace isolation", which is likely an older list. — [hermes-agent.nousresearch.com](https://hermes-agent.nousresearch.com/)
- **MCP:** "Connect any MCP server for extended capabilities", plus an MCP registry and optional MCP servers. — [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent)
- **Gateway:** Telegram, Discord, Slack, WhatsApp, Signal, Email (and Home Assistant) through one gateway process. Cron and scheduled automations are included. — [GitHub hermes-agent](https://github.com/NousResearch/hermes-agent)
- **Hook systems (four):** gateway event hooks (`~/.hermes/hooks/` with HOOK.yaml and handler.py), **plugin hooks** (`ctx.register_hook()`, running in CLI and gateway), **shell hooks** (a `hooks:` block in config.yaml) and **outbound webhooks** (signed lifecycle events to HTTP endpoints). — [hooks.md](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md)
- **`pre_tool_call`** receives `tool_name`, `args`, `task_id`, `session_id`, `tool_call_id` and `turn_id`. It can return:
  - `{"action":"block","message":...}`: the message goes back to the model as the error.
  - `{"action":"approve","message":...,"rule_key":...}`: escalates to the human-approval gate. Denial, timeout or gate error fails closed.
  - `{"action":"modify","args":{...}}`: shallow-merged over the original args.

  Shell hooks may also use the Claude-Code-style `{"decision":"modify","tool_input":{...}}`. Precedence is **block > approve > none**. Hooks **fail closed**: a timeout, an exception or a hook still running from a previous call blocks the tool, with a 60 s suppression window. — [hooks.md](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md)
- Other hooks: `post_tool_call` (with `result` and `duration_ms`), `transform_tool_result`, `transform_terminal_output`, `pre_llm_call` (context injection), `post_llm_call`, `transform_llm_output`, `pre_api_request`/`post_api_request`, streaming hooks, and approval observers `pre_approval_request`/`post_approval_response`. — [hooks.md](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md)
- Separately, observer hooks are documented as a "read-only telemetry contract" for reconstructing agent execution. — [Hermes observability README (mirror)](https://download.hermesedi.duckdns.org/.hermes/hermes-agent/docs/observability/README.md) (unofficial mirror)
- The built-in dangerous-command system lives in `tools/approval.py` with modes manual / smart / off. Issue #16475 requests a custom approval hook. A community plugin adds custom regex dangerous patterns. — [issue #16475](https://github.com/NousResearch/hermes-agent/issues/16475); [community plugin](https://awesome.ecosyste.ms/projects/github.com%2Fscross01%2Fhermes-custom-dangerous-patterns-plugin)
- Adoption claims: the project reportedly reached #1 on OpenRouter by daily token usage in May 2026, and academic papers use it as a harness alongside Claude Code. These are **secondary and unverified**. — [i-scoop](https://www.i-scoop.eu/hermes-agent-from-nous-research/); e.g. [arXiv 2606.07462](https://arxiv.org/pdf/2606.07462)

### Inferences
- In hook semantics, Hermes's `pre_tool_call` is almost exactly the target interface (allow/deny/modify/ask-human, fail-closed). It is also Claude-Code-compatible, so a filter written for Claude Code shell hooks could be ported.
- Its design centre is a self-improving *personal* agent with messaging gateways and autonomous skill writing. For a security product, self-authored skills and persistent memory widen the attack surface (memory and skill poisoning). They would need to be locked down or audited.
- Very fast growth and ~58k commits in roughly 8 months suggest high churn. API stability for embedding is a real risk, so pin versions.

### Gaps
- Exact current version and an authoritative release timeline (GitHub Releases empty; official docs unreachable).
- Whether `pre_tool_call` receives conversation context beyond IDs. A filter may have to look up the session by ID.
- Native OpenTelemetry support was not confirmed.
- Container hardening specifics (seccomp, user namespaces, network policy) were not verified.

## Comparable frameworks: licence, language, pre-execution hook, sandboxing, MCP, observability, maturity

### Takeaway
The cleanest **decision-returning** pre-execution seams are, in order: **Claude Agent SDK** (`PreToolUse` hooks and `canUseTool` returning allow/deny/ask plus `updatedInput`), **Hermes Agent** (`pre_tool_call` block/approve/modify), **OpenAI Agents SDK** (tool input guardrails, `needs_approval`, tracing), **Google ADK** (`before_tool_callback` can short-circuit with a result), **LangGraph / LangChain 1.0** (`interrupt()` and human-in-the-loop middleware with approve/edit/reject) and **Microsoft Agent Framework** (function middleware). **OpenHands** gives a risk-scoring analyzer rather than a verdict. **SWE-agent/mini-SWE-agent** and **smolagents** are minimal and hackable but have no formal hook. You would subclass the environment or executor instead.

### Cited Findings
**Microsoft AutoGen / Agent Framework**
- AutoGen has been in **maintenance mode** since October 2025: "will not receive new features… community managed", with security and bug fixes only. **Microsoft Agent Framework (MAF) 1.0 GA** shipped in early April 2026 (sources disagree between 2 and 3 April) for Python and .NET as AutoGen's successor. Middleware "intercepts agent actions for guardrails, logging, policy". — [techstrong.ai](https://techstrong.ai/features/microsoft-ships-agent-framework-1-0-a-production-ready-foundation-for-multi-agent-ai/); [atlan](https://atlan.com/know/ai-agent/what-is-autogen/)
- **[PK]** MAF is MIT-licensed and combines Semantic Kernel and AutoGen. It has agent-, function- and chat-level middleware and function-approval (`approval_mode="always_require"`) for human-in-the-loop. It emits OpenTelemetry natively and supports MCP. **AG2** is the community fork of AutoGen 0.2 (Apache-2.0). — [github.com/microsoft/agent-framework](https://github.com/microsoft/agent-framework); [github.com/ag2ai/ag2](https://github.com/ag2ai/ag2)

**OpenAI Agents SDK**
- It has guardrails at input, output and **tool** boundaries, plus approvals, sandbox-session resume and **sandbox agents** (container environments with files, commands, ports, snapshots), added in April 2026. — [OpenAI cookbook: migrate from Claude Agent SDK](https://developers.openai.com/cookbook/examples/agents_sdk/migrate-from-claude-agent-sdk/readme) (search snippet); [uibakery guide](https://uibakery.io/blog/openai-agents-sdk)
- The separate MIT **OpenAI Guardrails** library provides a `GuardrailAgent` drop-in with tool-level prompt-injection checks on every tool call and output. — [openai-guardrails-python Agents SDK integration](https://openai.github.io/openai-guardrails-python/agents_sdk_integration/)
- **[PK]** The SDK is MIT-licensed (Python and JS). Function tools accept `tool_input_guardrails`/`tool_output_guardrails`, which can allow, reject with a message to the model, or raise. Input and output guardrails use tripwires. Built-in **tracing** has spans per LLM call, tool call, handoff and guardrail, with exporters to third-party and OTel-compatible backends. It works with non-OpenAI models through LiteLLM or any Chat Completions endpoint, and supports MCP (stdio, SSE, streamable HTTP, hosted MCP). — [openai.github.io/openai-agents-python/guardrails](https://openai.github.io/openai-agents-python/guardrails/); [tracing](https://openai.github.io/openai-agents-python/tracing/)

**Claude Agent SDK (Anthropic)** — all **[PK]**
- Python and TypeScript, under Anthropic commercial terms rather than an OSI licence (verify). It is the harness behind Claude Code.
- **Hooks:** `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `PreCompact`, `SessionStart/End` and `Notification`. A `PreToolUse` hook receives `tool_name`, `tool_input`, `session_id` and `transcript_path`, and returns `permissionDecision: allow | deny | ask` with a reason. It can also return `updatedInput` to modify the call.
- A `canUseTool` callback offers programmatic permission. Permission modes are `default`, `acceptEdits`, `plan` and `bypassPermissions`, and newer releases add `dontAsk`/`auto` (these appear in this environment's own tool schemas).
- Other features: allow and deny tool rules, MCP (in-process SDK servers and external servers), subagents, and OpenTelemetry metrics and logs export from Claude Code. Sandboxing is OS-level (bubblewrap on Linux, Seatbelt on macOS) for Bash, plus optional containers.
- Sources: [docs.claude.com Agent SDK hooks](https://docs.claude.com/en/docs/agent-sdk/hooks); [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks); [permissions](https://docs.claude.com/en/docs/agent-sdk/permissions)
- The transcript path gives the hook full context. This matters for predictive filters. **[PK]**

**Google ADK** — **[PK]**
- Apache-2.0, in Python, Java, Go and TS. It has `before_tool_callback(tool, args, tool_context)`: return a dict to **skip the tool and use that dict as the result**, or mutate `args`. `before_model_callback` and `after_*` variants also exist, plus plugins (global callbacks) and a tool-confirmation (HITL) flow. It supports MCP via `MCPToolset`, has OpenTelemetry tracing, and runs code through Vertex code executors or containers. — [google.github.io/adk-docs/callbacks](https://google.github.io/adk-docs/callbacks/); [ADK safety](https://google.github.io/adk-docs/safety/)

**LangGraph / LangChain** — **[PK]**
- MIT, Python and JS. `interrupt()` and `Command(resume=...)` give durable human-in-the-loop that pauses the graph with checkpointing. LangChain 1.0 (October 2025) added agent **middleware** (`before_model`, `wrap_tool_call`, `HumanInTheLoopMiddleware` with approve/edit/reject per tool). MCP is supported via `langchain-mcp-adapters`. Tracing goes to LangSmith (proprietary SaaS) or OTel. The project is mature and widely deployed. — [LangGraph HITL docs](https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/); [LangChain middleware](https://docs.langchain.com/oss/python/langchain/middleware)

**CrewAI** — **[PK]**
- MIT, Python. It has task guardrails (functions validating task output), `@before_tool_call`/`@after_tool_call` hooks (added in 2025, verify) and step callbacks. It supports MCP via `crewai-tools` adapters. Telemetry is OTel-based (anonymous telemetry on by default). Code execution can run in Docker. It is aimed at role-based multi-agent "crews". — [docs.crewai.com](https://docs.crewai.com/)

**smolagents (Hugging Face)** — **[PK]**
- Apache-2.0, Python, minimal (~1k core LoC). `CodeAgent` writes Python actions. Execution goes through a restricted local Python interpreter (import allowlist) or remote executors (**E2B, Docker, Modal, WebAssembly/Pyodide**). There is no formal pre-execution hook, but `step_callbacks` and a custom executor or `final_answer_checks` can serve as seams. It supports MCP via `ToolCollection.from_mcp` and OTel via OpenInference instrumentation. — [huggingface.co/docs/smolagents](https://huggingface.co/docs/smolagents/index); [secure code execution](https://huggingface.co/docs/smolagents/tutorials/secure_code_execution)

**SWE-agent / mini-SWE-agent (Princeton/Stanford)** — **[PK]**
- MIT, Python. SWE-agent introduced the Agent-Computer Interface (NeurIPS 2024, [arXiv 2405.15793](https://arxiv.org/abs/2405.15793)). It runs commands in Docker through SWE-ReX (which also supports Modal and AWS backends). **mini-SWE-agent** is ~100 lines, bash-only, with no tool-calling API. Every action is a `subprocess.run`, and it reports >70% on SWE-bench Verified with frontier models. Interception means subclassing `Environment.execute` or the agent's `step`. That is trivial, but there is no hook API. Trajectories are saved as JSON (good trace data). It was also the base of EnIGMA, a CTF variant of SWE-agent. — [github.com/SWE-agent/mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent); [github.com/SWE-agent/SWE-agent](https://github.com/SWE-agent/SWE-agent)

**Block Goose** — **[PK]**
- Apache-2.0, Rust core with a desktop app and CLI. It is MCP-native: every extension is an MCP server. It has tool-permission modes (autonomous, approve, smart-approve, chat-only) and per-tool permissions. It was contributed to the Linux Foundation's **Agentic AI Foundation** (December 2025, alongside MCP and AGENTS.md; verify). — [github.com/block/goose](https://github.com/block/goose)

**Letta (ex-MemGPT)** — **[PK]**
- Apache-2.0, Python server with a REST API. It is stateful and memory-centric (core, archival and recall memory). It has tool rules that constrain call ordering and tool approval (HITL), plus MCP. Sandboxed tool execution runs on E2B or local. — [github.com/letta-ai/letta](https://github.com/letta-ai/letta)

**PydanticAI** — **[PK]**
- MIT, Python, from the Pydantic team. Typed tools and outputs. It has deferred tools / `requires_approval` for human-in-the-loop, `prepare` functions per tool and toolset wrappers (e.g. `ApprovalRequiredToolset`, `WrapperToolset`) that can intercept calls. It supports MCP as both client and server. Observability is OTel-native via Logfire (instrumented spans per model and tool call). This makes it closest in style to an existing FastAPI codebase. — [ai.pydantic.dev](https://ai.pydantic.dev/); [deferred tools](https://ai.pydantic.dev/deferred-tools/)

**Cline / Roo Code** — **[PK]**
- Apache-2.0, TypeScript VS Code extensions. They use per-action human approval (auto-approve settings), and Cline added hooks (PreToolUse-style, 2025). Both support MCP. They are IDE-bound and a poor base for a server-side security platform. — [github.com/cline/cline](https://github.com/cline/cline); [github.com/RooCodeInc/Roo-Code](https://github.com/RooCodeInc/Roo-Code)

**OpenAI Codex CLI** — **[PK]**
- Apache-2.0, Rust. Approval policies are `untrusted / on-request / on-failure / never`. Sandbox modes are `read-only / workspace-write / danger-full-access`, enforced by OS sandboxing (Seatbelt on macOS, Landlock + seccomp on Linux). It supports MCP as client and server, with OTel export configurable. It has no general-purpose programmable pre-tool hook comparable to Claude's (verify; hooks were under discussion). — [github.com/openai/codex](https://github.com/openai/codex)

**Cross-system study**
- A September 2026 source-code study of eleven coding-agent harnesses ("Harness Engineering: Anatomy, Architecture, and Evolution of Coding Agents") covers OpenHands' security subsystem. It is a useful primary comparator for interception points but was seen only as a snippet. — [arXiv 2609.00006](https://arxiv.org/pdf/2609.00006)

### Inferences
- Hook semantics fall into three tiers. Tier 1 (verdict + modify + ask): Claude Agent SDK, Hermes, LangChain HITL middleware, Google ADK, PydanticAI wrapper toolsets. Tier 2 (verdict or approval only): OpenAI Agents SDK tool guardrails and `needs_approval`, MAF function approval, Goose and Codex approval modes, OpenHands risk + confirmation. Tier 3 (subclass the loop yourself): mini-SWE-agent, smolagents.
- Vendor SDKs (OpenAI, Claude, ADK) are model-agnostic to varying degrees. The Claude Agent SDK is effectively Claude-only, which makes it unsuitable as the sole base when multi-LLM is a requirement.

### Gaps
- Most entries in this section are [PK] and were not re-fetched in October 2026, owing to the tool-call budget and DNS failures on vendor docs domains. Verify exact hook signatures, licences (especially the Claude Agent SDK licence terms) and the CrewAI and Cline hook names before citing them.
- No up-to-date star counts for the comparison frameworks.

## Sandboxing / execution backends: isolation strength and cost

### Takeaway
Plain Docker (shared kernel) is the weakest of these options. **gVisor** (user-space kernel intercepting syscalls) is stronger. **Firecracker microVMs** (separate kernel, KVM) give the strongest isolation commonly used for agents. Hosted options map onto these: **E2B = Firecracker**, **Modal = gVisor**, **Daytona = containers by default with optional VMs** (sources conflict). Cost and latency figures are vendor-reported and inconsistent.

### Cited Findings
- E2B sandboxes are Firecracker microVMs, "the same technology AWS Lambda uses", each with its own kernel. — [morphllm sandbox guide](https://www.morphllm.com/ai-agent-sandbox); [fly.io comparison](https://fly.io/learn/sprites-vs-e2b-vs-modal-vs-daytona/)
- Modal uses gVisor: containers share the host kernel through gVisor's application kernel, which intercepts syscalls. — [northflank e2b vs modal](https://northflank.com/blog/e2b-vs-modal)
- Daytona: one guide says gVisor, while Fly.io says "Linux container; VM sandboxes optional". **Conflict.** — [spheron](https://www.spheron.network/blog/ai-agent-code-execution-sandbox-e2b-daytona-firecracker/); [fly.io](https://fly.io/learn/sprites-vs-e2b-vs-modal-vs-daytona/)
- Start latency claims: E2B "sub-200ms" (one comparison) vs. about 1 s resume (Fly.io), Daytona under 90 ms, Modal unpublished. Fly.io says **no provider publishes p50/p99**. Three of the four meter sandboxes while they are alive, so idle sandboxes cost money. E2B Pro has 24 h maximum sessions. — [fly.io](https://fly.io/learn/sprites-vs-e2b-vs-modal-vs-daytona/); [morphllm e2b vs modal](https://www.morphllm.com/comparisons/e2b-vs-modal)
- GPUs: gVisor blocks direct PCIe passthrough, while Firecracker supports VFIO passthrough. Modal and Daytona are the GPU-capable choices. — [spheron](https://www.spheron.network/blog/ai-agent-code-execution-sandbox-e2b-daytona-firecracker/); [fly.io](https://fly.io/learn/sprites-vs-e2b-vs-modal-vs-daytona/)
- Framework support: OpenHands (Docker, Kubernetes); Hermes (local, Docker, SSH, Modal, Daytona, Vercel Sandbox, Singularity); smolagents (E2B, Docker, Modal, Wasm) **[PK]**; SWE-ReX (Docker, Modal, AWS) **[PK]**. — [software-agent-sdk](https://github.com/OpenHands/software-agent-sdk); [hermes-agent](https://github.com/NousResearch/hermes-agent)
- Kubernetes (with gVisor or Kata via RuntimeClass) is the usual self-hosted way to schedule per-session sandboxes at scale. **[PK]** — [gvisor.dev](https://gvisor.dev/docs/); [kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)

### Inferences
- Red-teaming and MCP-scanning agents run untrusted or adversarial code and contact hostile servers. They warrant gVisor at minimum, and Firecracker/E2B where tenants are mixed, with default-deny egress. SOC triage over read-only telemetry can use hardened Docker plus a read-only filesystem and a network allowlist.
- A sandbox and a predictive filter complement each other. The filter reduces harmful attempts, and the sandbox bounds the impact of whatever gets through.

### Gaps
- No independent benchmarked cost-per-hour or isolation comparison was found. All figures are vendor or blog figures.

## Cleanest seam for a predictive safety filter and per-call trace logging; build vs adopt for robustidps.ai

### Takeaway
For an **allow/deny/modify/ask-human** filter with rich context, the best-documented seams are the **Claude Agent SDK `PreToolUse`** hook (transcript path supplied) and **Hermes `pre_tool_call`** (block/approve/modify, fail-closed, Claude-hook-compatible). **OpenHands `SecurityAnalyzerBase`** is the best *security-native* seam (risk enum, ensemble, fail-closed, external analyzers like GraySwan already exist), but it scores risk rather than returning verdicts. For a small FastAPI + React team that already has its own Python agent and safeguards, the lowest-risk path is to **keep the in-house agent and expose the filter as a framework-agnostic policy-decision service**. Write thin adapters (OpenHands analyzer, Hermes and Claude hook, LangChain middleware) so the filter can be tested on several harnesses, rather than re-platforming.

### Cited Findings
- OpenHands: analyzer interface over `ActionEvent`s, with risk-to-confirmation policy, worst-case ensemble and error → HIGH. — [analyzer.py](https://raw.githubusercontent.com/OpenHands/software-agent-sdk/main/openhands-sdk/openhands/sdk/security/analyzer.py); [arXiv 2609.00006](https://arxiv.org/pdf/2609.00006)
- Hermes: block/approve/modify directives, precedence block > approve, fail-closed on timeout or exception. Separate read-only observer hooks for telemetry, `post_tool_call` with `duration_ms`, and signed outbound webhooks for lifecycle events (usable as a trace sink). — [hooks.md](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md); [observer hooks mirror](https://download.hermesedi.duckdns.org/.hermes/hermes-agent/docs/observability/README.md)
- Claude Agent SDK `PreToolUse` → `permissionDecision` allow/deny/ask plus `updatedInput`. **[PK]** — [Claude Agent SDK hooks](https://docs.claude.com/en/docs/agent-sdk/hooks)
- OpenAI Agents SDK tool guardrails and built-in tracing spans per tool call and guardrail. **[PK]** — [guardrails](https://openai.github.io/openai-agents-python/guardrails/); [tracing](https://openai.github.io/openai-agents-python/tracing/)
- PydanticAI / Logfire and MAF give native OpenTelemetry per model and tool call. **[PK]** — [ai.pydantic.dev](https://ai.pydantic.dev/); [microsoft/agent-framework](https://github.com/microsoft/agent-framework)
- mini-SWE-agent and SWE-agent save full trajectories as JSON. OpenHands persists event streams. Both are suitable as labelled training corpora for filters. **[PK]** — [mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent)

### Inferences
- **Recommended filter contract** (framework-neutral, mirroring the Hermes and Claude semantics):
  - Input: `{session_id, turn_id, tool_name, args, recent_context|transcript_ref, actor_role, environment}`.
  - Output: `{decision: allow|deny|modify|ask, modified_args?, risk: LOW|MED|HIGH|UNKNOWN, score, reason, filter_version}`.
  - Fail closed on timeout.
  - Map onto OpenHands by returning `SecurityAnalysis(risk, details)` with `ConfirmRisky`. Map onto Hermes and Claude as hook JSON. Map onto LangChain as `wrap_tool_call` middleware.
- **Trace schema for training/eval:** log one record per proposed call. Include pre-state context hash, proposed action, filter verdict and latency, human override (if any), executed result or observation, post-hoc label (harmful/benign, task success). Emit these as OTel spans following GenAI semantic conventions, so the same data feeds dashboards and offline filter training. OpenHands events and Hermes observer and webhook hooks can be adapted to this.
- **Build vs adopt for robustidps.ai:**
  - *Keep/build:* The existing agent already has response cache, schema validation, grounding check and call budgets. Its safety layer is the research contribution. Adopting a large harness (OpenHands is ~90k-star, coding-centric, Docker-heavy; Hermes is fast-churning and personal-assistant oriented) would bring in surface area unrelated to SOC triage or provenance graphs, and dependency churn.
  - *Adopt selectively:*
    - (a) Use the **OpenHands SDK** as a second harness for comparative evaluation. Its analyzer seam makes it easy to plug the filter in and compare against its built-in LLM, GraySwan and pattern analyzers.
    - (b) Use **mini-SWE-agent** as a minimal baseline harness for ablations, since it is easy to wrap.
    - (c) Use **Hermes or Claude-style hooks** to show the filter generalises across hook APIs.
    - (d) Borrow **PydanticAI/LangChain** only if a typed tool layer is needed. PydanticAI fits FastAPI/Pydantic stacks most naturally.
  - *Sandbox:* Run red-team and MCP-scanning tools in gVisor or E2B-class sandboxes. Docker is acceptable for read-only SOC triage.
- **Security-specific cautions:** self-improving skills and persistent memory (Hermes), self-rated risk (OpenHands `LLMSecurityAnalyzer` relies on the acting model, which a prompt-injected model can understate) and auto-approve modes are all bypass vectors. An independent predictive filter outside the acting LLM addresses exactly these.

### Gaps
- No published head-to-head evaluation of the pre-execution hooks across frameworks (latency, coverage, bypass rate) was found.
- Hermes and OpenHands native OTel support were not confirmed.
- The robustidps.ai agent internals were not inspected for this note. The build-vs-adopt view relies on the brief's description.
