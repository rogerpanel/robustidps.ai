# Agent Guard: a fail-closed safety filter for agent tool calls

Every tool call an agent proposes is checked here before it runs. The answer is
`allow`, `modify` (run with `modified_args`), `ask` (a person must approve) or
`deny`. Page: **Agent Security (Defend) > Safety Filter** (`/agent-guard`), with
tabs Test, Approvals, Tool Registry, Evaluate and Evidence.

## What it checks

| Layer | Check |
|---|---|
| Canonicalise | NFKC; hidden, bidirectional and tag characters removed and reported (hidden text in the tool name is a deny, in arguments an ask); rationale fields such as `reasoning` are ignored by rules |
| Tier | Tool name (glob) to an action tier with a verdict, e.g. read = allow, reversible containment = ask, irreversible = deny; unknown tools get the pack's default |
| Scope | Target arguments (hosts, IPs, URLs, CIDRs) must fall inside the agreed scope |
| Argument rules | Regex rules on argument values (mass targets, shell chaining, credential paths, metadata endpoints) |
| Clamps and redaction | Numeric caps (e.g. result limits) and removal of secret-bearing arguments become `modify` |
| Session | Budget of calls; a call identical to one already denied stays denied; after N denials every allowed call needs approval until a person resets the session |

Fail closed: filter errors, timeouts (`AGENT_GUARD_TIMEOUT_S`, default 2 s),
oversized arguments, a concurrent check for the same session, malformed hook
payloads and missing, pending, expired, used or mismatched approvals are all
denies. A new policy version re-judges earlier denials.

Policies classify actions and targets, never attacker-chosen names in
telemetry, so renaming an artefact cannot change a verdict (the Evaluate
suites test this with name-only variants).

## Shared infrastructure (used by other Agent Security modules)

Everything is scoped to a **tenant**: the e-mail behind the identity, so an
agent on a user's `rids_live_` API key and the same user signed in on the
website share sessions, approvals, the registry and the ledger.

- **Approval queue** (`approvals.py`). An `ask` returns `approval_id`. A
  signed-in person (never an API key) approves or denies with a note; the
  preview shows the exact cleaned arguments, targets, tier, reversibility and
  hidden characters. The agent repeats the same call with the `approval_id`
  and gets `allow` once. The approval is bound to the session and the
  canonical call; a denial makes the call sticky-denied; unanswered requests
  expire (`AGENT_GUARD_APPROVAL_TTL_MIN`, default 15).
- **Tool Registry** (`registry.py`). Register an MCP `tools/list`, tool array,
  OpenAI function tools or agent spec (also from the MCP/Agent Scanner page).
  Each tool gets a fingerprint over its cleaned name, description and schema;
  the text is run through the scanner; versions are diffed (added, removed,
  changed). A person pins a version (not possible while any tool has hidden
  characters). Coverage shows how a policy classifies each tool and suggests
  tiers from names and descriptions; the suggestions open as a policy to edit.
- **Evidence ledger** (`evidence.py`). Append-only, hash-chained records of
  non-allow decisions, approvals, registrations, pins, drift, session resets
  and evaluations. `/evidence/verify` recomputes the chain; the head hash and
  counts appear in the Agent Studio **Assurance Dossier** (runtime safety
  section) for the signed-in user.
- **Evaluation** (`evaluation.py`, `suites/*.json`). Labelled cases (exact
  verdicts; groups that differ only in names or stated reasons must agree).
  Reports exact accuracy, stop recall, false-stop rate, invariance and
  latency, with a `result_digest` over suite, policy, filter version and
  verdicts. Re-runs with the same inputs are compared automatically.
  `/evaluate/compare` puts the policy next to single-layer ablations
  (without scope, argument rules, clamps/redaction; tiers only) and two
  trivial baselines (allow everything, ask a person for everything), each
  with bootstrap 95% intervals over the cases (fixed seed, so the table and
  its `comparison_digest` are reproducible). The built-in suites are
  regression tests for the built-in packs, not an independent benchmark.
- **Runtime Monitor**: every decision is also an event there.
- **SOC Investigator**: optional "Safety Filter" setting; every tool call of
  the run is checked in-process and blocked or modified calls appear in the
  trace and in the ledger.

## API (`/api/agent-guard`)

| Method | Path | |
|---|---|---|
| POST | `/check` | `{session_id, tool_name, args, policy_id?, policy?, approval_id?, agent_id?, framework?}` |
| POST | `/hooks/claude?policy_id=` | Claude-style PreToolUse payload in, hook JSON out (Claude Code; Hermes shell hooks) |
| GET | `/decisions?session_id=` | Recent decisions (in memory) |
| POST | `/sessions/{id}/reset` | Person resets a session |
| GET/POST | `/approvals`, `/approvals/{id}`, `/approvals/{id}/decide` | Approval queue |
| GET/POST | `/toolsets`, `/toolsets/{name}`, `/toolsets/{name}/pin`, `/toolsets/{name}/verify`, `/toolsets/{name}/coverage` | Tool Registry |
| GET/POST | `/suites`, `/evaluate`, `/evaluate/compare` | Evaluation, ablations and baselines |
| GET | `/evidence`, `/evidence/verify`, `/evidence/summary`, `/evidence/export` | Evidence ledger |
| GET | `/policies`, `/policies/{id}`, `/policies/validate` (POST), `/info`, `/client.py`, `/integrations/{agentdojo,inspect}` | |

## Connecting agents: `client.py`

One stdlib file, also served at `/api/agent-guard/client.py`:

- `GuardClient.check()` and the `@guard.tool` decorator; with
  `approval_wait=<seconds>` an `ask` waits for a person and re-checks with
  the approval; a retried call reuses its pending approval.
- `hook`: Claude-style PreToolUse command hook.
- `mcp-proxy`: a gateway between an agent and a stdio MCP server:
  `python agent_guard_client.py mcp-proxy --policy mcp-general --toolset NAME --approval-wait 120 -- <server command>`.
  `tools/list` is verified against the pinned version (changed, new and
  hidden-character tools are withheld and calls to them refused), every
  `tools/call` is checked (deny or unapproved ask returns a tool error with
  the reason; modify forwards the corrected arguments), and hidden characters
  are stripped from results. Server credentials stay in the server process's
  environment on the user's machine; nothing is proxied through robustidps.ai.

Every failure is a deny: a tool the guard did not approve never runs.

## Benchmark harnesses: AgentDojo and Inspect (`integrations/`)

Both files sit next to `agent_guard_client.py` and are served at
`/api/agent-guard/integrations/agentdojo` and `/api/agent-guard/integrations/inspect`.

- `agentdojo_guard.py`: `GuardedToolsExecutor(guard)` replaces AgentDojo's
  `ToolsExecutor` inside `ToolsExecutionLoop`. Allowed calls run through the
  stock executor; modified calls run with the corrected arguments; ask and
  deny return a tool error with the reasons (paired with the original tool
  call id). `executor.decisions` keeps every verdict for analysis. Verified
  with agentdojo 0.1.35.
- `inspect_guard.py`: the `agent_guard` approver (registered with
  `@approver`, usable from Python `ApprovalPolicy` lists or approval YAML).
  allow = approve, modify = modify (corrected `ToolCall`), ask = escalate
  (or reject with `ask_as="reject"`), deny = reject (or terminate with
  `deny_as="terminate"`); guard failures reject. Verified with inspect_ai
  0.3.283, end to end with a scripted `mockllm` model.

Each connector uses one guard session per task or sample and a fresh prefix
per instance, so budgets and repeated-denial rules do not carry over between
tasks or runs. Both accept a `checker(tool, args)` function instead of the
HTTP client for offline experiments.

## Limits

Sessions and the in-memory decision log live in one backend process (the
backend runs one worker); approvals, registry and ledger are in the database.
The guard is deterministic (rules, not prediction); the predictive layer
(effect model, recoverability check, calibrated deferral) is the planned
research step.
