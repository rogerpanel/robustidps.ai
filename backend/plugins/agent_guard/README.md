# Agent Guard: a fail-closed safety filter for agent tool calls

Every tool call an agent proposes is checked here before it runs. The answer is
`allow`, `modify` (run with `modified_args`), `ask` (a human must approve) or
`deny`. Page: **Agent Security (Defend) > Safety Filter** (`/agent-guard`).

## What it checks (phase 0)

| Layer | Check |
|---|---|
| Canonicalise | NFKC; hidden, bidirectional and tag characters removed and reported (hidden text in the tool name is a deny, in arguments an ask); rationale fields such as `reasoning` are ignored by rules |
| Tier | Tool name (glob) to an action tier with a verdict, e.g. read = allow, reversible containment = ask, irreversible = deny; unknown tools get the pack's default |
| Scope | Target arguments (hosts, IPs, URLs, CIDRs) must fall inside the agreed scope |
| Argument rules | Regex rules on argument values (mass targets, shell chaining, credential paths, metadata endpoints) |
| Clamps and redaction | Numeric caps (e.g. result limits) and removal of secret-bearing arguments become `modify` |
| Session | Budget of calls; a call identical to one already denied stays denied; after N denials every allowed call needs approval until a human resets the session |

Fail closed: filter errors, timeouts (`AGENT_GUARD_TIMEOUT_S`, default 2 s),
oversized arguments, a concurrent check for the same session and malformed
hook payloads are all denies. A new policy version re-judges earlier denials.

Policies classify actions and targets, never attacker-chosen names in
telemetry, so renaming an artefact cannot change a verdict.

## Policy packs

`policies/soc-triage.json`, `policies/authorised-testing.json` (fill
`scope.allow` with your rules of engagement; empty means everything is out of
scope), `policies/mcp-general.json`. Submit your own JSON with `policy` in a
check request, or validate it at `POST /api/agent-guard/policies/validate`.

## API (`/api/agent-guard`)

| Method | Path | |
|---|---|---|
| POST | `/check` | `{session_id, tool_name, args, policy_id?, policy?, agent_id?, framework?}` returns the decision |
| POST | `/hooks/claude?policy_id=` | Claude-style PreToolUse payload in, hook JSON out (Claude Code; Hermes shell hooks use the same JSON) |
| GET | `/decisions?session_id=` | Recent decisions of the caller |
| POST | `/sessions/{id}/reset` | Human reset of a session's budget, denials and escalation |
| GET | `/policies`, `/policies/{id}`, `/info`, `/client.py` | |

Identity is the Agent Studio one: platform login token, `rids_live_` API key,
or demo mode. Every decision also feeds the Runtime Monitor
(allow, warn for modify/ask, block for deny).

## Connecting agents

`client.py` (also served at `/api/agent-guard/client.py`) is a single stdlib
file: `GuardClient.check()`, a `@guard.tool` decorator, and a command hook:

```bash
AGENT_GUARD_URL=https://robustidps.ai AGENT_GUARD_TOKEN=... \
python agent_guard_client.py hook --policy mcp-general   # stdin: hook JSON, stdout: verdict JSON
```

OpenHands: map the verdict to a security risk (allow LOW, modify MEDIUM,
ask/deny HIGH) in a `SecurityAnalyzer`; the hook endpoint returns it as
`agentGuard.openhands_risk`.

## Limits

Session state and the decision log are in memory in one backend process:
run one worker for the guard or move `SessionStore` to Redis before scaling
out. Phase 0 is deterministic; the predictive layer (effect model,
recoverability check, calibrated deferral) is the planned research step.
