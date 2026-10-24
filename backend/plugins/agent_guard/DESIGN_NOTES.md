# Agent Guard design notes: what we took from the external framework review

An external review of agent frameworks and safety filters (October 2026)
reached the same overall decision as our own research report: build the
enforcement layer, plug it into existing agent hosts through hooks and an
MCP gateway, and do not fork a framework. This note records which of its
points changed the guard, which are planned, and which we did not adopt.
Claims attributed to the review were not re-verified here.

## Adopted now

| Review point | What changed in Agent Guard |
|---|---|
| Bare vetoes turn safety into task denial (it cites a τ-bench study where mediation stopped up to 94% of non-compliant actions but strictly safe task success stayed below 5%) | **Repair before refusal.** `scope.on_violation: "project"` keeps the in-scope part of a call (drops out-of-scope list entries, narrows a range to the single allowed network inside it) and denies only when nothing in scope remains or the repair would be a guess. The authorised-testing pack now projects. |
| Approval should cover what actually runs | An approval request stores the repaired arguments; the reviewer sees them and the approved call runs with them. |
| Scalar budgets admit a sound check ("remaining budget ≥ cost of a safe abort; clip amounts") | **Session budgets** (`budgets`): a count of calls or the sum of a numeric argument per session, with a `reserve`; over-budget amounts are clipped to what is left, exhausted budgets stop the call, unparseable amounts are denied. Charged only when a call is let through. Packs: containment actions per session (SOC), active probes per session (testing). |
| Agent exploits rewrite their own guard or approval settings (the review lists Cursor, Copilot/VS Code and Claude Code advisories) | **`agent-config-write`** rule in the MCP/coding pack: writes or shell commands touching `.claude/`, `.cursor/`, `.codex/`, `.hermes/`, `.openhands/`, `.gemini/`, `.vscode/settings.json`, `mcp.json` / `.mcp.json` or `claude_desktop_config.json` are denied. Reading them stays allowed. |
| Keep the policy outside the agent's reach | Already the design: policies live on the server, the client only forwards calls, and approvals need a signed-in person. |
| Fail closed on anything unparseable | Already the design; extended to budgets (non-numeric amounts deny). |
| Measure denial, not only safety | **Intervention rate** (share of calls the filter touched) and **repair rate** (share of interventions that were repairs rather than stops) in evaluations and comparisons. |
| Hermes shell hooks fail open unless `fail_closed: true` | Noted on the Safety Filter page next to the hook configuration. |

## Planned

- **Session information flow.** Track data labels across a session
  (untrusted input read, sensitive data read, external send) and require
  approval when a session would combine all three, the "Rule of Two"
  pattern. Needs per-tool labels in the policy packs.
- **Typed actions for network tools.** Parse common tool arguments into
  target sets and rates before checking, and deny what cannot be parsed,
  instead of matching strings.
- **Lookahead.** The predictive layer from the research report: check that
  a safe fallback is still reachable after the proposed action.
- **Out-of-process enforcement for in-process hooks.** Host-side hooks act
  only as deny-by-default routers to the guard service (already true for
  the client and gateway; document per framework).
- **OpenHands SDK hooks** accept Claude-style JSON per the review; verify
  against the SDK and add a documented example (allow/deny only there).

## Not adopted

- Content about the review's own research programme (a UAV-specific
  filter, its venues and funding) is out of scope for this platform.
- Shell-string parsing as a safety argument: the review itself notes that
  command parsers fail open repeatedly; the coding pack keeps shell calls
  at "ask" and denies chaining instead of trying to parse shell.
