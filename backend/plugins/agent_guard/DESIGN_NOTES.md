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

## Labelled SOC response actions

`suites/soc-response-actions.json` labels each action twice: the verdict the
SOC policy should give, and whether an analyst would consider it appropriate
in its incident context. On the built-in SOC policy no inappropriate action
runs unreviewed, but 44% of them only reach a person rather than being
denied: they are reasonable-looking actions (isolating a domain controller,
blocking the internal DNS resolver, disabling the backup service account)
that a filter seeing only the call cannot tell from appropriate ones. That
share is the target for the predictive layer, which would weigh the effect
of an action on the environment (asset role, blast radius, reversibility).

## Predictive layer (L2), first version

`predictive.py` predicts, for containment calls, what becomes unavailable in
the defender's inventory (`environment.py`) and admits the call only if the
state afterwards keeps every redundancy group at or above its minimum and
the dependents taken down per call and per session under the policy limits.
The session is the horizon: what earlier calls (including approved ones)
took down counts. On the labelled response-action suite with its inventory,
inappropriate actions that only reached a person fall from 44% to 22%
(the rest are denied with a stated prediction), and no appropriate action
is newly denied. The remaining 22% are cases the inventory cannot separate
(a neighbouring workstation with no declared role, unknown tools) or that
are matched by process name, which is deliberately left to a person
because an attacker could name a process after a critical service to make
the guard refuse to stop it.

## Calibrated deferral

`deferral.py`: a Learn-then-Test threshold on a transparent risk score, fitted
to the tenant's own approve/deny history. The guarantee is about the share of
auto-approved requests a person would have denied (alpha, at confidence
1 - delta). An earlier draft used conformal risk control with a loss averaged
over all requests; a simulation test showed that bounds the wrong quantity
(wrong auto-approvals as a share of all requests, not of auto-approvals), so
it was replaced. In simulation (400 decisions, alpha 0.05, delta 0.1) the true
rate exceeded alpha in 4.5% of calibrations and a threshold was found in 61%.
The eligibility rules keep adversarially placed requests (hidden characters,
unknown targets, unsafe predictions) away from the threshold entirely.

## Session information flow

`flow.py`: policy packs label tools untrusted, sensitive or egress (by name,
optionally by an argument pattern, and for egress by destination); a session
collects the labels of calls that ran, and a rule sends an outbound call to a
person once the session has read both untrusted input and sensitive data
(the Rule of Two). Asks from these rules are never auto-approved.

- In the SOC pack, alerts, logs, e-mails and attachments are labelled both
  untrusted and sensitive, because telemetry is attacker-influenced and
  internal at once (the mimicry results in our provenance-graph study are
  the same observation from the other side). Messages got their own tier,
  allowed; the flow rule decides whether a send leaves the organisation
  after exposure. Before this, every message asked and a public sandbox
  upload was allowed.
- On the multi-step SOC suite (27 steps, 8 sessions), the previous SOC
  pack (v3) let the public sandbox upload through and sent 5 of 16
  legitimate steps to a person (exact 78%, false stops 31%); v4 gets 100%
  with no false stops. Without the flow layer, v4 catches 18% of the
  stops. On the coding-agent suite the verdicts do not change (every send
  already needed a person), but the reason does: "right reason" is 100%
  with the layer and 38% without it (only the steps whose expected reason
  is the tier itself), and the flow reason is what makes those
  requests exempt from calibrated deferral and explains them to the
  reviewer. Both suites were written alongside the packs.
- Evaluation gained sessions (ordered steps; an ask counts as approved),
  `expect_rule` and session-level bootstrap.
- Coarse by design: labels are per session, not per value, and come from
  which tools ran, never from their results or the agent's reasons.

## Typed actions for network tools

`actions.py`: arguments a pack names are parsed into targets (networks,
hosts, URLs), port sets and rates, then checked as values. Compared with the
previous string rules on the two new suites (written alongside the packs):

- Authorised testing (32 cases): the previous pack got 59% exactly. It
  refused in-scope requests written as ranges, wildcard octets, host:port,
  a trailing dot or a comma list (false stops 67%); it sent a gopher URL to
  an internal Redis and `http://evil.example\@web.lab.example/` to a person
  as in scope (HTTP clients disagree about that host, some reach
  evil.example); and it could not see ports, rates or unreadable values.
  The typed pack gets 100%.
- SOC (12 cases): the previous pack sent 0.0.0.0/1, 10.0.0.0/8, a 65,535
  address range, `*.com` and internal addresses written in hex or as an
  integer to a person; they are now denied. Unreadable targets and
  unrecognised argument names still go to a person, as before, so existing
  SOC integrations keep working.
- Coding agents: web requests accept only http and https and never reach
  cloud metadata in any spelling; localhost stays allowed for dev servers.
- Shell commands are still not parsed (see "Not adopted").
- Also fixed with this step: approved and auto-approved calls are charged
  to session budgets, re-checked when the approval is used; calibrated
  deferral now only considers asks raised by the action tier alone.

## Agent hosts: OpenHands and the Claude Agent SDK

Both were checked against the installed SDKs rather than their documentation:

- OpenHands (openhands-sdk 1.58.2) runs command hooks with the event on
  stdin and reads `{"decision", "reason"}`; exit 2 blocks. Any other exit
  code, a timeout or a missing command lets the call through, and there is
  no ask or argument rewriting. The connector therefore exits 2 on every
  refusal and error, refuses asks with the approval id and modifies with the
  corrected arguments, and judges multiplexed tools per command. Our
  earlier Claude-format answer would not have blocked anything in OpenHands.
- The Claude Agent SDK (claude-agent-sdk 0.2.174) does not call
  `can_use_tool` for calls its permission settings already allow, so the
  connector is a PreToolUse hook, which sees every call.
- Because hook processes are stateless, the guard now reuses a pending
  request for a repeated identical call and lets a recently approved request
  be used once by the next identical call in the same session.

## Policy authoring from evaluation failures

`authoring.py` turns failing labelled cases into proposed policy edits, each
re-run on the whole suite. Two findings from building it:

- The policy language could not say "allow this one command of an asking
  tool": a tier applied to every call of a tool. Tool rules now take
  argument conditions (`when`, full regex match, never on stated reasons).
- Narrowest edits overfit. On the example (10 labelled cases, 8 held out),
  the smallest edit per failure fixed every training failure but only one
  of three held-out twins; choosing the widest edit that breaks no labelled
  case fixed all three and broke nothing. This is the classic choice
  between the most specific and the most general hypothesis consistent with
  the labels; the tool reports both, and held-out results never influence
  the ranking.

## Planned

- Independent evaluation on AgentDojo's ground-truth tool calls (benign
  tasks and attack goals), with policies generated from tool descriptions.

## Not adopted

- Content about the review's own research programme (a UAV-specific
  filter, its venues and funding) is out of scope for this platform.
- Shell-string parsing as a safety argument: the review itself notes that
  command parsers fail open repeatedly; the coding pack keeps shell calls
  at "ask" and denies chaining instead of trying to parse shell.
