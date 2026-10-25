"""Policy authoring from evaluation failures.

For every labelled case the policy gets wrong (wrong verdict, or the right
verdict for the wrong reason), propose concrete edits to the policy, apply
each one, re-run the whole suite and report what it does:

  fixes     the failing case it was proposed for (candidates that do not are
            dropped) and any other failing cases
  breaks    cases that were right before and are wrong after
  changes   every case whose verdict moves, right or wrong
  breadth   1 = one value, 2 = one tool (or one scope or destination entry),
            3 = a group (a file stem, folder, MCP server, limit or rule decision),
            4 = a whole rule removed (wider edits move more future calls)

Candidates are ranked by: fixes the target, breaks nothing, then by strategy:
narrowest (narrow), widest (general), or least added review burden (balanced:
legitimate calls that newly need a person or are refused). With a held-out suite, every candidate is also run there, so an edit
that fits the cases it was made from but moves held-out verdicts is visible
before anyone adopts it. Nothing is applied automatically: the result is a
proposal (a policy to open, validate and test), because the labels can be
wrong too.

Edits proposed (all deterministic, from the case and the rules that fired):
  - classify the tool into a tier whose decision is the expected verdict;
  - for a verdict that is too strict: add the target to the scope, raise a
    typed-action limit or budget to what the case needs, relax or remove the
    argument rule that fired, mark a destination internal for a flow rule;
  - for a verdict that is too lenient: an argument rule for that exact value.
Causes outside the policy (environment inventory, session history) are
reported as notes without an edit.
"""
from __future__ import annotations

import copy
import re
from fnmatch import fnmatchcase

from plugins.agent_guard import actions as typed
from plugins.agent_guard.canonical import canonical_tool, matchable_strings
from plugins.agent_guard.contract import SEVERITY, ProposedCall
from plugins.agent_guard.engine import SessionStore, decide
from plugins.agent_guard.environment import Environment
from plugins.agent_guard.evaluation import Case, Suite, apply_suite_scope, run
from plugins.agent_guard.evidence import digest
from plugins.agent_guard.policy import Policy, parse_policy

MAX_CANDIDATES_PER_CASE = 8
MAX_FAILURES = 40
SHOW_PER_CASE = 4
MAX_RUNS = 160          # suite runs per request (each candidate re-runs the suite, and the held-out suite)


# ── edits ────────────────────────────────────────────────────────────

def apply_ops(policy: Policy, ops: list[dict]) -> Policy:
    """Apply edit operations to a copy of the policy; raises ValueError if the result is invalid."""
    data = copy.deepcopy(policy.model_dump())
    for op in ops:
        kind = op["op"]
        if kind == "add_tool_rule":
            data["tools"].insert(0, {"match": op["match"], "tier": op["tier"], "when": op.get("when", {})})
        elif kind == "add_tier":
            data["tiers"][op["name"]] = {"decision": op["decision"], "description": op["description"],
                                         "reversible": op.get("reversible")}
        elif kind == "remove_arg_rule":
            data["arg_rules"] = [r for r in data["arg_rules"] if r["id"] != op["id"]]
        elif kind == "set_arg_rule_decision":
            for r in data["arg_rules"]:
                if r["id"] == op["id"]:
                    r["decision"] = op["decision"]
        elif kind == "add_arg_rule":
            data["arg_rules"].insert(0, op["rule"])
        elif kind == "add_scope_allow":
            data["scope"]["allow"] = [*data["scope"]["allow"], op["entry"]]
        elif kind == "set_budget":
            for b in data["budgets"]:
                if b["id"] == op["id"]:
                    b["max_total"] = op["max_total"]
        elif kind == "set_action_limit":
            for a in data["actions"]:
                if a["id"] == op["id"]:
                    a[op["field"]] = op["value"]
        elif kind == "add_flow_internal":
            for lab in data["flow"]["labels"]:
                if lab["label"] == op["label"] and lab.get("destination_args"):
                    lab["internal"] = [*lab.get("internal", []), op["entry"]]
        else:
            raise ValueError(f"unknown edit '{kind}'")
    data["version"] = f"{policy.version}+edit"
    return parse_policy(data)


def _target_entry(value: str) -> str | None:
    """A scope entry covering exactly this target (address, network or host)."""
    try:
        for t in typed.parse_targets(value):
            return t.label() if t.net is None or t.net.num_addresses > 1 else str(t.net.network_address)
    except ValueError:
        return None
    return None


def _decision_for(case: Case, policy: Policy, suite: Suite):
    """The case judged alone (for the limits and destinations behind a verdict)."""
    env = Environment.model_validate(suite.environment) if suite.environment else None
    return decide(ProposedCall(session_id=f"authoring:{case.id}", tool_name=case.tool, args=case.args),
                  apply_suite_scope(policy, suite), SessionStore(), "authoring", env)


def candidates(case: Case, row: dict, policy: Policy, suite: Suite) -> tuple[list[dict], list[str]]:
    """Edits that might fix this case, and notes for causes outside the policy."""
    tool, _ = canonical_tool(case.tool)
    out: list[dict] = []
    notes: list[str] = []
    want, got = case.expect, row["got"]
    if case.accept:  # aim at the nearest acceptable verdict, not the preferred one
        ordered = sorted(case.accept, key=SEVERITY.__getitem__)
        if SEVERITY[got] > SEVERITY[ordered[-1]]:
            want = ordered[-1]
        elif SEVERITY[got] < SEVERITY[ordered[0]]:
            want = ordered[0]
    rules = row["rules"]
    tier_now = policy.tier_for(tool)

    def add(description: str, ops: list[dict], breadth: int) -> None:
        out.append({"description": description, "ops": ops, "breadth": breadth})

    def tier_ops(decision: str, match: list[str], when: dict | None = None) -> list[tuple[str, list[dict]]]:
        """Ways to put matching calls in a tier with this decision (creating one if the pack has none)."""
        rule = {"op": "add_tool_rule", "match": match, **({"when": when} if when else {})}
        names = [n for n, t in policy.tiers.items() if t.decision == decision]
        if names:
            return [(n, [{**rule, "tier": n}]) for n in names]
        name = f"authored-{decision}"
        return [(name, [{"op": "add_tier", "name": name, "decision": decision, "description": f"Authored: tools to "
                         f"{decision}", "reversible": None}, {**rule, "tier": name}])]

    server = tool.split("__")[1] if tool.count("__") >= 2 else None
    strings = [(p.split(".")[0].split("[")[0], v) for p, v in matchable_strings(case.args)]
    strings = [(k, v) for k, v in strings if isinstance(case.args.get(k), str)][:4]

    # Tier: classify the tool where its decision matches the label.
    if want in ("allow", "ask", "deny"):
        matching = [n for n, t in policy.tiers.items() if t.decision == want]
        for name in matching:
            if name != tier_now:
                tier = policy.tiers[name]
                add(f"Classify '{tool}' in tier '{name}' ({tier.decision}{', reversible' if tier.reversible else ''})",
                    [{"op": "add_tool_rule", "match": [tool], "tier": name}], 2)
        if not matching:
            for name, ops in tier_ops(want, [tool]):
                add(f"Create tier '{name}' ({want}) and classify '{tool}' in it", ops, 2)
        if server:
            for name, ops in tier_ops(want, [f"mcp__{server}__*"]):
                add(f"Classify every '{server}' MCP tool (mcp__{server}__*) in tier '{name}' ({want})", ops, 3)
        if SEVERITY[got] > SEVERITY[want] and any(r.startswith("tier:") for r in rules):
            for key, value in strings:
                for name, ops in tier_ops(want, [tool], {key: re.escape(value)}):
                    add(f"Classify '{tool}' in tier '{name}' ({want}) only when '{key}' is exactly '{value[:60]}'",
                        ops, 1)
    if case.expect_rule and case.expect_rule.startswith("tier:") and row.get("reason_ok") is False:
        name = case.expect_rule[5:]
        if name in policy.tiers and name != tier_now:
            add(f"Classify '{tool}' in tier '{name}'", [{"op": "add_tool_rule", "match": [tool], "tier": name}], 2)

    too_strict = SEVERITY[got] > SEVERITY[want]
    if too_strict:
        d = _decision_for(case, policy, suite)
        for rid in rules:
            arg_rule = next((r for r in policy.arg_rules if r.id == rid), None)
            if arg_rule is not None:
                if arg_rule.decision == "deny" and want in ("ask", "allow", "modify"):
                    add(f"Let argument rule '{rid}' ask instead of deny",
                        [{"op": "set_arg_rule_decision", "id": rid, "decision": "ask"}], 3)
                add(f"Remove argument rule '{rid}'", [{"op": "remove_arg_rule", "id": rid}], 4)
            elif rid == "out-of-scope" or rid.endswith(":out-of-scope"):
                keys = set(policy.scope.target_args if policy.scope else [])
                for a in policy.actions:
                    keys |= {k for k in case.args if any(fnmatchcase(k.lower(), g.lower()) for g in a.target_args)}
                for k in sorted(keys):
                    v = case.args.get(k)
                    for item in (v if isinstance(v, list) else [v]):
                        entry = _target_entry(str(item)) if item is not None else None
                        if entry and policy.scope is not None:
                            add(f"Add '{entry}' to the scope", [{"op": "add_scope_allow", "entry": entry}], 2)
            elif ":too-many-" in rid:
                aid, check = rid.split(":", 1)
                rep = next((r for r in (d.actions or []) if r["id"] == aid), None)
                field = {"too-many-targets": "max_targets", "too-many-ports": "max_ports",
                         "too-many-probes": "max_probes"}[check]
                need = {"max_targets": "n_targets", "max_ports": "ports", "max_probes": "probes"}[field]
                if rep and isinstance(rep.get(need), int) and rep[need] > 0:
                    add(f"Raise {aid}.{field} to {rep[need]:,}",
                        [{"op": "set_action_limit", "id": aid, "field": field, "value": rep[need]}], 3)
            elif any(b.id == rid for b in policy.budgets):
                b = next(b for b in policy.budgets if b.id == rid)
                add(f"Double budget '{rid}' to {b.max_total * 2:g}",
                    [{"op": "set_budget", "id": rid, "max_total": b.max_total * 2}], 3)
            elif rid.startswith("flow:") and d.flow:
                reason = d.flow.get("label_reasons", {}).get("egress", "")
                m = re.search(r" to (.+)$", reason)
                for dest in (m.group(1).split(", ") if m else []):
                    host = dest.split("@")[-1] if "@" in dest else None
                    entry = f"*@{host}" if host else _target_entry(dest)
                    if entry:
                        add(f"Treat '{entry}' as internal for the flow rules",
                            [{"op": "add_flow_internal", "label": "egress", "entry": entry}], 2)
            elif rid.startswith("predicted-"):
                notes.append(f"'{rid}' comes from the environment inventory: change the asset, its group minimum or "
                             "the blast-radius limits rather than the rules.")
            elif rid in ("session-escalated", "repeat-of-denied-call"):
                notes.append(f"'{rid}' comes from earlier steps in the session, not from this call.")
    elif SEVERITY[got] < SEVERITY[want] and want in ("ask", "deny"):
        def rule(key: str, pattern: str, label: str, breadth: int) -> None:
            add(f"Argument rule: {want} '{tool}' when '{key}' {label}",
                [{"op": "add_arg_rule", "rule": {
                    "id": f"authored-{digest([tool, key, pattern])[:8]}", "description": f"Authored from case {case.id}",
                    "tools": [tool], "args": [key], "pattern": pattern, "decision": want}}], breadth)
        for key, value in strings:
            rule(key, f"^{re.escape(value)}$", f"is exactly '{value[:60]}' (this value only)", 1)
            if "/" in value or "\\" in value:  # paths: the file's stem anywhere, or everything in its directory
                base = re.split(r"[/\\]", value)[-1]
                stem = base.split(".")[0]
                folder = value[: len(value) - len(base)]
                if stem and stem != base:
                    rule(key, rf"(^|[/\\]){re.escape(stem)}[^/\\]*$", f"names a file called '{stem}*' in any folder", 3)
                if folder.strip("/\\"):
                    rule(key, f"^{re.escape(folder)}", f"is inside '{folder}'", 3)
    if want == "modify" and got != "modify":
        notes.append("A 'modify' label needs a repair rule (clamp, redaction, scope projection or rate limit); "
                     "add one to the policy by hand.")
    if row.get("reason_ok") is False and row["correct"] and not out:
        notes.append(f"Right verdict, different reason: expected '{case.expect_rule}', got {', '.join(rules)}.")
    seen, unique = set(), []
    for c in out:
        key = digest(c["ops"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique[:MAX_CANDIDATES_PER_CASE], notes


# ── evaluation of candidates ─────────────────────────────────────────

def _ok(row: dict) -> bool:
    return row["correct"] and row.get("reason_ok") is not False


def _stopped(row: dict) -> bool:
    """A case whose preferred verdict lets the call run, but which now needs a person or is refused."""
    return row["expect"] in ("allow", "modify") and row["got"] in ("ask", "deny")


def _diff(before: dict, after: dict) -> dict:
    b = {r["id"]: r for r in before["rows"]}
    a = {r["id"]: r for r in after["rows"]}
    newly = sorted(i for i in b if not _stopped(b[i]) and _stopped(a[i]))
    relieved = sorted(i for i in b if _stopped(b[i]) and not _stopped(a[i]))
    return {"fixed": sorted(i for i in b if not _ok(b[i]) and _ok(a[i])),
            "broken": sorted(i for i in b if _ok(b[i]) and not _ok(a[i])),
            "changed": sorted(i for i in b if b[i]["got"] != a[i]["got"]),
            # Review burden: legitimate calls (preferred verdict allow or modify) that newly reach a person or are
            # refused, minus those relieved. Accepted verdict sets can make such calls "correct" while still costing
            # a reviewer's time, so the burden is reported separately from correctness.
            "burden": len(newly) - len(relieved), "burden_cases": newly[:50]}


def _rank(strategy: str):
    """narrow: the smallest edit that fixes the case; general: the widest edit that breaks no labelled case.
    Held-out results are reported but never used to rank, so the held-out suite stays a fair test."""
    if strategy == "general":
        return lambda e: (len(e["broken"]), -e["breadth"], -len(e["fixed"]), len(e["changed"]))
    if strategy == "balanced":  # breaks nothing, then adds the least review burden, then fixes the most
        return lambda e: (len(e["broken"]), e["burden"], -len(e["fixed"]), e["breadth"], len(e["changed"]))
    return lambda e: (len(e["broken"]), e["breadth"], len(e["changed"]), -len(e["fixed"]))


def suggest(suite: Suite, policy: Policy, holdout: Suite | None = None, strategy: str = "narrow",
            max_burden: int | None = None) -> dict:
    """`max_burden`: leave out of the combined proposal any edit that adds more review burden than this."""
    if strategy not in ("narrow", "general", "balanced"):
        raise ValueError("strategy must be 'narrow', 'general' or 'balanced'")
    if max_burden is not None and max_burden < 0:
        raise ValueError("max_burden must be 0 or more")
    if suite.scope_allow is not None and policy.scope is not None:
        # The suite fixes the scope for its run; fold it into the policy so scope edits can be proposed and shown.
        policy = apply_suite_scope(policy, suite)
        suite = suite.model_copy(update={"scope_allow": None})
    base = run(suite, policy)
    base_hold = run(holdout, policy) if holdout is not None else None
    cases = {c.id: c for c in suite.cases}
    failing = [r for r in base["rows"] if not _ok(r)][:MAX_FAILURES]
    report, runs, truncated = [], 0, False
    for row in failing:
        if runs >= MAX_RUNS:
            truncated = True
            break
        case = cases[row["id"]]
        cands, notes = candidates(case, row, policy, suite)
        scored = []
        for c in cands:
            if runs >= MAX_RUNS:
                truncated = True
                break
            try:
                edited = apply_ops(policy, c["ops"])
            except Exception:  # noqa: BLE001 — an edit that does not validate is not proposed
                continue
            after = run(suite, edited)
            runs += 1
            diff = _diff(base, after)
            if case.id not in diff["fixed"]:
                continue
            entry = {**c, **diff, "exact_accuracy": after["summary"]["exact_accuracy"], "policy": edited.model_dump()}
            if holdout is not None:
                hold = run(holdout, edited)
                runs += 1
                hd = _diff(base_hold, hold)
                entry["holdout"] = {**hd, "exact_accuracy": hold["summary"]["exact_accuracy"]}
            scored.append(entry)
        scored.sort(key=_rank(strategy))
        report.append({"case": case.id, "tool": case.tool, "expect": case.expect, "got": row["got"],
                       "expect_rule": case.expect_rule, "rules": row["rules"], "context": case.context,
                       "suggestions": scored[:SHOW_PER_CASE], "notes": notes})

    # Combined proposal: the best suggestion per failure that breaks nothing (here or held out), applied together.
    chosen, ops = [], []
    for f in report:
        best = next((s for s in f["suggestions"] if not s["broken"]
                     and (max_burden is None or s["burden"] <= max_burden)), None)
        if best is not None:
            chosen.append({"case": f["case"], "description": best["description"]})
            ops.extend(best["ops"])
    combined = None
    if ops:
        try:
            edited = apply_ops(policy, ops)
            after = run(suite, edited)
            combined = {"edits": chosen, **_diff(base, after), "exact_accuracy": after["summary"]["exact_accuracy"],
                        "policy": edited.model_dump()}
            if holdout is not None:
                hold = run(holdout, edited)
                combined["holdout"] = {**_diff(base_hold, hold), "exact_accuracy": hold["summary"]["exact_accuracy"]}
        except Exception:  # noqa: BLE001 — edits that conflict are left for a person to combine
            combined = None
    return {
        "suite": base["summary"]["suite"], "policy": base["summary"]["policy"], "strategy": strategy,
        "max_burden": max_burden,
        "exact_accuracy": base["summary"]["exact_accuracy"], "failures": len(failing),
        "holdout": ({"suite": base_hold["summary"]["suite"], "exact_accuracy": base_hold["summary"]["exact_accuracy"]}
                    if base_hold else None),
        "report": report, "combined": combined, "candidate_runs": runs, "truncated": truncated,
        "suggestion_digest": digest({"suite": base["suite_digest"], "policy": base["policy_digest"],
                                     "report": [[f["case"], [s["ops"] for s in f["suggestions"]]] for f in report]}),
        "note": "Proposals only: open one as a policy, validate and test it. Labels can be wrong too, and an edit "
                "made from a few cases can move cases nobody labelled; use a held-out suite to see that.",
    }
