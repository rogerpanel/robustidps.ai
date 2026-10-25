"""Write the paper's numbers (LaTeX macros) and tables from results/*.json. Do not edit the outputs by hand.

    python research/agent-guard-bench/harness/make_tables.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
GEN = ROOT / "paper" / "generated"


def pct(x, digits=1):
    if x is None:
        return "n/a"
    v = round(100 * x, digits)
    return (f"{v:.{digits}f}".rstrip("0").rstrip(".") if digits else f"{v:.0f}") + r"\%"


def num(x, digits=2):
    return f"{x:.{digits}f}"


def ci(pair, f=pct):
    return f"[{f(pair[0])}, {f(pair[1])}]"


def main() -> None:
    ad = json.loads((RES / "agentdojo_results.json").read_text())
    it = json.loads((RES / "internal_results.json").read_text())
    GEN.mkdir(parents=True, exist_ok=True)
    m: dict[str, str] = {}

    # ── AgentDojo replay ──
    suites = ad["suites"]
    m["AdVersion"] = ad["meta"]["agentdojo_version"]
    m["AdBench"] = ad["meta"]["benchmark_version"]
    m["FilterVersion"] = ad["meta"]["filter_version"]
    m["AdBenign"] = str(sum(s["n_benign"] for s in suites.values()))
    m["AdAttacks"] = str(sum(s["n_attacks"] for s in suites.values()))
    m["AdGoals"] = str(sum(s["n_goals"] for s in suites.values()))
    m["AdTools"] = str(sum(sum(ad["policies"][n]["tiers"]["tiers"].values()) for n in suites))
    m["AdGoalsNoCalls"] = str(sum(len(s["excluded"]["injection_tasks_without_tool_calls"]) for s in suites.values()))
    m["AdGoalsNoCallsWorkspace"] = str(len(suites["workspace"]["excluded"]["injection_tasks_without_tool_calls"]))
    m["AdGoalsNoCallsTravel"] = str(len(suites["travel"]["excluded"]["injection_tasks_without_tool_calls"]))
    m["AdUnexposedPairs"] = str(sum(s["excluded"]["pairs_excluded_unexposed"] for s in suites.values()))
    m["AdSeconds"] = str(round(ad["meta"]["seconds"]))
    P = ad["pooled"]
    keys = {"Allow": "allow everything", "Ask": "ask for everything", "Tiers": "tiers", "Flow": "tiers+flow",
            "Cons": "tiers+flow (conservative)"}
    for short, name in keys.items():
        v = P[name]
        m[f"Ad{short}Unattended"] = pct(v["benign_unattended"])
        m[f"Ad{short}Completes"] = pct(v["benign_completes_with_review"])
        m[f"Ad{short}Asks"] = num(v["benign_asks_per_task"])
        m[f"Ad{short}GoalUnreviewed"] = pct(v["attack_goal_unreviewed"])
        m[f"Ad{short}GoalDenied"] = pct(v["attack_goal_denied"])
        m[f"Ad{short}GoalPerson"] = pct(v["attack_goal_to_person"])
        if "ci95_trajectories" in v:
            c = v["ci95_trajectories"]
            m[f"Ad{short}GoalUnreviewedCI"] = ci(c["attack_goal_unreviewed"])
            m[f"Ad{short}UnattendedCI"] = ci(c["benign_unattended"])
            m[f"Ad{short}AsksCI"] = ci(c["benign_asks_per_task"], num)
    m["AdAskReduction"] = pct(1 - P["tiers"]["benign_asks_per_task"] / P["ask for everything"]["benign_asks_per_task"], 0)
    m["AdRuleOfThree"] = pct(3 / int(m["AdGoals"]), 1)
    unrev = ad["goal_tools"]
    m["AdTiersUnreviewedGoalTool"] = r"\texttt{get\_webpage}"
    # deferral interplay
    D = ad["deferral"]["pooled"]
    for short, name in (("Tiers", "tiers"), ("Flow", "tiers+flow"), ("Cons", "tiers+flow (conservative)")):
        d = D[name]
        m[f"Def{short}GoalEligible"] = pct(d["asks"]["attack-goal"]["eligible_share"])
        m[f"Def{short}BenignEligible"] = pct(d["asks"]["benign"]["eligible_share"])
        m[f"Def{short}GoalUnreviewed"] = pct(d["attack_goal_unreviewed_if_deferred"])
        m[f"Def{short}BenignUnattended"] = pct(d["benign_unattended_if_deferred"])
    # authoring on AgentDojo (mean over the two folds)
    au = ad["authoring"]

    def fold_mean(name, path):
        vals = []
        for f in au[name].values():
            x = f
            for p in path:
                x = x[p]
            vals.append(x)
        return sum(vals) / len(vals)
    m["AuSlackGoalBefore"] = pct(fold_mean("slack", ["test_before", "attack_goal_unreviewed"]))
    m["AuSlackGoalAfter"] = pct(fold_mean("slack", ["test_after", "attack_goal_unreviewed"]))
    m["AuSlackAsksBefore"] = num(fold_mean("slack", ["test_before", "benign_asks_per_task"]))
    m["AuSlackAsksAfter"] = num(fold_mean("slack", ["test_after", "benign_asks_per_task"]))
    lat = ad["latency_ms"]
    m["LatMedian"] = f"{lat['median']:.3f}"
    m["LatPNinetyFive"] = f"{lat['p95']:.3f}"
    m["LatN"] = f"{lat['n']:,}".replace(",", "{,}")

    # ── internal ──
    ba = it["before_after"]
    m["BaFlowBefore"] = pct(ba["session-flow-soc"]["before"]["exact_accuracy"])
    m["BaFlowFalseStopBefore"] = pct(ba["session-flow-soc"]["before"]["false_stop_rate"])
    m["BaTypedTestBefore"] = pct(ba["typed-actions-testing"]["before"]["exact_accuracy"])
    m["BaTypedTestFalseStopBefore"] = pct(ba["typed-actions-testing"]["before"]["false_stop_rate"])
    m["BaTypedSocBefore"] = pct(ba["typed-actions-soc"]["before"]["exact_accuracy"])
    pr = it["predictive"]
    m["PredInapPersonWith"] = pct(pr["with prediction"]["inappropriate"]["to_a_person"])
    m["PredInapPersonWithout"] = pct(pr["without prediction"]["inappropriate"]["to_a_person"])
    m["PredInapDeniedWith"] = pct(pr["with prediction"]["inappropriate"]["denied"])
    m["PredAppDeniedWith"] = pct(pr["with prediction"]["appropriate"]["denied"])
    m["PredAppDeniedWithout"] = pct(pr["without prediction"]["appropriate"]["denied"])
    ae = it["authoring_example"]
    m["AuExNarrowHoldout"] = pct(ae["narrow"]["holdout_after"], 0)
    m["AuExGeneralHoldout"] = pct(ae["general"]["holdout_after"], 0)
    m["AuExHoldoutBefore"] = pct(ae["narrow"]["holdout_before"], 1)
    sim = it["deferral_simulation"]
    m["SimRuns"] = f"{sim['runs']:,}".replace(",", "{,}")
    m["SimOptimal"] = pct(sim["optimal_auto_share"], 0)
    for g, tag in (("every score", "Every"), ("deciles", "Dec")):
        t = sim["by_grid"][g]
        m[f"Sim{tag}MaxViolation"] = pct(max(v["violations"] for v in t.values()))
        for n in ("100", "400", "1600"):
            word = {"100": "Hundred", "400": "FourHundred", "1600": "SixteenHundred"}[n]
            m[f"Sim{tag}Ready{word}"] = pct(t[n]["ready"], 0)
            m[f"Sim{tag}Share{word}"] = pct(t[n]["mean_auto_share_when_ready"], 0)
    m["InSuites"] = str(len(it["suites"]))
    m["InCases"] = str(sum(s["cases"] for s in it["suites"].values()))

    lines = ["% Generated by harness/make_tables.py from results/*.json; do not edit by hand."]
    for k in sorted(m):
        if m[k] == "":
            continue
        lines.append(f"\\providecommand{{\\{k}}}{{}}\\renewcommand{{\\{k}}}{{{m[k]}}}")
    (GEN / "results_macros.tex").write_text("\n".join(lines) + "\n")

    # ── tables ──
    rows = []
    for short, name, label in (("Allow", "allow everything", "Allow everything (no filter)"),
                               ("Ask", "ask for everything", "Ask a person for everything"),
                               ("Tiers", "tiers", "Tiers from descriptions"),
                               ("Flow", "tiers+flow", "\\quad + flow, hinted labels"),
                               ("Cons", "tiers+flow (conservative)", "\\quad + flow, conservative labels")):
        rows.append(f"{label} & \\Ad{short}Unattended & \\Ad{short}Completes & \\Ad{short}Asks & "
                    f"\\Ad{short}GoalUnreviewed & \\Ad{short}GoalPerson & \\Ad{short}GoalDenied \\\\")
    (GEN / "table_agentdojo.tex").write_text(r"""\begin{table*}[t]
\centering
\caption{AgentDojo \AdBench{} replay: \AdBenign{} benign tasks and \AdAttacks{} hijacked-agent attacks (\AdGoals{} attack goals), all pooled over the four suites. Benign: share of tasks that run with no person (\emph{unattended}), share that complete when a person approves every request (\emph{with review}), and requests per task. Attack: share whose goal calls all run without a person (\emph{unreviewed}), reach a person, or are refused. Policies are generated from tool names and descriptions only.}
\label{tab:agentdojo}
\begin{tabular}{lcccccc}
\toprule
& \multicolumn{3}{c}{Benign tasks} & \multicolumn{3}{c}{Attack goals} \\
\cmidrule(lr){2-4}\cmidrule(lr){5-7}
Policy & Unattended & With review & Requests/task & Unreviewed & To a person & Refused \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}
\end{table*}
""")
    rows = []
    for n, s in suites.items():
        t, c = s["metrics"]["tiers"], s["metrics"]["tiers+flow (conservative)"]
        rows.append(f"{n.capitalize()} & {s['n_benign']} & {s['n_attacks']} & {s['n_goals']} & "
                    f"{pct(t['benign_unattended'], 0)} & {num(t['benign_asks_per_task'])} & {pct(t['attack_goal_unreviewed'])} & "
                    f"{pct(c['benign_unattended'], 0)} & {num(c['benign_asks_per_task'])} & {pct(c['attack_goal_unreviewed'])} \\\\")
    (GEN / "table_agentdojo_suites.tex").write_text(r"""\begin{table}[t]
\centering
\caption{Per AgentDojo suite: tasks, attack replays and goals, then benign unattended share, requests per benign task and unreviewed attack goals, for tiers alone and with conservative flow labels.}
\label{tab:agentdojo-suites}
\setlength{\tabcolsep}{3pt}
\resizebox{\columnwidth}{!}{%
\begin{tabular}{lrrrcccccc}
\toprule
& & & & \multicolumn{3}{c}{Tiers} & \multicolumn{3}{c}{+ flow (conservative)} \\
\cmidrule(lr){5-7}\cmidrule(lr){8-10}
Suite & Tasks & Attacks & Goals & Unatt. & Req. & Unrev. & Unatt. & Req. & Unrev. \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}}
\end{table}
""")
    rows = []
    for short, name, label in (("Tiers", "tiers", "Tiers"), ("Flow", "tiers+flow", "+ flow, hinted"),
                               ("Cons", "tiers+flow (conservative)", "+ flow, conservative")):
        rows.append(f"{label} & \\Def{short}BenignEligible & \\Def{short}GoalEligible & \\Def{short}BenignUnattended & "
                    f"\\Def{short}GoalUnreviewed \\\\")
    (GEN / "table_deferral.tex").write_text(r"""\begin{table}[t]
\centering
\caption{Calibrated deferral on the AgentDojo replay. \emph{Eligible}: share of benign and attack-goal approval requests that deferral could ever auto-approve. Right: benign tasks unattended and attack goals unreviewed if a calibrated threshold covered every eligible request, the case for a deployment whose history has few denials.}
\label{tab:deferral}
\setlength{\tabcolsep}{2.5pt}
\small
\begin{tabular}{lcccc}
\toprule
& \multicolumn{2}{c}{Eligible} & \multicolumn{2}{c}{All eligible approved} \\
\cmidrule(lr){2-3}\cmidrule(lr){4-5}
Policy & Benign & Attack & Unattended & Unreviewed \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}
\end{table}
""")
    rows = []
    names = {"agent-hosts-mcp": "Agent hosts (coding)", "authorised-testing-core": "Authorised testing",
             "mcp-general-core": "Coding / MCP", "session-flow-mcp": "Flow sessions (coding)",
             "session-flow-soc": "Flow sessions (SOC)", "soc-response-actions": "SOC response actions",
             "soc-triage-core": "SOC triage", "typed-actions-soc": "Typed actions (SOC)",
             "typed-actions-testing": "Typed actions (testing)"}
    for sid, s in it["suites"].items():
        t = {r["name"]: r for r in s["table"]}
        abl = [r for r in s["table"] if r["kind"] == "ablation" and r["name"] != "tiers only"]
        worst = min(abl, key=lambda r: r["exact_accuracy"]) if abl else None
        worst_txt = (f"{worst['name'].replace('without ', '')} ({pct(worst['exact_accuracy'], 0)})"
                     if worst and worst["exact_accuracy"] < 1 else "none")
        rows.append(f"{names.get(sid, sid)} & {s['cases']} & {pct(t['full policy']['exact_accuracy'], 0)} & "
                    f"{pct(t['tiers only']['exact_accuracy'], 0)} & {worst_txt} \\\\")
    (GEN / "table_internal.tex").write_text(r"""\begin{table}[t]
\centering
\caption{Built-in labelled suites (written alongside the packs; regression tests, not an independent benchmark): exact-verdict accuracy of the full pack, of tiers alone, and the single layer whose removal costs most.}
\label{tab:internal}
\setlength{\tabcolsep}{3pt}
\resizebox{\columnwidth}{!}{%
\begin{tabular}{lrccl}
\toprule
Suite & Cases & Full & Tiers only & Costliest removal \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}}
\end{table}
""")
    rows = []
    for n in ("100", "200", "400", "800", "1600"):
        e, d = sim["by_grid"]["every score"][n], sim["by_grid"]["deciles"][n]
        rows.append(f"{n} & {pct(e['ready'], 0)} & {pct(e['violations'])} & {pct(d['ready'], 0)} & {pct(d['violations'])} & "
                    f"{pct(d['mean_auto_share_when_ready'], 0)} \\\\")
    (GEN / "table_simulation.tex").write_text(r"""\begin{table}[t]
\centering
\caption{Learn then Test ($\alpha=0.05$, $\delta=0.1$), \SimRuns{} simulated histories per size: share of runs that find a threshold (\emph{ready}), share in which the true denial rate under it exceeds $\alpha$ (\emph{violated}), and the auto-approved share. The best threshold auto-approves \SimOptimal{}.}
\label{tab:simulation}
\setlength{\tabcolsep}{3pt}
\small
\begin{tabular}{rccccc}
\toprule
& \multicolumn{2}{c}{Every score} & \multicolumn{3}{c}{Decile grid} \\
\cmidrule(lr){2-3}\cmidrule(lr){4-6}
History & Ready & Violated & Ready & Violated & Auto share \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}
\end{table}
""")
    print("wrote", ", ".join(sorted(p.name for p in GEN.iterdir())))


if __name__ == "__main__":
    main()
