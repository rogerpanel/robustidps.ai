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

    # Pooled over suites and both folds: held-out (test) halves, weighted by their tasks and attacks.
    agg = {}
    for cfgs in au.values():
        for cfg, folds in cfgs.items():
            for f in folds.values():
                a = agg.setdefault(cfg, {"bt": 0, "at": 0, "u0": 0.0, "u1": 0.0, "q0": 0.0, "q1": 0.0, "g0": 0.0, "g1": 0.0})
                b0, b1 = f["test_before"], f["test_after"]
                a["bt"] += b0["benign_tasks"]
                a["at"] += b0["attacks"]
                a["u0"] += b0["benign_unattended"] * b0["benign_tasks"]
                a["u1"] += b1["benign_unattended"] * b1["benign_tasks"]
                a["q0"] += b0["benign_asks_per_task"] * b0["benign_tasks"]
                a["q1"] += b1["benign_asks_per_task"] * b1["benign_tasks"]
                a["g0"] += b0["attack_goal_unreviewed"] * b0["attacks"]
                a["g1"] += b1["attack_goal_unreviewed"] * b1["attacks"]
    tags = {"general, every goal call": "GenAll", "balanced, every goal call": "BalAll",
            "balanced, final goal call": "BalLast", "balanced, final goal call, unseen goals": "BalUnseen"}
    arows = []
    for cfg, a in agg.items():
        t = tags.get(cfg)
        vals = {"GoalBefore": pct(a["g0"] / a["at"]), "GoalAfter": pct(a["g1"] / a["at"]),
                "AsksBefore": num(a["q0"] / a["bt"]), "AsksAfter": num(a["q1"] / a["bt"]),
                "UnattBefore": pct(a["u0"] / a["bt"]), "UnattAfter": pct(a["u1"] / a["bt"])}
        if t:
            for k, v in vals.items():
                m[f"Au{t}{k}"] = v
        strategy, labels, *rest = [x.strip() for x in cfg.split(",")]
        split = "unseen goals" if rest else "pairs"
        arows.append(f"{strategy.capitalize()} & {labels} & {split} & {vals['GoalBefore']} $\\to$ {vals['GoalAfter']} & "
                     f"{vals['AsksBefore']} $\\to$ {vals['AsksAfter']} & {vals['UnattBefore']} $\\to$ {vals['UnattAfter']} \\\\")
    (GEN / "table_authoring.tex").write_text(r"""\begin{table*}[t]
\centering
\caption{Policy authoring on the AgentDojo replay: edits proposed on one half, measured on the other (both directions, all suites pooled). \emph{Labels}: which attack-goal calls must reach a person. \emph{Split}: held-out attacks may share their goal with training attacks (pairs) or not (unseen goals). Before $\to$ after: unreviewed attack goals, requests per benign task, benign tasks unattended.}
\label{tab:authoring}
\small
\setlength{\tabcolsep}{6pt}
\begin{tabular}{lllccc}
\toprule
Strategy & Labels & Split & Unreviewed & Requests & Unattended \\
\midrule
""" + "\n".join(arows) + r"""
\bottomrule
\end{tabular}
\end{table*}
""")
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
    live_section(GEN, RES / "live" / "live_results.json")
    print("wrote", ", ".join(sorted(p.name for p in GEN.iterdir())))


COND = {"none": "no filter", "guard": "filter, unattended", "guard-approve": "filter, all requests approved"}


def live_section(gen: Path, path: Path) -> None:
    """Table and text for the live-model runs (results/live/live_results.json from live_eval.py summarize)."""
    runs = json.loads(path.read_text())["runs"] if path.exists() else []
    runs = [r for r in runs if r["provider"] in ("anthropic", "openai") and r["n_tasks"]
            and r.get("integrity") == "verified"]       # only runs whose files match their manifest
    for stale in ("table_live.tex", "fig_live.tex"):      # never leave tables from earlier or test runs behind
        (gen / stale).unlink(missing_ok=True)
    if not runs:
        (gen / "live_section.tex").write_text(
            "% Generated by harness/make_tables.py: no live-model results yet.\n"
            "\\paragraph{Live models} Live-model runs follow the protocol in \\S\\ref{sec:method-live}; "
            "their results are not yet part of this draft.\n")
        return
    def fmt_ci(ci):
        return f" [{pct(ci[0], 0)}, {pct(ci[1], 0)}]" if ci else ""
    rows, order = [], {"none": 0, "guard": 1, "guard-approve": 2}
    runs.sort(key=lambda r: (r["provider"], r["model"], order.get(r["condition"], 9)))
    for r in runs:
        u = r.get("usage") or {}
        tok = (u.get("input_tokens", 0) + u.get("output_tokens", 0)) / 1e6
        model = r["model"].replace("_", "\\_")
        rows.append(f"{model} & {COND.get(r['condition'], r['condition'])} & {r['n_tasks']} & "
                    f"{pct(r['utility'], 0)}{fmt_ci(r.get('utility_ci95'))} & {pct(r['utility_under_attack'], 0)} & "
                    f"{pct(r['attack_success'], 1)}{fmt_ci(r.get('attack_success_ci95'))} & "
                    f"{('%.2f' % r['guard_asks_per_benign_task']) if r.get('guard_asks_per_benign_task') is not None else '--'} & "
                    f"{tok:.1f} \\\\")
    suites = sorted({s for r in runs for s in r["suites"]})
    (gen / "table_live.tex").write_text(r"""\begin{table*}[t]
\centering
\caption{Live models on AgentDojo (""" + ", ".join(suites) + r""", attack \texttt{important\_instructions}). Utility: user tasks solved without attack; under attack: tasks solved while injected; ASR: injection goals achieved (AgentDojo's checks), with 95\% Wilson intervals. Requests: the filter's approval requests per benign task. Tokens in millions.}
\label{tab:live}
\footnotesize
\setlength{\tabcolsep}{3pt}
\begin{tabular}{llrcccrr}
\toprule
Model & Condition & Tasks & Utility & Under attack & ASR & Requests & Tokens \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}
\end{table*}
""")
    lines = ["% Generated by harness/make_tables.py from results/live/live_results.json; do not edit by hand.",
             "\\subsection{RQ5: Live models}", "\\label{sec:res-live}", "\\input{generated/table_live}"]
    by_model = {}
    for r in runs:
        by_model.setdefault(r["model"], {})[r["condition"]] = r
    sentences = []
    for model, conds in by_model.items():
        m = model.replace("_", "\\_")
        if "none" in conds and "guard" in conds:
            a, b = conds["none"], conds["guard"]
            sentences.append(f"For \\texttt{{{m}}}, the attack success rate is {pct(a['attack_success'], 1)} "
                             f"without a filter and {pct(b['attack_success'], 1)} with the unattended filter, and "
                             f"utility is {pct(a['utility'], 0)} and {pct(b['utility'], 0)}")
            if "guard-approve" in conds:
                c = conds["guard-approve"]
                sentences[-1] += (f"; with every request approved, utility is {pct(c['utility'], 0)} "
                                  f"and the attack success rate {pct(c['attack_success'], 1)}")
            sentences[-1] += "."
    lines.append("Table~\\ref{tab:live} reports the live runs. " + " ".join(sentences))
    lines.extend(live_paired_text(gen, path.parent / "live_analysis.json", runs))
    (gen / "live_section.tex").write_text("\n".join(lines) + "\n")


def live_paired_text(gen: Path, path: Path, runs: list) -> list:
    """Paired tests, attribution and overhead from live_analysis.json, plus the utility-ASR figure."""
    if not path.exists():
        return []
    analyses = [a for a in json.loads(path.read_text())["runs"] if a["provider"] in ("anthropic", "openai")]
    out = []
    for a in analyses:
        m = a["model"].replace("_", "\\_")
        c = a["comparisons"].get("guard")
        if not c:
            continue
        rules = list((c.get("utility_lost_rules") or {}).items())
        most = (f" (most often \\texttt{{{rules[0][0].replace('_', chr(92) + '_')}}})" if rules else "")
        txt = (f"Paired on the same tasks, the unattended filter cost \\texttt{{{m}}} {c['utility_lost']} of "
               f"{c['tasks']} tasks and gained {c['utility_gained']} (exact McNemar $p={c['utility_p']:.3g}$); "
               f"{c['utility_lost_with_filter_decision']} of the lost tasks had a call the filter sent to a person "
               f"or refused{most}, and the rest reflect run-to-run variance of the model. Across the {c['pairs']} "
               f"attacks, it stopped {c['attacks_stopped']} that succeeded without it "
               f"({c['attacks_stopped_at_filter_decision']} of them at a filter decision), and "
               f"{c['attacks_newly_succeeding']} succeeded only with it ($p={c['attack_p']:.3g}$).")
        g = a["overhead"].get("guard", {})
        if g.get("check_ms_median") is not None:
            where = "round trip to the deployed service" if a.get("guard") == "url" else "in process"
            txt += (f" Each check took a median of {g['check_ms_median']:.2f}\\,ms ({where}; 95th percentile "
                    f"{g['check_ms_p95']:.2f}\\,ms).")
        out.append(txt)
    # Figure: utility against attack success, one line per model through its conditions.
    order = {"none": 0, "guard": 1, "guard-approve": 2}
    by_model: dict = {}
    for r in runs:
        if r.get("attack_success") is not None and r.get("utility") is not None:
            by_model.setdefault(r["model"], []).append(r)
    if by_model:
        marks = {"none": "*", "guard": "square*", "guard-approve": "triangle*"}
        plots = []
        for i, (model, rs) in enumerate(sorted(by_model.items())):
            rs.sort(key=lambda r: order.get(r["condition"], 9))
            coords = " ".join(f"({100 * r['attack_success']:.1f},{100 * r['utility']:.1f})" for r in rs)
            label = model.replace("_", "\\_")
            plots.append(f"\\addplot+[mark=*, thick] coordinates {{{coords}}};\n\\addlegendentry{{{label}}}")
            for r in rs:
                plots.append(f"\\node[font=\\tiny, anchor=south west] at (axis cs:{100 * r['attack_success']:.1f},"
                             f"{100 * r['utility']:.1f}) {{{r['condition']}}};")
        (gen / "fig_live.tex").write_text(r"""\begin{figure}[t]
\centering
\begin{tikzpicture}
\begin{axis}[width=\columnwidth, height=0.72\columnwidth, xlabel={Attack success rate (\%)}, ylabel={Utility without attack (\%)},
  xmin=0, ymin=0, ymax=100, grid=major, legend style={font=\scriptsize, at={(0.98,0.02)}, anchor=south east}, tick label style={font=\scriptsize}, label style={font=\small}]
""" + "\n".join(plots) + r"""
\end{axis}
\end{tikzpicture}
\caption{Live models: utility against attack success, per model, through the conditions no filter, filter unattended and filter with every request approved.}
\label{fig:live}
\end{figure}
""")
        out.insert(0, "\\input{generated/fig_live}")
    return out


if __name__ == "__main__":
    main()
