#!/usr/bin/env python3
"""Turn agent run folders into the paper's tables, figure data and macros.

    python scripts/results_to_tex.py \
        --pilot results/pilot-2026-10-10 \
        --runs results/study/*/ \
        --baseline full \
        --out paper

Each study run folder is what the agent writes: traces/<date>-<run>/ with a
summary.json (configuration, metrics, task_rows) and one JSON per task.
Runs with the same configuration label are treated as repeats: tables show
mean ± standard deviation across them. Without study runs, the study tables
are written as "pending" so the paper still compiles.

Outputs (under --out):
    data/runs.csv            one row per configuration (means, sds, deltas)
    data/per_task.csv        task x configuration mean reward and verdict accuracy
    data/pilot_per_task.csv  the pilot run, per task
    tables/*.tex             booktabs tables included by the paper
    results_macros.tex       \\newcommand values quoted in the text
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import statistics
from pathlib import Path
from typing import Any

METRICS = [
    ("mean_quality", "Quality", 3),
    ("mean_efficiency", "Efficiency", 3),
    ("mean_reward", "Reward", 3),
    ("verdict_accuracy", "Verdict acc.", 3),
    ("false_positive_rate", "FPR", 3),
    ("false_negative_rate", "FNR", 3),
    ("mean_tool_calls", "Calls/task", 2),
]


# ---------------------------------------------------------------- loading
def load_run(folder: Path) -> dict[str, Any]:
    summary = json.loads((folder / "summary.json").read_text())
    rows = summary.get("task_rows")
    if not rows:  # older summaries: rebuild rows from task results
        rows = [{"task_id": r["task_id"], "quality": r.get("quality_score", 0.0),
                 "efficiency": r.get("efficiency_score", 0.0), "reward": r.get("total_reward", 0.0),
                 "calls": r.get("tool_calls", 0), "completion": r.get("completion_reason"),
                 "platform": None, "expected_verdict": None, "verdict": None}
                for r in summary.get("task_results", [])]
    metrics = summary.get("metrics") or {"overall": _group(rows)}
    return {"label": (summary.get("config") or {}).get("label") or folder.name,
            "config": summary.get("config") or {}, "metrics": metrics, "rows": rows,
            "folder": str(folder)}


def _mean(xs: list[float]) -> float | None:
    return sum(xs) / len(xs) if xs else None


def _group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    judged = [r for r in rows if r.get("expected_verdict") in ("malicious", "benign")]
    benign = [r for r in judged if r["expected_verdict"] == "benign"]
    mal = [r for r in judged if r["expected_verdict"] == "malicious"]
    return {
        "tasks": len(rows),
        "mean_quality": _mean([float(r["quality"]) for r in rows]),
        "mean_efficiency": _mean([float(r["efficiency"]) for r in rows]),
        "mean_reward": _mean([float(r["reward"]) for r in rows]),
        "mean_tool_calls": _mean([float(r["calls"]) for r in rows]),
        "verdict_accuracy": _mean([float(r.get("verdict") == r["expected_verdict"]) for r in judged]),
        "false_positive_rate": _mean([float(r.get("verdict") == "malicious") for r in benign]),
        "false_negative_rate": _mean([float(r.get("verdict") == "benign") for r in mal]),
    }


def load_pilot(folder: Path) -> dict[str, Any]:
    rows = list(csv.DictReader(open(folder / "per_task.csv")))
    for r in rows:
        r["verdict"] = r["expected_verdict"] if float(r["quality"]) > 0 else None
    summary = json.loads((folder / "summary.json").read_text())
    metrics = _group(rows)
    # The run's own printed means are exact; per-task values in the CSV are rounded.
    for k in ("mean_quality", "mean_efficiency", "mean_reward", "mean_tool_calls"):
        if isinstance(summary.get(k), (int, float)):
            metrics[k] = float(summary[k])
    return {"rows": rows, "summary": summary, "metrics": metrics}


# ---------------------------------------------------------------- formatting
def fmt(v: float | None, nd: int) -> str:
    return "--" if v is None or (isinstance(v, float) and math.isnan(v)) else f"{v:.{nd}f}"


def fmt_ms(values: list[float], nd: int) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "--"
    if len(vals) == 1:
        return fmt(vals[0], nd)
    return f"{statistics.mean(vals):.{nd}f}\\,$\\pm$\\,{statistics.stdev(vals):.{nd}f}"


def tex_escape(s: str) -> str:
    out = str(s)
    for a, b in (("\\", "\\textbackslash{}"), ("&", "\\&"), ("%", "\\%"), ("$", "\\$"),
                 ("#", "\\#"), ("_", "\\_"), ("{", "\\{"), ("}", "\\}"), ("~", "\\textasciitilde{}"),
                 ("^", "\\textasciicircum{}")):
        out = out.replace(a, b)
    return out


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def pending_table(caption: str, label: str) -> str:
    return (f"\\begin{{table}}[t]\\centering\\caption{{{caption}}}\\label{{{label}}}\n"
            "\\begin{tabular}{p{0.92\\columnwidth}}\\toprule\n"
            "\\textit{Pending: generated by \\texttt{scripts/results\\_to\\_tex.py} from the study runs.}\\\\\n"
            "\\bottomrule\\end{tabular}\\end{table}\n")


# ---------------------------------------------------------------- tables
def pilot_tables(p: dict[str, Any], out: Path, macros: dict[str, str]) -> None:
    rows, m = p["rows"], p["metrics"]
    with open(out / "data" / "pilot_per_task.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["task", "expected", "quality", "efficiency", "reward", "calls", "optimal"])
        for r in rows:
            w.writerow([r["task_id"], r["expected_verdict"], r["quality"], r["efficiency"],
                        r["reward"], r["calls"], r.get("optimal", "")])
    lines = [
        "\\begin{table}[t]\\centering\\footnotesize",
        "\\caption{Pilot run on the 11 Windows tasks (Claude Opus 5.5, effort \\emph{high}, "
        "full configuration). Quality is 0 for a wrong verdict, so every verdict here was correct.}",
        "\\label{tab:pilot}",
        "\\resizebox{\\columnwidth}{!}{%",
        "\\begin{tabular}{@{}llrrrr@{}}\\toprule",
        "Task & Expected & Quality & Effic. & Reward & Calls\\\\\\midrule",
    ]
    for r in rows:
        lines.append(f"\\texttt{{{tex_escape(r['task_id'])}}} & {r['expected_verdict']} & "
                     f"{float(r['quality']):.3f} & {float(r['efficiency']):.3f} & "
                     f"{float(r['reward']):.3f} & {int(float(r['calls']))}\\\\")
    lines += [
        "\\midrule",
        f"Mean & & {m['mean_quality']:.3f} & {m['mean_efficiency']:.3f} & "
        f"{m['mean_reward']:.3f} & {m['mean_tool_calls']:.2f}\\\\",
        "\\bottomrule\\end{tabular}}\\end{table}",
    ]
    write(out / "tables" / "results_pilot.tex", "\n".join(lines) + "\n")
    s = p["summary"]
    macros.update({
        "ResPilotTasks": str(m["tasks"]),
        "ResPilotQuality": f"{m['mean_quality']:.3f}",
        "ResPilotEfficiency": f"{m['mean_efficiency']:.3f}",
        "ResPilotReward": f"{m['mean_reward']:.3f}",
        "ResPilotCalls": f"{m['mean_tool_calls']:.2f}",
        "ResPilotAccuracy": f"{100 * m['verdict_accuracy']:.0f}\\%",
        "ResPilotWall": f"{s.get('wall_clock_seconds', 0):.0f}",
        "ResPilotMinCalls": str(min(int(float(r["calls"])) for r in rows)),
        "ResPilotMaxCalls": str(max(int(float(r["calls"])) for r in rows)),
    })


def study_tables(runs: list[dict[str, Any]], baseline: str, out: Path,
                 macros: dict[str, str]) -> None:
    by_label: dict[str, list[dict[str, Any]]] = {}
    for r in runs:
        by_label.setdefault(r["label"], []).append(r)
    order = sorted(by_label, key=lambda k: (k != baseline, k))
    base = by_label.get(baseline) or by_label[order[0]]

    def vals(group: list[dict[str, Any]], key: str, slice_: tuple[str, str] | None = None):
        out_ = []
        for r in group:
            m = r["metrics"]
            g = m.get(slice_[0], {}).get(slice_[1]) if slice_ else m.get("overall")
            out_.append((g or {}).get(key))
        return out_

    # runs.csv + main/ablation tables
    with open(out / "data" / "runs.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["configuration", "repeats", "ablations"] + [k for k, _, _ in METRICS]
                   + [f"{k}_sd" for k, _, _ in METRICS] + ["delta_reward", "delta_quality"])
        for lab in order:
            g = by_label[lab]
            means = [_mean([v for v in vals(g, k) if v is not None]) for k, _, _ in METRICS]
            sds = [statistics.stdev([v for v in vals(g, k) if v is not None])
                   if len([v for v in vals(g, k) if v is not None]) > 1 else 0.0 for k, _, _ in METRICS]
            dr = (_mean(vals(g, "mean_reward")) or 0) - (_mean(vals(base, "mean_reward")) or 0)
            dq = (_mean(vals(g, "mean_quality")) or 0) - (_mean(vals(base, "mean_quality")) or 0)
            w.writerow([lab, len(g), "+".join(g[0]["config"].get("ablations", []))]
                       + [None if v is None else round(v, 4) for v in means]
                       + [round(v, 4) for v in sds] + [round(dr, 4), round(dq, 4)])

    head = " & ".join(["Configuration", "$n$"] + [t for _, t, _ in METRICS] + ["$\\Delta$Reward"])
    lines = ["\\begin{table*}[t]\\centering\\footnotesize",
             "\\caption{Ablation study on SOCGraph-21. Each row turns off one component of the full "
             "agent; values are means over repeated runs ($\\pm$ standard deviation when $n>1$). "
             "$\\Delta$Reward is relative to the full configuration on the same tasks.}",
             "\\label{tab:ablation}",
             "\\begin{tabular}{@{}l r " + "r" * len(METRICS) + " r@{}}\\toprule",
             head + "\\\\\\midrule"]
    for lab in order:
        g = by_label[lab]
        dr = (_mean(vals(g, "mean_reward")) or 0) - (_mean(vals(base, "mean_reward")) or 0)
        cells = [fmt_ms(vals(g, k), nd) for k, _, nd in METRICS]
        delta = "--" if g is base else f"{dr:+.3f}"
        lines.append(f"{tex_escape(lab)} & {len(g)} & " + " & ".join(cells) + f" & {delta}\\\\")
    lines += ["\\bottomrule\\end{tabular}\\end{table*}"]
    write(out / "tables" / "results_ablation.tex", "\n".join(lines) + "\n")

    # breakdown by platform and expected verdict
    slices = [("by_platform", "windows", "Windows"), ("by_platform", "linux", "Linux"),
              ("by_expected_verdict", "malicious", "Malicious"),
              ("by_expected_verdict", "benign", "Benign")]
    lines = ["\\begin{table*}[t]\\centering\\footnotesize",
             "\\caption{Quality and verdict accuracy by platform and by expected verdict.}",
             "\\label{tab:breakdown}",
             "\\begin{tabular}{@{}l " + "rr" * len(slices) + "@{}}\\toprule",
             "Configuration & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{t}}}" for _, _, t in slices)
             + "\\\\",
             "".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(slices))),
             " & " + " & ".join(["Qual.", "Acc."] * len(slices)) + "\\\\\\midrule"]
    for lab in order:
        g = by_label[lab]
        cells = []
        for key, val, _ in slices:
            cells.append(fmt_ms(vals(g, "mean_quality", (key, val)), 3))
            cells.append(fmt_ms(vals(g, "verdict_accuracy", (key, val)), 2))
        lines.append(f"{tex_escape(lab)} & " + " & ".join(cells) + "\\\\")
    lines += ["\\bottomrule\\end{tabular}\\end{table*}"]
    write(out / "tables" / "results_breakdown.tex", "\n".join(lines) + "\n")

    # per-task matrix
    tasks = sorted({row["task_id"] for r in runs for row in r["rows"]})
    meta = {row["task_id"]: row for r in runs for row in r["rows"]}
    with open(out / "data" / "per_task.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["task", "platform", "expected"] + [f"{lab}:reward" for lab in order]
                   + [f"{lab}:verdict_acc" for lab in order])
        for t in tasks:
            rew, acc = [], []
            for lab in order:
                rr = [row for r in by_label[lab] for row in r["rows"] if row["task_id"] == t]
                rew.append(_mean([float(x["reward"]) for x in rr]))
                acc.append(_mean([float(x.get("verdict") == x.get("expected_verdict")) for x in rr
                                  if x.get("expected_verdict")]))
            w.writerow([t, meta[t].get("platform"), meta[t].get("expected_verdict")]
                       + [None if v is None else round(v, 4) for v in rew]
                       + [None if v is None else round(v, 4) for v in acc])
    lines = ["\\begin{table*}[t]\\centering\\scriptsize",
             "\\caption{Mean reward per task and configuration. A dagger marks a configuration whose "
             "verdict was wrong in at least one repeat.}",
             "\\label{tab:pertask}",
             "\\begin{tabular}{@{}lll" + "r" * len(order) + "@{}}\\toprule",
             "Task & Platform & Expected & " + " & ".join(tex_escape(lab) for lab in order)
             + "\\\\\\midrule"]
    for t in tasks:
        cells = []
        for lab in order:
            rr = [row for r in by_label[lab] for row in r["rows"] if row["task_id"] == t]
            if not rr:
                cells.append("--")
                continue
            mean_r = _mean([float(x["reward"]) for x in rr])
            wrong = any(x.get("expected_verdict") and x.get("verdict") != x["expected_verdict"]
                        for x in rr)
            cells.append(f"{mean_r:.3f}" + ("$^\\dagger$" if wrong else ""))
        lines.append(f"\\texttt{{{tex_escape(t)}}} & {meta[t].get('platform') or '--'} & "
                     f"{meta[t].get('expected_verdict') or '--'} & " + " & ".join(cells) + "\\\\")
    lines += ["\\bottomrule\\end{tabular}\\end{table*}"]
    write(out / "tables" / "results_per_task.tex", "\n".join(lines) + "\n")

    bm = {k: _mean([v for v in vals(base, k) if v is not None]) for k, _, _ in METRICS}
    macros.update({
        "ResStudyAvailable": "1",
        "ResStudyConfigs": str(len(order)),
        "ResStudyRepeats": str(len(base)),
        "ResStudyTasks": str(base[0]["metrics"]["overall"].get("tasks", "--")),
        "ResFullQuality": fmt(bm["mean_quality"], 3),
        "ResFullEfficiency": fmt(bm["mean_efficiency"], 3),
        "ResFullReward": fmt(bm["mean_reward"], 3),
        "ResFullAccuracy": fmt(None if bm["verdict_accuracy"] is None else 100 * bm["verdict_accuracy"], 0) + "\\%",
        "ResFullFPR": fmt(bm["false_positive_rate"], 3),
        "ResFullFNR": fmt(bm["false_negative_rate"], 3),
        "ResFullCalls": fmt(bm["mean_tool_calls"], 2),
    })


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pilot", type=Path, help="pilot folder (per_task.csv + summary.json)")
    ap.add_argument("--runs", nargs="*", default=[], help="study run folders (globs allowed)")
    ap.add_argument("--baseline", default="full", help="configuration label used as baseline")
    ap.add_argument("--out", type=Path, default=Path("paper"))
    args = ap.parse_args()

    (args.out / "data").mkdir(parents=True, exist_ok=True)
    (args.out / "tables").mkdir(parents=True, exist_ok=True)
    macros: dict[str, str] = {"ResStudyAvailable": "0"}
    if args.pilot:
        pilot_tables(load_pilot(args.pilot), args.out, macros)
    folders = sorted({Path(p) for pat in args.runs for p in glob.glob(pat)
                      if (Path(p) / "summary.json").is_file()})
    if folders:
        study_tables([load_run(f) for f in folders], args.baseline, args.out, macros)
        print(f"study: {len(folders)} run folder(s)")
    else:
        for name, cap, lab in (("results_ablation", "Ablation study on SOCGraph-21.", "tab:ablation"),
                               ("results_breakdown", "Quality and verdict accuracy by platform and "
                                "expected verdict.", "tab:breakdown"),
                               ("results_per_task", "Mean reward per task and configuration.",
                                "tab:pertask")):
            write(args.out / "tables" / f"{name}.tex", pending_table(cap, lab))
        print("study: no run folders yet; wrote pending tables")
    lines = ["% Generated by scripts/results_to_tex.py; do not edit by hand."]
    for k, v in sorted(macros.items()):
        lines.append(f"\\providecommand{{\\{k}}}{{}}\\renewcommand{{\\{k}}}{{{v}}}")
    write(args.out / "results_macros.tex", "\n".join(lines) + "\n")
    print(f"wrote tables and macros under {args.out}")


if __name__ == "__main__":
    main()
