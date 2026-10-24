#!/usr/bin/env python3
"""Compare models on SOCGraph-21 v1.1 and on the mimicry variant.

    python scripts/model_compare.py --pack benchmark/socgraph-21-v1.1.zip \
        --run "Claude Opus 5.5|v1.1|results/study/r*-full/" \
        --run "Claude Opus 5.5|mimicry|results/cues/*-full-mimicry/" \
        --run "GPT-6 astra|v1.1|results/models/*-gpt-6-astra-v1.1/" \
        --run "GPT-6 astra|mimicry|results/models/*-gpt-6-astra-mimicry/" \
        --out paper

Each --run is MODEL|CONDITION|GLOB over run folders (repeats). Writes
tables/models.tex (detection and cost metrics, mean +- sd over repeats),
tables/verdict_matrix.tex (correct verdicts per task and condition),
data/models_radar.csv and data/models_bars.csv (figure data), and
models_macros.tex (paired effects, tests, stability, cue analysis).

Detection metrics treat "malicious" as the positive class. Paired effects are
per-task differences averaged over repeats, with a bootstrap 95% interval over
tasks. Calibration metrics such as ECE need a confidence per verdict, which the
runtime's submission format does not carry, so none are reported.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import random
import re
import statistics
import zipfile
from pathlib import Path
from typing import Any

BOOT = 10000
TEST_CUE = re.compile(r"\b(test|testing|atomic|red[ -]team|simulat\w*|exercise|authori[sz]ed)\b", re.I)


def camel(s: str) -> str:
    """Letters-only key for LaTeX macro names (which cannot contain digits)."""
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z]+", s) if w)


def mkey(model: str) -> str:
    return camel(model.split()[0])


def ckey(cond: str) -> str:
    return "Base" if cond.startswith("v") else camel(cond)


def load(glob_pat: str) -> list[dict[str, Any]]:
    runs = []
    for folder in sorted(glob.glob(glob_pat)):
        p = Path(folder) / "summary.json"
        if p.is_file():
            s = json.loads(p.read_text())
            runs.append({"repeat": s.get("repeat"), "rows": s["task_rows"],
                         "trace_folder": s.get("trace_folder")})
    if not runs:
        raise SystemExit(f"no runs match {glob_pat}")
    return runs


def run_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    tp = sum(r["expected_verdict"] == "malicious" and r.get("verdict") == "malicious" for r in rows)
    fn = sum(r["expected_verdict"] == "malicious" and r.get("verdict") != "malicious" for r in rows)
    fp = sum(r["expected_verdict"] == "benign" and r.get("verdict") == "malicious" for r in rows)
    tn = sum(r["expected_verdict"] == "benign" and r.get("verdict") != "malicious" for r in rows)
    rec = tp / (tp + fn) if tp + fn else 0.0
    spec = tn / (tn + fp) if tn + fp else 0.0
    prec = tp / (tp + fp) if tp + fp else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / den if den else 0.0
    n = len(rows)
    return {
        "quality": statistics.mean(r["quality"] for r in rows),
        "efficiency": statistics.mean(r["efficiency"] for r in rows),
        "reward": statistics.mean(r["reward"] for r in rows),
        "accuracy": (tp + tn) / n, "recall": rec, "specificity": spec, "precision": prec,
        "f1": f1, "mcc": mcc, "balanced": (rec + spec) / 2,
        "calls": statistics.mean(r["calls"] for r in rows),
        "out_tokens": statistics.mean((r.get("usage") or {}).get("output", 0) for r in rows),
        "wall": statistics.mean(r.get("wall_seconds") or 0 for r in rows),
        "fn": fn, "malicious": tp + fn, "fp": fp, "benign": tn + fp,
    }


def ms(vals: list[float], nd: int) -> str:
    if len(vals) == 1:
        return f"{vals[0]:.{nd}f}"
    return f"{statistics.mean(vals):.{nd}f}\\,$\\pm$\\,{statistics.stdev(vals):.{nd}f}"


def per_task(runs: list[dict[str, Any]], key: str) -> dict[str, float]:
    acc: dict[str, list[float]] = {}
    for run in runs:
        for r in run["rows"]:
            v = (float(r.get("verdict") == r["expected_verdict"]) if key == "correct"
                 else float(r[key]))
            acc.setdefault(r["task_id"], []).append(v)
    return {t: statistics.mean(v) for t, v in acc.items()}


def boot_diff(a: dict[str, float], b: dict[str, float]) -> tuple[float, float, float]:
    tasks = sorted(set(a) & set(b))
    d = [a[t] - b[t] for t in tasks]
    rnd = random.Random(20261013)
    bs = sorted(statistics.mean(rnd.choices(d, k=len(d))) for _ in range(BOOT))
    return statistics.mean(d), bs[int(0.025 * BOOT)], bs[int(0.975 * BOOT) - 1]


def boot_did(a1, a0, b1, b0) -> tuple[float, float, float]:
    """(a1 - a0) - (b1 - b0), per task, bootstrap over tasks."""
    tasks = sorted(set(a1) & set(a0) & set(b1) & set(b0))
    d = [(a1[t] - a0[t]) - (b1[t] - b0[t]) for t in tasks]
    rnd = random.Random(20261014)
    bs = sorted(statistics.mean(rnd.choices(d, k=len(d))) for _ in range(BOOT))
    return statistics.mean(d), bs[int(0.025 * BOOT)], bs[int(0.975 * BOOT) - 1]


def fisher(a: int, b: int, c: int, d: int) -> float:
    n, r1, c1 = a + b + c + d, a + b, a + c

    def p(x: int) -> float:
        return math.comb(r1, x) * math.comb(n - r1, c1 - x) / math.comb(n, c1)

    p0 = p(a)
    return min(1.0, sum(p(x) for x in range(max(0, c1 - (n - r1)), min(r1, c1) + 1)
                        if p(x) <= p0 * (1 + 1e-9)))


def stability(runs: list[dict[str, Any]]) -> float:
    verdicts: dict[str, set] = {}
    for run in runs:
        for r in run["rows"]:
            verdicts.setdefault(r["task_id"], set()).add(r.get("verdict"))
    return sum(len(v) == 1 for v in verdicts.values()) / len(verdicts)


def cue_misses(runs: list[dict[str, Any]]) -> tuple[int, int]:
    """Missed attacks, and how many of them justify the benign verdict with test cues."""
    misses = cued = 0
    for run in runs:
        folder = Path(run["trace_folder"])
        for r in run["rows"]:
            if r["expected_verdict"] != "malicious" or r.get("verdict") == "malicious":
                continue
            misses += 1
            f = folder / f"{r['task_id']}.json"
            if f.is_file():
                sub = json.loads(f.read_text()).get("submission") or {}
                text = " ".join(str(sub.get(k, "")) for k in ("reasoning", "summary"))
                cued += bool(TEST_CUE.search(text))
    return misses, cued


def pval(p: float) -> str:
    return "$p<0.001$" if p < 0.001 else f"$p={p:.3f}$"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--run", action="append", required=True, help="MODEL|CONDITION|GLOB")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    with zipfile.ZipFile(args.pack) as zf:
        manifest = json.loads(zf.read("manifest.json"))["tasks"]
    order = [t["id"] for t in manifest]
    meta = {t["id"]: t for t in manifest}

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for spec in args.run:
        model, cond, pat = spec.split("|", 2)
        groups[(model, cond)] = load(pat)
    models = list(dict.fromkeys(m for m, _ in groups))
    conds = list(dict.fromkeys(c for _, c in groups))
    metrics = {k: [run_metrics(r["rows"]) for r in v] for k, v in groups.items()}

    (args.out / "tables").mkdir(parents=True, exist_ok=True)
    (args.out / "data").mkdir(parents=True, exist_ok=True)
    cols = [("quality", "Quality", 3), ("efficiency", "Effic.", 3), ("reward", "Reward", 3),
            ("accuracy", "Acc.", 3), ("recall", "Recall", 3), ("specificity", "Spec.", 3),
            ("f1", "F1", 3), ("mcc", "MCC", 3), ("calls", "Calls", 1),
            ("out_tokens", "Out tok.", 0)]
    lines = ["\\begin{table*}[!t]\\centering\\footnotesize\\setlength{\\tabcolsep}{3.5pt}",
             "\\caption{Two models on \\bench v1.1 and on the \\emph{mimicry} variant, same agent and "
             "settings (full configuration, reasoning effort \\emph{high}). Means $\\pm$ standard "
             "deviation over three repeats. Detection metrics take \\emph{malicious} as the positive "
             "class: recall is the share of attacks caught, specificity the share of benign tasks "
             "cleared; MCC is the Matthews correlation coefficient. \\emph{Out tok.}: output "
             "tokens per task. \\emph{Stable}: share of tasks with the same verdict in all repeats.}",
             "\\label{tab:models}",
             "\\resizebox{\\textwidth}{!}{%",
             "\\begin{tabular}{@{}ll" + "r" * (len(cols) + 1) + "@{}}\\toprule",
             "Model & Pack & " + " & ".join(c[1] for c in cols) + " & Stable\\\\\\midrule"]
    macros: dict[str, str] = {}
    for m in models:
        for c in conds:
            if (m, c) not in metrics:
                continue
            ms_ = metrics[(m, c)]
            cells = [ms([x[k] for x in ms_], nd) for k, _, nd in cols]
            stab = stability(groups[(m, c)])
            lines.append(f"{m} & {c} & " + " & ".join(cells) + f" & {stab:.2f}\\\\")
            key = mkey(m) + ckey(c)
            for k, _, nd in cols:
                macros[f"Mc{key}{camel(k)}"] = f"{statistics.mean(x[k] for x in ms_):.{max(nd, 2) if k != 'out_tokens' else 0}f}"
            macros[f"Mc{key}Stable"] = f"{stab:.2f}"
            fn = sum(x["fn"] for x in ms_)
            mal = sum(x["malicious"] for x in ms_)
            macros[f"Mc{key}Missed"] = f"{fn}/{mal}"
            misses, cued = cue_misses(groups[(m, c)])
            macros[f"Mc{key}CueMisses"] = f"{cued}/{misses}"
        if m != models[-1]:
            lines.append("\\midrule")
    lines += ["\\bottomrule\\end{tabular}}\\end{table*}"]
    (args.out / "tables" / "models.tex").write_text("\n".join(lines) + "\n")

    # Paired effects
    rew = {k: per_task(v, "reward") for k, v in groups.items()}
    cor = {k: per_task(v, "correct") for k, v in groups.items()}
    if len(models) == 2 and "v1.1" in conds:
        a, b = models[1], models[0]
        for c in conds:
            mean, lo, hi = boot_diff(rew[(a, c)], rew[(b, c)])
            macros[f"McDiffReward{ckey(c)}"] = f"{mean:+.3f}"
            macros[f"McDiffReward{ckey(c)}CI"] = f"[{lo:+.3f}, {hi:+.3f}]"
        if "mimicry" in conds:
            for m in models:
                mean, lo, hi = boot_diff(rew[(m, "mimicry")], rew[(m, "v1.1")])
                macros[f"Mc{mkey(m)}MimicryDrop"] = f"{mean:+.3f}"
                macros[f"Mc{mkey(m)}MimicryDropCI"] = f"[{lo:+.3f}, {hi:+.3f}]"
                x0 = metrics[(m, "v1.1")]
                x1 = metrics[(m, "mimicry")]
                f0, n0 = sum(x["fn"] for x in x0), sum(x["malicious"] for x in x0)
                f1, n1 = sum(x["fn"] for x in x1), sum(x["malicious"] for x in x1)
                macros[f"Mc{mkey(m)}MimicryMissP"] = pval(fisher(f1, n1 - f1, f0, n0 - f0))
            mean, lo, hi = boot_did(rew[(a, "mimicry")], rew[(a, "v1.1")],
                                    rew[(b, "mimicry")], rew[(b, "v1.1")])
            macros["McDiD"] = f"{mean:+.3f}"
            macros["McDiDCI"] = f"[{lo:+.3f}, {hi:+.3f}]"
        fa = sum(x["fn"] for x in metrics[(a, "v1.1")])
        na = sum(x["malicious"] for x in metrics[(a, "v1.1")])
        fb = sum(x["fn"] for x in metrics[(b, "v1.1")])
        nb = sum(x["malicious"] for x in metrics[(b, "v1.1")])
        macros["McMissP"] = pval(fisher(fa, na - fa, fb, nb - fb))

    # Per-task verdict matrix
    head = " & ".join(f"\\rotatebox{{70}}{{{m.split()[0]}, {c}}}" for m in models for c in conds
                      if (m, c) in groups)
    rows_tex = []
    for verdict in ("malicious", "benign"):
        rows_tex.append(f"\\multicolumn{{{2 + len(groups)}}}{{@{{}}l}}{{\\emph{{{verdict} tasks}}}}\\\\")
        for t in order:
            if meta[t]["verdict"] != verdict:
                continue
            cells = []
            for m in models:
                for c in conds:
                    if (m, c) not in groups:
                        continue
                    n = len(groups[(m, c)])
                    k = round(cor[(m, c)].get(t, 0) * n)
                    wrong = n - k
                    shade = ("green!20" if wrong == 0 else "orange!30" if wrong == 1
                             else "red!25" if wrong == 2 else "red!50")
                    cells.append(f"\\cellcolor{{{shade}}}{k}/{n}")
            rows_tex.append(f"\\texttt{{{t.replace('_', '-')}}} & {meta[t]['platform'][:3]} & " + " & ".join(cells) + "\\\\")
    mat = ["\\begin{table}[t]\\centering\\scriptsize\\setlength{\\tabcolsep}{3pt}",
           "\\caption{Correct verdicts per task (out of three repeats) for each model and pack. "
           "Green: always correct; orange: wrong once; red: wrong in two or all three repeats.}",
           "\\label{tab:verdictmatrix}",
           "\\begin{tabular}{@{}ll" + "c" * len(groups) + "@{}}\\toprule",
           "Task & OS & " + head + "\\\\\\midrule", *rows_tex, "\\bottomrule\\end{tabular}\\end{table}"]
    (args.out / "tables" / "verdict_matrix.tex").write_text("\n".join(mat) + "\n")

    # Figure data
    with open(args.out / "data" / "models_bars.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["condition"] + [f"{mkey(m)}_{s}" for m in models for s in ("reward", "reward_sd", "recall", "recall_sd")])
        for c in conds:
            row = [c]
            for m in models:
                xs = metrics.get((m, c)) or []
                for k in ("reward", "recall"):
                    vals = [x[k] for x in xs]
                    row += [round(statistics.mean(vals), 4) if vals else "",
                            round(statistics.stdev(vals), 4) if len(vals) > 1 else 0]
            w.writerow(row)
    axes = [("accuracy", "v1.1", "Accuracy"), ("recall", "v1.1", "Recall"),
            ("specificity", "v1.1", "Specificity"), ("quality", "v1.1", "Quality"),
            ("efficiency", "v1.1", "Efficiency"), ("recall", "mimicry", "Recall (mimicry)")]
    with open(args.out / "data" / "models_radar.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["angle", "axis"] + [mkey(m) for m in models])
        for i, (k, c, name) in enumerate(axes + axes[:1]):
            vals = [round(statistics.mean(x[k] for x in metrics[(m, c)]), 4) for m in models]
            w.writerow([round(360 * i / len(axes), 2), name] + vals)
    macros["McModelA"] = models[0]
    macros["McModelB"] = models[1] if len(models) > 1 else ""
    text = ["% Generated by scripts/model_compare.py; do not edit by hand."]
    text += [f"\\providecommand{{\\{k}}}{{}}\\renewcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items())]
    (args.out / "models_macros.tex").write_text("\n".join(text) + "\n")
    print("\n".join(lines))
    print(open(args.out / "models_macros.tex").read())


if __name__ == "__main__":
    main()
