#!/usr/bin/env python3
"""Does the recommended remedy work? (RQ7)

Evaluate two defences against attacker-chosen names, on the same tasks and agent:
  canon      name-blind canonicalisation: operator-chosen artefacts (in any spelling) are mapped to stable
             tokens before the agent sees the graph, so canon(v1.1) and canon(mimicry) are identical
             (scripts/make_variants.py). The agent must decide from behaviour, not names.
  name-rule  an explicit system-prompt rule that names are attacker-controlled and a benign verdict needs
             behavioural evidence (agent flag --name-rule), evaluated on the mimicry pack.

Against the v1.1 and mimicry baselines (already run), this measures whether a defence recovers the attacks that
renaming hid, and at what cost in false positives and quality.

    python scripts/remedy.py \
        --cond "Claude Opus 5.5|v1.1|results/study/r*-full/" \
        --cond "Claude Opus 5.5|mimicry|results/cues/*-full-mimicry/" \
        --cond "Claude Opus 5.5|canon|results/remedy/claude-*-canon/" \
        --cond "Claude Opus 5.5|name-rule|results/remedy/claude-*-namerule-mimicry/" \
        --cond "GPT-6 astra|v1.1|results/models/*-gpt-6-astra-v1.1/" \
        --cond "GPT-6 astra|mimicry|results/models/*-gpt-6-astra-mimicry/" \
        --cond "GPT-6 astra|canon|results/remedy/gpt-*-canon/" \
        --cond "GPT-6 astra|name-rule|results/remedy/gpt-*-namerule-mimicry/" \
        --out paper

With no --cond runs present, a "pending" table and the macros are written so the paper still compiles.
"""
from __future__ import annotations

import argparse
import glob
import itertools
import json
import re
import statistics
from pathlib import Path
from typing import Any

CONDS = ["v1.1", "mimicry", "canon", "name-rule"]
LABELS = {"v1.1": "v1.1 (names present)", "mimicry": "mimicry (renamed)",
          "canon": "+ canonicalisation", "name-rule": "+ name rule (on mimicry)"}


def camel(s: str) -> str:
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z]+", s) if w)


def load(pat: str) -> list[list[dict[str, Any]]]:
    runs = []
    for folder in sorted(glob.glob(pat)):
        p = Path(folder) / "summary.json"
        if p.is_file():
            runs.append(json.loads(p.read_text())["task_rows"])
    return runs


def metrics(runs: list[list[dict[str, Any]]]) -> dict[str, Any]:
    miss: dict[str, list[float]] = {}
    fp: dict[str, list[float]] = {}
    qual, caught_by_task = [], {}
    for rows in runs:
        for r in rows:
            if r.get("expected_verdict") == "malicious":
                m = float(r.get("verdict") != "malicious")
                miss.setdefault(r["task_id"], []).append(m)
                caught_by_task.setdefault(r["task_id"], []).append(1 - m)
            elif r.get("expected_verdict") == "benign":
                fp.setdefault(r["task_id"], []).append(float(r.get("verdict") == "malicious"))
            qual.append(float(r.get("quality", 0.0)))
    reps = len(runs)
    missed = round(sum(statistics.mean(v) for v in miss.values()) * reps)
    mal = len(miss) * reps
    false = round(sum(statistics.mean(v) for v in fp.values()) * reps)
    ben = len(fp) * reps
    return {"miss_by_task": {t: statistics.mean(v) for t, v in miss.items()},
            "recall": 1 - (missed / mal) if mal else 0.0, "missed": missed, "malicious": mal,
            "fpr": false / ben if ben else 0.0, "false": false, "benign": ben,
            "quality": statistics.mean(qual) if qual else 0.0, "reps": reps,
            "caught": {t: statistics.mean(v) for t, v in caught_by_task.items()}}


def signflip_p(diffs: list[float]) -> float:
    d = [x for x in diffs if abs(x) > 1e-12]
    k = len(d)
    if k == 0:
        return 1.0
    obs = abs(sum(d))
    hits = sum(abs(sum(s * x for s, x in zip(sg, d))) >= obs - 1e-12 for sg in itertools.product((1, -1), repeat=k))
    return min(1.0, hits / 2 ** k)


def pval(p: float) -> str:
    return "$p<0.001$" if p < 0.001 else f"$p={p:.3f}$"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cond", action="append", default=[], help="MODEL|CONDITION|GLOB")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    (args.out / "tables").mkdir(parents=True, exist_ok=True)

    groups: dict[tuple[str, str], list[list[dict[str, Any]]]] = {}
    for spec in args.cond:
        model, cond, pat = spec.split("|", 2)
        runs = load(pat)
        if runs:
            groups[(model, cond)] = runs
    models = list(dict.fromkeys(m for m, _ in groups))
    macros: dict[str, str] = {}

    have_remedy = any(c in ("canon", "name-rule") for _, c in groups)
    if not have_remedy:
        macros["ResRemedyAvailable"] = "0"
        (args.out / "tables" / "remedy.tex").write_text(
            "% No remedy runs yet; see scripts/remedy.py and LIVE_RUNS equivalent.\n"
            "\\begin{table}[t]\\centering\\caption{Defences against attacker-chosen names (RQ7): to be added "
            "once the runs complete.}\\label{tab:remedy}\\begin{tabular}{@{}l@{}}\\toprule Pending\\\\\\bottomrule"
            "\\end{tabular}\\end{table}\n")
        write_macros(args.out / "remedy_macros.tex", macros)
        print("no remedy runs found; wrote pending table and macros")
        return

    macros["ResRemedyAvailable"] = "1"
    met = {k: metrics(v) for k, v in groups.items()}
    lines = ["\\begin{table}[t]\\centering\\footnotesize\\setlength{\\tabcolsep}{4pt}",
             "\\caption{Defences against attacker-chosen names (RQ7), same agent and tasks. "
             "\\emph{Canonicalisation} maps operator-chosen names to stable tokens before the agent reads the "
             "graph (so the v1.1 and mimicry inputs coincide); \\emph{name rule} adds a prompt rule that names "
             "are attacker-controlled, on the mimicry pack. Recall is the share of attacks caught, FPR the "
             "share of benign tasks flagged; \\emph{recovered} is attacks missed under mimicry but caught here. "
             "Means over three repeats.}",
             "\\label{tab:remedy}",
             "\\begin{tabular}{@{}llrrrr@{}}\\toprule",
             "Model & Condition & Recall & FPR & Quality & Recovered\\\\\\midrule"]
    for m in models:
        for c in CONDS:
            if (m, c) not in met:
                continue
            x = met[(m, c)]
            key = camel(m.split()[0]) + camel(c)
            recovered = "--"
            if c in ("canon", "name-rule") and (m, "mimicry") in met:
                mm = met[(m, "mimicry")]
                rec = sum(1 for t in x["caught"] if x["caught"][t] > 0.5 and mm["caught"].get(t, 1) < 0.5)
                recovered = f"{rec}/{mm['missed']}"
                macros[f"Res{key}Recovered"] = recovered
                # clustered paired test of miss rate vs mimicry
                tasks = sorted(set(x["miss_by_task"]) & set(mm["miss_by_task"]))
                cp = signflip_p([x["miss_by_task"][t] - mm["miss_by_task"][t] for t in tasks])
                macros[f"Res{key}VsMimicryClusterP"] = pval(cp)
            lines.append(f"{m} & {LABELS[c]} & {x['recall']:.3f} & {x['fpr']:.3f} & {x['quality']:.3f} "
                         f"& {recovered}\\\\")
            macros[f"Res{key}Recall"] = f"{x['recall']:.3f}"
            macros[f"Res{key}Fpr"] = f"{x['fpr']:.3f}"
            macros[f"Res{key}Missed"] = f"{x['missed']}/{x['malicious']}"
            macros[f"Res{key}Quality"] = f"{x['quality']:.3f}"
        if m != models[-1]:
            lines.append("\\midrule")
    lines += ["\\bottomrule\\end{tabular}\\end{table}"]
    (args.out / "tables" / "remedy.tex").write_text("\n".join(lines) + "\n")
    write_macros(args.out / "remedy_macros.tex", macros)
    print(f"wrote remedy table and {len(macros)} macros for models {models}")


def write_macros(path: Path, macros: dict[str, str]) -> None:
    out = ["% Generated by scripts/remedy.py; do not edit by hand."]
    for k in sorted(macros):
        out.append(f"\\providecommand{{\\{k}}}{{}}\\renewcommand{{\\{k}}}{{{macros[k]}}}")
    path.write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
