#!/usr/bin/env python3
"""Per-call statistics from the study traces: what the safeguards did, what the
runtime rejected, token use, how hosts were cited, and how often submissions
referred to the alert's source field.

    python scripts/trace_stats.py --pack benchmark/socgraph-21-v1.1.zip \
        --runs "results/study/*/" --out paper

Writes tables/safeguards.tex and trace_macros.tex.
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import re
import zipfile
from pathlib import Path
from typing import Any

ORDER = ["full", "no cache", "no validation", "no grounding", "no budget", "no method"]
SOURCE_CUE = re.compile(r"attack_data|Security-Datasets|simulat", re.I)


def camel(label: str) -> str:
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z]+", label) if w)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    with zipfile.ZipFile(args.pack) as zf:
        ids = {}
        for t in json.loads(zf.read("manifest.json"))["tasks"]:
            g = json.loads(zf.read(f"tasks/{t['id']}.json"))["graph"]
            ids[t["id"]] = set(g["entities"]) | set(g["relations"])

    c: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for folder in sorted(glob.glob(args.runs)):
        summary = json.loads((Path(folder) / "summary.json").read_text())
        lab = summary["config"]["label"]
        for tf in sorted(Path(summary["trace_folder"]).glob("*.json")):
            if tf.name == "summary.json":
                continue
            t: dict[str, Any] = json.loads(tf.read_text())
            k = c[lab]
            k["tasks"] += 1
            u = t.get("usage") or {}
            for f in ("input", "output", "cache_read", "cache_write", "llm_calls"):
                k[f"tok_{f}"] += int(u.get(f, 0) or 0)
            for st in t.get("steps", []):
                if st.get("type") != "tool_call":
                    continue
                status, res = st.get("status"), st.get("result", "")
                if status == "cached":
                    k["cache"] += 1
                elif status == "refused_locally":
                    if res.startswith("Arguments do not match"):
                        k["validation"] += 1
                    elif "never appeared" in res:
                        k["grounding"] += 1
                    else:
                        k["budget_time"] += 1
                elif status == "error" and ("Invalid arguments" in res or "Malformed" in res):
                    k["runtime_schema"] += 1
            sub = t.get("submission") if isinstance(t.get("submission"), dict) else {}
            if t["result"].get("completion_reason") == "terminated" and sub:
                k["submissions"] += 1
                text = " ".join(str(sub.get(x, "")) for x in ("reasoning", "summary"))
                if SOURCE_CUE.search(text):
                    k["source_cue"] += 1
                    meta = t.get("task_meta") or {}
                    right = sub.get("verdict") == meta.get("expected_verdict")
                    k["source_cue_right" if right else "source_cue_wrong"] += 1
                arts = sub.get("ir_artifacts") or []
                if arts:
                    k["mal_subs"] += 1
                    k["host_by_id"] += any(str(a.get("entity_id", "")).startswith("host-") for a in arts)
                    k["host_by_name"] += any(a.get("kind") == "host_to_isolate"
                                             and a.get("entity_id") not in ids[t["task_id"]] for a in arts)
                    k["non_id_artifacts"] += sum(a.get("entity_id") not in ids[t["task_id"]] for a in arts)
                    k["artifacts"] += len(arts)

    labels = [lab for lab in ORDER if lab in c] + sorted(set(c) - set(ORDER))
    lines = ["\\begin{table*}[t]\\centering\\footnotesize",
             "\\caption{What happened at the tool interface, summed over all repeats: calls answered "
             "by the cache, calls refused locally by schema validation, by the grounding check and by "
             "the budget or deadline, and malformed calls the runtime rejected (each spent a call). "
             "Tokens and model calls are means per task; \\emph{Host by id/name}: correct malicious "
             "submissions naming the host by its entity id, or by its hostname.}",
             "\\label{tab:safeguards}",
             "\\begin{tabular}{@{}lrrrrrrrrrr@{}}\\toprule",
             "Configuration & Tasks & Cache & Valid. & Ground. & Budget & Runtime rej. & "
             "Output tok. & Cache-read tok. & Model calls & Host by id/name\\\\\\midrule"]
    macros: dict[str, str] = {}
    for lab in labels:
        k = c[lab]
        n = k["tasks"]
        lines.append(
            f"{lab} & {n} & {k['cache']} & {k['validation']} & {k['grounding']} & {k['budget_time']} & "
            f"{k['runtime_schema']} & {k['tok_output'] / n:,.0f} & {k['tok_cache_read'] / n:,.0f} & "
            f"{k['tok_llm_calls'] / n:.2f} & {k['host_by_id']}/{k['host_by_name']}\\\\".replace(",", "{,}"))
        key = camel(lab)
        for f in ("tasks", "cache", "validation", "grounding", "budget_time", "runtime_schema",
                  "submissions", "source_cue", "source_cue_right", "source_cue_wrong", "mal_subs",
                  "host_by_id", "host_by_name", "non_id_artifacts", "artifacts"):
            macros[f"Tr{key}{camel(f)}"] = str(k[f])
        macros[f"Tr{key}OutTok"] = f"{k['tok_output'] / n:,.0f}".replace(",", "{,}")
        macros[f"Tr{key}CacheReadTok"] = f"{k['tok_cache_read'] / n:,.0f}".replace(",", "{,}")
        macros[f"Tr{key}ModelCalls"] = f"{k['tok_llm_calls'] / n:.2f}"
    tot = collections.Counter()
    for k in c.values():
        tot.update(k)
    for f in ("tasks", "submissions", "source_cue", "source_cue_right", "source_cue_wrong",
              "mal_subs", "host_by_id", "host_by_name", "non_id_artifacts", "artifacts", "cache"):
        macros[f"TrAll{camel(f)}"] = str(tot[f])
    macros["TrAllSourceCuePct"] = f"{100 * tot['source_cue'] / max(1, tot['submissions']):.0f}"
    lines += ["\\bottomrule\\end{tabular}\\end{table*}"]
    (args.out / "tables").mkdir(parents=True, exist_ok=True)
    (args.out / "tables" / "safeguards.tex").write_text("\n".join(lines) + "\n")
    text = ["% Generated by scripts/trace_stats.py; do not edit by hand."]
    text += [f"\\providecommand{{\\{k}}}{{}}\\renewcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items())]
    (args.out / "trace_macros.tex").write_text("\n".join(text) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
