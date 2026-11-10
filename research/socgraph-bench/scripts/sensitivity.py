#!/usr/bin/env python3
"""Scoring sensitivity: rescore the study's submissions under alternative rules.

The benchmark's scorer is fixed (v1.1). This script asks how much of the
quality the agent loses is due to two choices that a different but defensible
scorer could make, and writes the answer as a table and macros for the paper:

  official   the v1.1 scorer (reproduces the runs' recorded quality exactly)
  relations  benign tasks: relations between lineage entities, and relations
             of the triggering process, are neutral like the lineage itself
  hostnames  a host named by its hostname instead of its entity id counts as
             that host entity
  both       both changes

    python scripts/sensitivity.py --pack benchmark/socgraph-21-v1.1.zip \
        --runs "results/study/*/" --out paper

The rules in `score()` mirror agent/robust/localdata/runtime.py; the script
checks that the official variant reproduces every recorded quality.
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
import zipfile
from pathlib import Path
from typing import Any

KINDS = {
    "host": {"host_to_isolate"},
    "windows_user": {"identity_to_rotate", "identity_observed"},
    "linux_user": {"identity_to_rotate", "identity_observed"},
    "windows_process": {"process_observed", "cleanup_to_verify", "other"},
    "linux_process": {"process_observed", "cleanup_to_verify", "other"},
    "windows_file": {"file_to_delete", "file_observed", "persistence_to_remove", "cleanup_to_verify"},
    "linux_file": {"file_to_delete", "file_observed", "persistence_to_remove", "cleanup_to_verify"},
    "registry_key": {"persistence_to_remove", "registry_observed", "cleanup_to_verify"},
    "network_connection": {"network_block", "artifact_observed"},
    "scheduled_task": {"persistence_to_remove"},
    "windows_service": {"persistence_to_remove"},
    "named_pipe": {"artifact_observed"},
}
NON_EVIDENCE = {"count", "last_seen", "timestamp", "process_guid", "hostname", "process_id"}
VARIANTS = ("official", "relations", "hostnames", "both")


def load_pack(path: Path) -> dict[str, dict[str, Any]]:
    out = {}
    with zipfile.ZipFile(path) as zf:
        for t in json.loads(zf.read("manifest.json"))["tasks"]:
            rec = json.loads(zf.read(f"tasks/{t['id']}.json"))
            ans = json.loads(zf.read(f"answers/{t['id']}.json"))
            ents, rels = rec["graph"]["entities"], rec["graph"]["relations"]
            hosts = {e.get("hostname", "").lower(): i for i, e in ents.items()
                     if e.get("type") == "host" and e.get("hostname")}
            # hostnames may also be cited fully qualified or short
            for name, i in list(hosts.items()):
                hosts.setdefault(name.split(".")[0], i)
            lineage = set(ans.get("neutral", [])) | set(ans.get("evidence_fields", {}))
            trigger = rec["alert"]["trigger_entities"][0]
            extra = {rid for rid, r in rels.items()
                     if (r["source"] in lineage and r["target"] in lineage) or r["source"] == trigger}
            out[t["id"]] = {"ents": ents, "verdict": ans["verdict"], "core": set(ans["core"]),
                            "acceptable": set(ans["acceptable"]),
                            "evidence": {k: set(v) for k, v in ans.get("evidence_fields", {}).items()},
                            "neutral": set(ans.get("neutral", [])), "neutral_rel": extra,
                            "hosts": hosts, "platform": t["platform"]}
    return out


def score(task: dict[str, Any], sub: dict[str, Any], variant: str) -> float:
    rel_rule = variant in ("relations", "both")
    host_rule = variant in ("hostnames", "both")

    def resolve(x: Any) -> Any:
        if host_rule and isinstance(x, str) and x not in task["ents"]:
            return task["hosts"].get(x.lower(), task["hosts"].get(x.lower().split(".")[0], x))
        return x

    if sub.get("verdict") != task["verdict"]:
        return 0.0
    if task["verdict"] == "malicious":
        cited: dict[str, float] = {}
        for a in sub.get("ir_artifacts") or []:
            eid, kind = resolve(a.get("entity_id")), a.get("kind")
            ent = task["ents"].get(eid) or {}
            credit = 1.0 if kind in KINDS.get(ent.get("type", ""), set()) else 0.5
            cited[eid] = max(cited.get(eid, 0.0), credit)
        recall = sum(cited.get(i, 0.0) for i in task["core"]) / len(task["core"])
        precision = (sum(1 for i in cited if i in task["acceptable"]) / len(cited)) if cited else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return 0.5 + 0.5 * f1
    neutral = task["neutral"] | (task["neutral_rel"] if rel_rule else set())
    hits, outside = set(), 0
    for ev in sub.get("legitimacy_evidence") or []:
        anchor = resolve(ev.get("entity_id") or ev.get("relation_id"))
        fields = set(ev.get("property_fields") or [])
        valid = task["evidence"].get(anchor, set()) - NON_EVIDENCE
        if anchor in task["evidence"]:
            if fields & valid or (ev.get("anchor") == "relation" and not fields):
                hits.add(anchor)
        elif anchor not in neutral:
            outside += 1
    coverage = len(hits) / len(task["evidence"])
    penalty = outside / (len(hits) + outside) if hits or outside else 0.0
    return 0.5 + 0.5 * max(0.0, coverage - 0.5 * penalty)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--runs", required=True, help="glob of study run folders")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--label", default="full", help="configuration to report")
    args = ap.parse_args()
    tasks = load_pack(args.pack)
    rows: list[dict[str, Any]] = []
    for folder in sorted(glob.glob(args.runs)):
        summary = json.loads((Path(folder) / "summary.json").read_text())
        if summary["config"]["label"] != args.label:
            continue
        trace_dir = Path(summary["trace_folder"])
        for tf in sorted(trace_dir.glob("*.json")):
            if tf.name == "summary.json":
                continue
            tr = json.loads(tf.read_text())
            task = tasks[tr["task_id"]]
            done = tr["result"]["completion_reason"] == "terminated" and isinstance(tr.get("submission"), dict)
            q = {v: (score(task, tr["submission"], v) if done else 0.0) for v in VARIANTS}
            recorded = {r["task_id"]: r["quality"] for r in summary["task_rows"]}[tr["task_id"]]
            if abs(round(q["official"], 4) - recorded) > 1e-4:
                raise SystemExit(f"{tf}: official rescoring {q['official']:.4f} != recorded {recorded}")
            rows.append({"task": tr["task_id"], "platform": task["platform"],
                         "verdict": task["verdict"], **q})
    if not rows:
        raise SystemExit("no task traces found")

    def mean(variant: str, **filt: str) -> float:
        sel = [r[variant] for r in rows if all(r[k] == v for k, v in filt.items())]
        return statistics.mean(sel)

    groups = [("All", {}), ("Windows", {"platform": "windows"}), ("Linux", {"platform": "linux"}),
              ("Malicious", {"verdict": "malicious"}), ("Benign", {"verdict": "benign"})]
    names = {"official": "Official (v1.1)", "relations": "+ lineage relations neutral",
             "hostnames": "+ hostnames accepted", "both": "+ both"}
    lines = ["\\begin{table}[t]\\centering\\footnotesize",
             f"\\caption{{Scoring sensitivity: mean quality of the {args.label} agent's "
             f"{len(rows)} submissions rescored under alternative rules (no new model calls).}}",
             "\\label{tab:sensitivity}", "\\resizebox{\\columnwidth}{!}{%",
             "\\begin{tabular}{@{}l" + "r" * len(groups) + "@{}}\\toprule",
             "Scoring rule & " + " & ".join(g for g, _ in groups) + "\\\\\\midrule"]
    macros = {}
    for v in VARIANTS:
        vals = [mean(v, **f) for _, f in groups]
        lines.append(f"{names[v]} & " + " & ".join(f"{x:.3f}" for x in vals) + "\\\\")
        key = v.capitalize()
        for (g, _), x in zip(groups, vals):
            macros[f"Sens{key}{g}"] = f"{x:.3f}"
    lines += ["\\bottomrule\\end{tabular}}\\end{table}"]
    (args.out / "tables").mkdir(parents=True, exist_ok=True)
    (args.out / "tables" / "sensitivity.tex").write_text("\n".join(lines) + "\n")
    text = ["% Generated by scripts/sensitivity.py; do not edit by hand."]
    text += [f"\\providecommand{{\\{k}}}{{}}\\renewcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items())]
    (args.out / "sensitivity_macros.tex").write_text("\n".join(text) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
