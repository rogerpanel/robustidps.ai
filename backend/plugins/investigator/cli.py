"""Run investigations from the command line, without the web app.

    cd backend
    python -m plugins.investigator.cli --list
    python -m plugins.investigator.cli --mission m01-svc-backup-lockouts --provider deepseek
    python -m plugins.investigator.cli --all --provider anthropic --max-tool-calls 12

Keys come from ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY /
DEEPSEEK_API_KEY. Use --all to compare agent versions across every
practice mission.
"""
from __future__ import annotations

import argparse
import json
import sys

from .agent import DEFAULT_MODELS, RunConfig, investigate
from .evidence import MissionEvidence
from .missions import load_missions
from .scorer import score


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SOC Investigator")
    ap.add_argument("--list", action="store_true", help="list practice missions")
    ap.add_argument("--mission", help="mission id to run")
    ap.add_argument("--all", action="store_true", help="run every mission and summarise")
    ap.add_argument("--provider", default="anthropic", choices=sorted(DEFAULT_MODELS))
    ap.add_argument("--model")
    ap.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    ap.add_argument("--max-tool-calls", type=int, default=15)
    ap.add_argument("--trace", action="store_true", help="print the full trace as JSON")
    args = ap.parse_args(argv)

    missions = load_missions()
    if args.list:
        for m in missions.values():
            print(f"{m.id:32s} {m.difficulty:8s} {m.title}")
        return 0
    targets = list(missions.values()) if args.all else [missions[args.mission]] if args.mission else []
    if not targets:
        ap.error("give --mission ID, --all, or --list")

    cfg = RunConfig(provider=args.provider, model=args.model, effort=args.effort,
                    max_tool_calls=args.max_tool_calls)
    total = 0.0
    for m in targets:
        trace = investigate(m.brief, MissionEvidence(m), cfg)
        s = score(trace, m.answer, m.optimal_tool_calls)
        verdict = (trace["verdict"] or {}).get("verdict", "-")
        line = f"{m.id:32s} {trace['status']:6s} verdict={verdict:22s} calls={trace['tool_calls']:3d}"
        if s:
            line += f"  score={s['score']:5.1f}  quality={s['quality']:.2f}  eff={s['efficiency']}"
            total += s["score"]
        if trace["error"]:
            line += f"  ERROR {trace['error']}"
        print(line)
        if args.trace:
            print(json.dumps({"trace": trace, "score": s}, indent=2, ensure_ascii=False, default=str))
    if len(targets) > 1:
        print(f"\nmean score: {total / len(targets):.1f} over {len(targets)} missions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
