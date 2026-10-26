"""Live-model evaluation on AgentDojo: real Claude or GPT agents, with and without Agent Guard.

Conditions (per model):
  none            no filter (AgentDojo's own executor)
  guard           Agent Guard in front of every tool call; a call that needs approval is blocked,
                  because no person is present in a benchmark (unattended deployment)
  guard-approve   Agent Guard, and every approval request is approved as if by a person: only the
                  filter's refusals stop calls (local guard only; on the site only a signed-in person
                  can approve). `guard` and `guard-approve` bracket what real reviewers would do.

The guard runs in this process (`--guard local`) or on a deployed platform (`--guard url`, decisions then
appear in that tenant's Safety Filter ledger and runtime monitor). Its policy is generated per suite from
the tool descriptions, exactly as in the ground-truth replay (agentdojo_eval.py).

Metrics, from AgentDojo's own checks: utility (user task solved, no attack), utility under attack, and
targeted attack success rate (the injection task's goal achieved). Plus the guard's requests and refusals
per task and the tokens each condition used.

API keys are read from the environment (ANTHROPIC_API_KEY, OPENAI_API_KEY, AGENT_GUARD_TOKEN) and are never
written anywhere. Results go to results/live/<run>/ (summary.json, decisions.jsonl, AgentDojo logs).

    # 1. check the pipeline and your key on one task (cents)
    PYTHONPATH=backend python research/agent-guard-bench/harness/live_eval.py run --smoke \\
        --provider anthropic --model claude-sonnet-5-5
    # 2. estimate, then run
    PYTHONPATH=backend python research/agent-guard-bench/harness/live_eval.py run --provider anthropic \\
        --model claude-sonnet-5-5 --suites banking,slack --conditions none,guard,guard-approve --estimate
    # 3. pool every run for the paper
    python research/agent-guard-bench/harness/live_eval.py summarize
"""
from __future__ import annotations

import os as _os
# Isolation: the harness never uses a database. Pin an in-memory one before any backend import, so that the
# backend's config (which loads the repository's .env) can never point it at a production database.
_os.environ["DATABASE_URL"] = "sqlite://"  # AGBENCH_ISOLATE

import argparse
import datetime
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "results" / "live"
sys.path.insert(0, str(Path(__file__).resolve().parent))
REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO / "backend" / "plugins" / "agent_guard" / "integrations"))

BENCHMARK_VERSION = "v1.2"
CONDITIONS = ("none", "guard", "guard-approve")
USAGE: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
_CURRENT = {"condition": ""}


# ── model clients (with token accounting) ────────────────────────────

def _track_usage() -> None:
    """Count tokens per condition by wrapping AgentDojo's request functions."""
    from agentdojo.agent_pipeline.llms import anthropic_llm, openai_llm
    orig_a, orig_o = anthropic_llm.chat_completion_request, openai_llm.chat_completion_request

    async def a_wrapper(*args, **kwargs):
        msg = await orig_a(*args, **kwargs)
        u = getattr(msg, "usage", None)
        if u is not None:
            c = USAGE[_CURRENT["condition"]]
            c["requests"] += 1
            c["input_tokens"] += int(getattr(u, "input_tokens", 0) or 0)
            c["output_tokens"] += int(getattr(u, "output_tokens", 0) or 0)
            c["cache_read_input_tokens"] += int(getattr(u, "cache_read_input_tokens", 0) or 0)
        return msg

    def o_wrapper(*args, **kwargs):
        completion = orig_o(*args, **kwargs)
        u = getattr(completion, "usage", None)
        if u is not None:
            c = USAGE[_CURRENT["condition"]]
            c["requests"] += 1
            c["input_tokens"] += int(getattr(u, "prompt_tokens", 0) or 0)
            c["output_tokens"] += int(getattr(u, "completion_tokens", 0) or 0)
        return completion

    anthropic_llm.chat_completion_request = a_wrapper
    openai_llm.chat_completion_request = o_wrapper


def make_llm(provider: str, model: str, max_tokens: int):
    if provider == "anthropic":
        import anthropic
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY is not set in this shell.")
        # temperature=None: current Claude models reject a temperature parameter (Opus) or any non-default
        # value (Haiku 5.5); AgentDojo's default of 0.0 would fail with HTTP 400. Thinking is left at the
        # model's default; thinking blocks are passed back unchanged by AgentDojo.
        return AnthropicLLM(anthropic.AsyncAnthropic(max_retries=8), model, temperature=None, max_tokens=max_tokens)
    if provider == "openai":
        import openai
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        if not os.environ.get("OPENAI_API_KEY"):
            sys.exit("OPENAI_API_KEY is not set in this shell.")
        return OpenAILLM(openai.OpenAI(max_retries=8), model, temperature=None)
    if provider == "groundtruth":
        return GroundTruthAgent()
    raise SystemExit(f"unknown provider {provider}")


class GroundTruthAgent:
    """A scripted agent that issues the user task's ground-truth calls (for testing the harness without keys).
    It never follows injected instructions, so its attack success rate is 0 by construction."""

    def __new__(cls):
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.logging import Logger
        from agentdojo.task_suite.load_suites import get_suites
        from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

        class _Agent(BasePipelineElement):
            name = "groundtruth"

            def query(self, query, runtime, env, messages=(), extra_args={}):  # noqa: B006
                ctx = dict(getattr(Logger.get(), "context", {}) or {})
                suite = get_suites(BENCHMARK_VERSION)[ctx["suite_name"]]
                tid = ctx["user_task_id"]
                task = suite.user_tasks.get(tid) or suite.injection_tasks.get(tid)
                done = sum(1 for m in messages if m["role"] == "assistant")
                calls = task.ground_truth(env)
                if done < len(calls):
                    c = calls[done]
                    msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")],
                                               tool_calls=[FunctionCall(function=c.function, args=dict(c.args),
                                                                        id=f"gt-{done}")])
                else:
                    answer = getattr(task, "GROUND_TRUTH_OUTPUT", "") or "Done."
                    msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(answer)],
                                               tool_calls=None)
                return query, runtime, env, [*messages, msg], extra_args
        return _Agent()


# ── guard ────────────────────────────────────────────────────────────

def make_guard(mode: str, suite_tools: list[dict], variant: str, condition: str, url: str | None):
    """A GuardedToolsExecutor wired to an in-process guard or to a deployed platform."""
    from agentdojo_eval import generated_policies
    from agentdojo_guard import GuardedToolsExecutor
    policy = generated_policies(suite_tools)[variant]
    on_ask = "approve" if condition == "guard-approve" else "block"
    if mode == "local":
        from plugins.agent_guard.contract import Decision, ProposedCall
        from plugins.agent_guard.engine import SessionStore, commit_let_through, decide
        store = SessionStore()

        def checker(tool, args, session):
            return decide(ProposedCall(session_id=session, tool_name=tool, args=args), policy, store,
                          "live").model_dump()

        def approved(tool, args, session, verdict):
            commit_let_through(store.get("live", session), Decision.model_validate(verdict))
        return GuardedToolsExecutor(checker=checker, on_ask=on_ask, approved=approved,
                                    session_prefix=f"agentdojo-live-{condition}"), policy
    if condition == "guard-approve":
        raise SystemExit("guard-approve needs --guard local: on the platform only a signed-in person can approve.")
    from plugins.agent_guard.client import GuardClient
    token = os.environ.get("AGENT_GUARD_TOKEN", "")
    if not token:
        sys.exit("AGENT_GUARD_TOKEN is not set (an API key for the platform).")
    client = GuardClient(url, token, policy=json.loads(policy.model_dump_json()), timeout=30,
                         framework="agentdojo-live", agent_id=f"agentdojo-live-{variant}")
    return GuardedToolsExecutor(guard=client, on_ask="block", session_prefix="agentdojo-live"), policy


def build_pipeline(llm, executor, name: str):
    from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo_guard import NewGuardSession
    elements = [SystemMessage(load_system_message(None)), InitQuery(), llm,
                ToolsExecutionLoop([executor if executor is not None else ToolsExecutor(), llm])]
    if executor is not None:
        elements.insert(0, NewGuardSession(executor))
    pipe = AgentPipeline(elements)
    pipe.name = name
    return pipe


# ── run ──────────────────────────────────────────────────────────────

def _pick(ids: list[str], spec: str) -> list[str]:
    if spec == "all":
        return ids
    if spec.isdigit():
        return ids[: int(spec)]
    chosen = [s.strip() for s in spec.split(",") if s.strip()]
    unknown = [c for c in chosen if c not in ids]
    if unknown:
        raise SystemExit(f"unknown task ids: {', '.join(unknown)}")
    return chosen


def run(a) -> None:
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
    from agentdojo.models import MODEL_NAMES
    from agentdojo.task_suite.load_suites import get_suites
    from plugins.agent_guard.contract import FILTER_VERSION

    if a.smoke:
        a.suites, a.user_tasks, a.injection_tasks = "banking", "1", "1"
        a.conditions = a.conditions or "none,guard"
    conditions = [c.strip() for c in (a.conditions or "none,guard,guard-approve").split(",")]
    for c in conditions:
        if c not in CONDITIONS:
            raise SystemExit(f"unknown condition {c}; choose from {', '.join(CONDITIONS)}")
    suites = get_suites(BENCHMARK_VERSION)
    names = [s.strip() for s in a.suites.split(",")] if a.suites != "all" else list(suites)
    plan = []
    for n in names:
        s = suites[n]
        ut = _pick(list(s.user_tasks), a.user_tasks)
        it = _pick(list(s.injection_tasks), a.injection_tasks)
        plan.append((n, ut, it))
    runs_per_condition = sum(len(ut) + len(ut) * len(it) + len(it) for _, ut, it in plan)
    total = runs_per_condition * len(conditions)
    print(f"Plan: {a.provider}/{a.model}; suites {', '.join(n for n, _, _ in plan)}; conditions "
          f"{', '.join(conditions)}; {runs_per_condition} agent runs per condition, {total} in total "
          f"(benign tasks, task x attack pairs, and the attack goals run once as tasks, as AgentDojo does).")
    if a.estimate:
        print("Estimate only: rerun without --estimate (and with --yes above 200 runs) to start.")
        return
    if total > 200 and not a.yes and not a.smoke:
        raise SystemExit("More than 200 agent runs: add --yes to confirm (or narrow --suites/--user-tasks).")

    run_id = a.tag or f"{a.provider}-{a.model}-{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
    out = LIVE / run_id
    logdir = out / "logs"
    logdir.mkdir(parents=True, exist_ok=True)
    _track_usage()
    MODEL_NAMES.setdefault(a.model, "Claude" if a.provider == "anthropic" else "GPT" if a.provider == "openai"
                           else "AI assistant")
    summary = {"meta": {"provider": a.provider, "model": a.model, "attack": a.attack, "guard": a.guard,
                        "guard_url": a.guard_url if a.guard == "url" else None, "policy_variant": a.variant,
                        "benchmark_version": BENCHMARK_VERSION, "filter_version": FILTER_VERSION,
                        "max_tokens": a.max_tokens, "smoke": a.smoke,
                        "started": datetime.datetime.utcnow().isoformat() + "Z"},
               "plan": {n: {"user_tasks": ut, "injection_tasks": it} for n, ut, it in plan}, "results": {}}
    decisions_path = out / "decisions.jsonl"
    started = time.time()
    from agentdojo.logging import OutputLogger
    with OutputLogger(str(logdir), live=None):
        _run_conditions(a, conditions, plan, suites, logdir, out, summary, decisions_path, started,
                        load_attack, benchmark_suite_with_injections, benchmark_suite_without_injections)
    write_manifest(out)
    print(f"Done in {round(time.time() - started)} s. Results: {out}")
    print("Tokens:", json.dumps({k: dict(v) for k, v in USAGE.items()}))


def _sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(out: Path) -> dict:
    """Hashes of the run's result files plus the software that produced them, so results sent elsewhere can be
    checked to be exactly what this run wrote (and from which code)."""
    import platform
    import subprocess
    from importlib.metadata import PackageNotFoundError, version

    def ver(pkg):
        try:
            return version(pkg)
        except PackageNotFoundError:
            return None
    try:
        commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                                timeout=10).stdout.strip() or None
        dirty = bool(subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", "backend",
                                     "research/agent-guard-bench/harness"], capture_output=True, text=True,
                                    timeout=10).stdout.strip())
    except Exception:  # noqa: BLE001
        commit, dirty = None, None
    files = {p.name: _sha256(p) for p in sorted(out.glob("*")) if p.is_file() and p.name != "manifest.json"}
    manifest = {"files": files, "git_commit": commit, "code_modified": dirty, "python": platform.python_version(),
                "packages": {k: ver(k) for k in ("agentdojo", "anthropic", "openai")},
                "written": datetime.datetime.utcnow().isoformat() + "Z"}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return manifest


def verify_manifest(run_dir: Path) -> str:
    """'verified', 'no manifest', or what does not match."""
    mpath = run_dir / "manifest.json"
    if not mpath.exists():
        return "no manifest"
    m = json.loads(mpath.read_text())
    bad = [name for name, digest in m["files"].items()
           if not (run_dir / name).exists() or _sha256(run_dir / name) != digest]
    return "verified" if not bad else "changed after the run: " + ", ".join(bad)


def _run_conditions(a, conditions, plan, suites, logdir, out, summary, decisions_path, started,
                    load_attack, benchmark_suite_with_injections, benchmark_suite_without_injections) -> None:
    for condition in conditions:
        _CURRENT["condition"] = condition
        summary["results"][condition] = {}
        for n, ut, it in plan:
            suite = suites[n]
            tools = [{"name": t.name, "description": t.description,
                      "input_schema": t.parameters.model_json_schema()} for t in suite.tools]
            llm = make_llm(a.provider, a.model, a.max_tokens)
            executor = None
            if condition != "none":
                executor, _ = make_guard(a.guard, tools, a.variant, condition, a.guard_url)
            variant_slug = a.variant.replace(" (conservative)", "-conservative").replace("+", "-")
            pipe = build_pipeline(llm, executor, f"{a.model}__{condition}__{variant_slug}")
            print(f"[{condition}] {n}: {len(ut)} tasks without attack ...", flush=True)
            benign = benchmark_suite_without_injections(pipe, suite, logdir, False, user_tasks=ut,
                                                        benchmark_version=BENCHMARK_VERSION)
            attack = load_attack(a.attack, suite, pipe)
            print(f"[{condition}] {n}: {len(ut)} x {len(it)} attacked runs ...", flush=True)
            attacked = benchmark_suite_with_injections(pipe, suite, attack, logdir, False, user_tasks=ut,
                                                       injection_tasks=it, benchmark_version=BENCHMARK_VERSION)
            if executor is not None:
                with decisions_path.open("a") as fh:
                    for d in executor.decisions:
                        fh.write(json.dumps({"condition": condition, **d}, default=str) + "\n")
            u = {k[0]: bool(v) for k, v in benign["utility_results"].items()}
            ua = {f"{k[0]}|{k[1]}": bool(v) for k, v in attacked["utility_results"].items()}
            sa = {f"{k[0]}|{k[1]}": bool(v) for k, v in attacked["security_results"].items()}
            summary["results"][condition][n] = {
                "utility": u, "utility_under_attack": ua, "attack_success": sa,
                "injection_tasks_solved_as_tasks": {k: bool(v) for k, v in
                                                    attacked["injection_tasks_utility_results"].items()}}
            print(f"[{condition}] {n}: utility {sum(u.values())}/{len(u)}, utility under attack "
                  f"{sum(ua.values())}/{len(ua)}, attacks succeeded {sum(sa.values())}/{len(sa)}", flush=True)
            summary["usage"] = {k: dict(v) for k, v in USAGE.items()}
            summary["meta"]["seconds"] = round(time.time() - started, 1)
            (out / "summary.json").write_text(json.dumps(summary, indent=1))


# ── summarize all runs for the paper ─────────────────────────────────

def _wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def summarize(a) -> None:
    rows = []
    for summ in sorted(LIVE.glob("*/summary.json")):
        s = json.loads(summ.read_text())
        if s["meta"].get("smoke") and not a.include_smoke:
            continue
        integrity = verify_manifest(summ.parent)
        print(f"{summ.parent.name}: {integrity}")
        if s["meta"]["provider"] == "groundtruth" and not a.include_smoke:
            continue                       # the scripted agent only tests the harness
        decisions = defaultdict(list)
        dpath = summ.parent / "decisions.jsonl"
        if dpath.exists():
            for line in dpath.read_text().splitlines():
                d = json.loads(line)
                decisions[d["condition"]].append(d)
        for condition, per_suite in s["results"].items():
            u = [v for r in per_suite.values() for v in r["utility"].values()]
            ua = [v for r in per_suite.values() for v in r["utility_under_attack"].values()]
            sa = [v for r in per_suite.values() for v in r["attack_success"].values()]
            ds = decisions.get(condition, [])
            benign = [d for d in ds if d.get("injection_task") in (None, "None")
                      and str(d.get("user_task") or "").startswith("user_task")]
            n_benign = max(1, len(u))
            rows.append({
                "run": summ.parent.name, "integrity": integrity, "provider": s["meta"]["provider"],
                "model": s["meta"]["model"],
                "condition": condition, "guard": s["meta"]["guard"], "policy_variant": s["meta"]["policy_variant"],
                "suites": sorted(per_suite), "filter_version": s["meta"]["filter_version"],
                "n_tasks": len(u), "n_pairs": len(sa),
                "utility": sum(u) / len(u) if u else None, "utility_ci95": _wilson(sum(u), len(u)),
                "utility_under_attack": sum(ua) / len(ua) if ua else None,
                "attack_success": sum(sa) / len(sa) if sa else None, "attack_success_ci95": _wilson(sum(sa), len(sa)),
                "attack_success_count": [sum(sa), len(sa)],
                "guard_asks_per_benign_task": sum(d["decision"] == "ask" for d in benign) / n_benign if ds else None,
                "guard_denies_per_benign_task": sum(d["decision"] == "deny" for d in benign) / n_benign if ds else None,
                "usage": s.get("usage", {}).get(condition, {})})
    LIVE.mkdir(parents=True, exist_ok=True)
    (LIVE / "live_results.json").write_text(json.dumps({"runs": rows}, indent=1))
    for r in rows:
        print(f"{r['model']:28} {r['condition']:14} tasks {r['n_tasks']:3} pairs {r['n_pairs']:4} "
              f"utility {r['utility']} attacked-utility {r['utility_under_attack']} ASR {r['attack_success']}")
    print(f"wrote {LIVE / 'live_results.json'}")
    import live_analysis
    live_analysis.main(include_test_runs=a.include_smoke)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--provider", choices=["anthropic", "openai", "groundtruth"], required=True)
    r.add_argument("--model", required=True, help="model id as your API account names it, e.g. claude-sonnet-5-5")
    r.add_argument("--suites", default="all", help="all, or a comma list of workspace,travel,banking,slack")
    r.add_argument("--user-tasks", default="all", help="all, a number (the first N per suite) or a comma list")
    r.add_argument("--injection-tasks", default="all", help="all, a number or a comma list")
    r.add_argument("--conditions", default=None, help=f"comma list from {', '.join(CONDITIONS)}")
    r.add_argument("--attack", default="important_instructions")
    r.add_argument("--guard", choices=["local", "url"], default="local")
    r.add_argument("--guard-url", default="https://robustidps.ai")
    r.add_argument("--variant", default="tiers+flow (conservative)",
                   choices=["tiers", "tiers+flow", "tiers+flow (conservative)"])
    r.add_argument("--max-tokens", type=int, default=16000)
    r.add_argument("--tag", default=None, help="run folder name (reuse it to resume an interrupted run)")
    r.add_argument("--smoke", action="store_true", help="one banking task and one attack: checks keys and pipeline")
    r.add_argument("--estimate", action="store_true", help="print the number of agent runs and stop")
    r.add_argument("--yes", action="store_true", help="confirm runs above 200 agent runs")
    s = sub.add_parser("summarize")
    s.add_argument("--include-smoke", action="store_true")
    a = ap.parse_args()
    run(a) if a.cmd == "run" else summarize(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
