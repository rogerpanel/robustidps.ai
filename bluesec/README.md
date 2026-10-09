# RobustIDPS agent for BlueSec1

An investigation agent for the BlueSec1 runtime. It is installed into a clone
of the organisers' reference agent
(<https://github.com/False-Positive-Community/bluesec1-agent>). Their runtime
client and their reference agent stay exactly as published; this adds
`src/bluesec1_agent/robust/` next to them.

## What it changes compared with the reference agent

| | Reference agent | This agent |
|---|---|---|
| Tool calls | one per LLM turn, through a fixed JSON wrapper | native tool calling, built from each task's `available_tools`; independent calls can share a turn |
| Repeated call | spent again | answered from a local cache, nothing spent |
| Bad arguments | sent, spent, then the error comes back | validated locally against the advertised schema first (an unchanged retry is still sent, so the server stays the authority) |
| Invented ids in the submission | sent as is | one local warning listing ids never seen in the alert or any result |
| Budget | 100 steps, then the task fails | soft budget (told to wrap up) and a hard cap (evidence calls refused, so it submits instead of failing) |
| Method | general rules | competing hypotheses including a benign one, a decisive call per hypothesis, a per-kind guide to `ir_artifacts` and `legitimacy_evidence` |
| Models | any OpenAI-compatible | Claude (adaptive thinking, effort, prompt caching, server-side fallback) or any OpenAI-compatible |
| Record | log lines | `traces/<run>/<task>.json`: every call with its reasoning, cached and refused calls, the submission and the server's quality and efficiency scores; plus `summary.json` |

## Run it on the server

Run it on the Hetzner server, over SSH, inside `tmux`. If the SSH session
drops and kills the agent, the run stays open on the competition side until it
is released, and you cannot start another one.

```bash
# 0. uv (skip if `uv --version` works)
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.local/bin/env

# 1. the organisers' agent, next to the robustidps.ai checkout
cd ~ && git clone https://github.com/False-Positive-Community/bluesec1-agent.git
cd ~/robustidps.ai && git pull            # use your actual checkout path

# 2. add this agent to it, install, run all tests
bash ~/robustidps.ai/bluesec/install.sh ~/bluesec1-agent
cd ~/bluesec1-agent
uv sync
uv run --with anthropic --with jsonschema pytest

# 3. configuration
cp .env.example .env
nano .env    # SCENARIO_RUNTIME_TOKEN from bluesec.team, plus the lines in
             # ~/robustidps.ai/bluesec/env.robust.example (ANTHROPIC_API_KEY, ...)
chmod 600 .env

# 4. offline check: real model, built-in mock tasks, no competition run used
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --mock

# 5. practice arena, then read the traces
tmux new -s bluesec
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --arena practice
```

If tasks abort with `model refused: ...`, run the probe. It sends only the
first request in three variants and shows which one is declined (a few cents):

```bash
uv run --with anthropic --with jsonschema --env-file .env python -m bluesec1_agent.robust.probe
```

The runtime's free-text fields are called `reasoning`. Claude declines
requests that ask it to write out its reasoning (`reasoning_extraction`), so
the model sees them as `purpose` (what a call checks) and `summary` (the
incident summary), and they are renamed back to `reasoning` before sending.

Options: `--provider openai` (uses `LLM_BASE_URL`, `LLM_API_KEY`,
`LLM_DEFAULT_MODEL`), `--model`, `--effort low|medium|high|xhigh|max`,
`--agent-name`, `--arena`.

The original agent still runs as before with `uv run --env-file .env bluesec1-agent`.
(The moderator's note says `uv launch`; the command is `uv run`.)

## Improving between runs

The leaderboard keeps your current result, so iterate on the practice arena:

1. Open `traces/<run>/summary.json` and sort tasks by `quality_score`.
2. For a low-quality task, read its trace: wrong verdict, missing artifacts,
   wrong `kind`, or legitimacy evidence citing the wrong fields.
3. For a low-efficiency task, look for calls whose result changed nothing.
4. Adjust `SYSTEM_PROMPT` in `src/bluesec1_agent/robust/prompt.py` (or in
   this repo and reinstall), or the budgets in `.env`, and run again.
