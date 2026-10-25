# Live-model runs (Claude and GPT on AgentDojo)

These runs give the paper its live-model results (Table "Live models", RQ5). They run on the
server host in their own Python environment, separate from the Docker containers, so the
website is not touched. API keys stay on the server: the harness reads them from the
environment and never writes them to any file.

## 1. One-time setup on the server

```bash
cd ~/robustidps.ai && git pull origin claude/robustidps-dev-continue-0Kln1
python3 --version                      # needs 3.10 or newer
python3 -m venv ~/agbench              # if this fails: sudo apt install python3-venv
~/agbench/bin/pip install "agentdojo==0.1.35" sqlalchemy
```

Put the keys in a file only you can read (type them in the editor, not on the command line,
so they do not land in the shell history):

```bash
nano ~/.agbench.env
```

with these lines (leave out the ones you do not use):

```
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export AGENT_GUARD_TOKEN=...
```

then

```bash
chmod 600 ~/.agbench.env
```

`AGENT_GUARD_TOKEN` is only for step 5 (a rids_live_ key, preferably of a separate account,
see there). Long runs should survive a dropped SSH connection: start them inside `tmux`
(`sudo apt install tmux` if missing; `tmux new -s agbench`, detach with Ctrl+B then D,
reattach with `tmux attach -t agbench`).

## 2. Smoke test (a few cents per provider)

```bash
cd ~/robustidps.ai && source ~/.agbench.env
PYTHONPATH=backend ~/agbench/bin/python research/agent-guard-bench/harness/live_eval.py run --smoke \
    --provider anthropic --model claude-sonnet-5-5
PYTHONPATH=backend ~/agbench/bin/python research/agent-guard-bench/harness/live_eval.py run --smoke \
    --provider openai --model YOUR_GPT_MODEL_ID
```

A smoke test is one banking task and one attack, without and with the guard: 6 agent runs.
It prints a line per step and, at the end, `Tokens: {...}`. Tokens per agent run is about the
total divided by 6, which with the run count from step 3 gives the cost of a full run.
If it fails with an API error, send me the error text (never the key).

GPT model ids: use the id your OpenAI account shows (the models page of the OpenAI
dashboard). Claude ids: `claude-sonnet-5-5`, `claude-opus-5-5`, `claude-haiku-5-5`.

## 3. Estimate, then run

```bash
PYTHONPATH=backend ~/agbench/bin/python research/agent-guard-bench/harness/live_eval.py run \
    --provider anthropic --model claude-sonnet-5-5 --suites banking,slack \
    --conditions none,guard,guard-approve --estimate
```

prints the number of agent runs. For reference: banking and slack together are 300 runs per
condition (900 for three conditions); all four suites are 1,081 per condition (3,243). Start
the run with the same command, `--estimate` replaced by `--yes --tag claude-sonnet-pilot`.
The same with `--provider openai --model YOUR_GPT_MODEL_ID --tag gpt-pilot`.

To resume an interrupted run, start the identical command with the same `--tag`; finished
tasks are skipped.

What the conditions mean: `none` is the agent without a filter; `guard` blocks every call
that needs approval (no person is present); `guard-approve` approves every request, so only
the filter's refusals stop calls. Together they bracket what real reviewers would do.

## 4. Pool the results

```bash
~/agbench/bin/python research/agent-guard-bench/harness/live_eval.py summarize
```

writes `research/agent-guard-bench/results/live/live_results.json` and prints a line per model
and condition. Send me the results folder without the bulky conversation logs:

```bash
tar czf ~/live-results.tgz -C ~/robustidps.ai/research/agent-guard-bench/results \
    --exclude='*/logs' live
```

Copy `~/live-results.tgz` to your computer (for example `scp root@37.27.31.70:live-results.tgz .`)
and upload it here; I add it to the repository and the paper picks it up (Table "Live models"
and its text are generated from it). The full logs (`results/live/<run>/logs`) contain every
conversation; keep them for the artifact.

## 5. Optional: run through the deployed site

This checks the live service end to end: the agent runs on the server, and every tool call is
judged by https://robustidps.ai with the same policy, so the decisions appear in that account's
Safety Filter (Evidence tab, Runtime Monitor). Every "ask" also creates an approval request in
that account (they expire after the approval TTL), so use the API key of a separate account to
keep your own Approvals tab clean.

```bash
PYTHONPATH=backend ~/agbench/bin/python research/agent-guard-bench/harness/live_eval.py run \
    --provider anthropic --model claude-sonnet-5-5 --guard url --guard-url https://robustidps.ai \
    --conditions guard --suites banking --user-tasks 4 --injection-tasks 3 --tag site-check
```

`guard-approve` is not available here by design: on the site only a signed-in person can
approve a request.
