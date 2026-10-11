# Build → Secure → Ship — the RobustIDPS.ai agent guide

> **Audience** — a developer, IT engineer, or mission planner shipping
> their first (or hundredth) agent to production with RobustIDPS.ai as
> the guardrail and the assurance evidence.
>
> **Substrate** — the live platform at `https://robustidps.ai`. Every
> command below is copy-pasteable against that backend. No local backend
> required — `pip install robustidps[aegis]` and a
> `ROBUSTIDPS_API_BASE` env var is all you need.
>
> **Two flow modes** — Everything below has a *no-code* path (the
> Quickstart hub + Express mode wizard) and an *engineer* path (JSON
> spec + CLI). Pick whichever suits you. Both produce the same
> production artefact.

---

## 0. Prerequisites

```bash
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install "robustidps[aegis,pytest]"
export ROBUSTIDPS_API_BASE="https://robustidps.ai"
```

Sanity check:

```bash
curl -sf "$ROBUSTIDPS_API_BASE/api/agent-studio/access-info" \
  | python3 -m json.tool
```

If you see `demo_mode: true`, the server has open demo access and you
can walk every page without an API key. Otherwise proceed to §1.

## 0.5 What's persisted server-side?

All Agent Studio state — customers, API keys, admin grants, deployments,
sessions, eval / red-team / supply-chain history, **and per-user
workspaces** — lives in SQLAlchemy tables. Works on **SQLite (dev)** and
**PostgreSQL (production)**. Strict per-user isolation is enforced at
the application layer via `scoped()`; enable Postgres-true row-level
security with `backend/plugins/agent_studio/RLS_POSTGRES.sql`.

## 0.6 Four ways to identify

Every Agent Studio page shows an **AccessBanner** at the top so you know
which identity mode is active:

| Mode | Trigger | What you can do |
|---|---|---|
| 🟢 Admin (platform JWT, `role: admin`) | Log in as an admin user | Everything, everywhere, no API key |
| 🟢 Admin (env bypass) | `AGENT_STUDIO_AUTH_DISABLED=1` on server | Same as above, dev only |
| 🔵 Authenticated user (non-admin) | Platform JWT with a tier | Tier-scoped access; workspaces saved to your identity |
| 🔵 API key | `Authorization: Bearer rids_live_…` | Tier-scoped per issued key |
| 🟠 Demo (anonymous) | `AGENT_STUDIO_DEMO_MODE=1` on server | Read + rate-limited writes; **cannot persist workspaces** |
| 🔴 Locked | None of the above | Sign in or paste a key |

---

## 1. Sign up

### 1a. Stripe self-serve (most regions)

1. Open `https://robustidps.ai/agent-studio`.
2. Enter your work email in the **SaaS tiers** card.
3. Click **Subscribe to Pro** (or Enterprise). Staging mode redirects to
   the Account Console with a synthetic session ID; no card charged
   until Stripe is funded.
4. On the Account Console, click **Activate & issue API key**. Save the
   `rids_live_…` plaintext — it's shown once.

### 1b. Admin-issued grant (Russia / Crimea / wire / crypto / sponsorship)

Regions where Stripe doesn't operate, or customers who pay by bank wire /
YooMoney / QIWI / SBP / USDT / crypto / sponsorship / academic:

1. Pay through your channel.
2. Send proof to `licensing@robustidps.ai`.
3. Admin issues the grant; you receive `customer_id + rids_live_…`.

```bash
# Admin issuance from the CLI:
ROBUSTIDPS_ADMIN_TOKEN=… robustidps agent admin grant \
  --email customer@example.ru --tier pro --months 12 \
  --rail yoomoney --note "YooMoney tx 2026-06-22 RUB 30000"
```

```bash
export ROBUSTIDPS_API_KEY="rids_live_…"
```

---

## 2. Pick your role & template

Open `https://robustidps.ai/agent-studio/quickstart`. The **role picker**
at the top narrows the catalog:

- *I'm a security engineer* — SOC / IR / vuln / hunt / MCP / compliance
- *I'm a security tester* — red-team / pentest / phishing
- *I'm a network ops engineer* — network traffic monitor + SOC / IR / vuln
- *I'm a UAV mission planner* — UAV swarm coordinator + IR + compliance
- *I'm a developer* — customer-support / billing / docs / blank
- *I'm an IT admin* — compliance / MCP / docs / IR

**15 templates ship out of the box** — 6 defenders + 3 attackers + 6
productivity/role-targeted (customer support, billing copilot, docs Q&A,
network traffic monitor, UAV swarm coordinator, blank).

Click **Build → Configure → Test → Ship** on any card to enter the
4-stage wizard.

---

## 3. Four-stage BuildWizard

### Step 1 — Create agent

Two modes:

- **🧭 Express** (default, no-code) — 5 dropdowns / textareas:
  - Agent name
  - Purpose (plain English)
  - Allowed tools (checkbox list, pre-checked from the template)
  - Network access (blocked / allowlist / open)
  - Memory (none / session / long-term)
  - On critical input (refuse / warn / escalate)
- **⚙ JSON** — full spec editor for engineers.

A **Platform Models picker** below lets you attach any of the 17
platform-side detection / response models as *special tools*:

| Category | Models |
|---|---|
| Ensemble / triage | `surrogate` |
| Temporal | `neural_ode`, `sde_tgnn` |
| Federated | `optimal_transport`, `fedgtd` |
| Foundation (LLM) | `cybersec_llm` |
| CL-RL response | `clrl_unified` (+ 4 sub-models) |
| Certified | `lipmamba`, `sode_guard` |
| Self-supervised | `ssl_graph_anomaly`, `ssl_graph_anomaly_full` |
| PQC | `multi_agent_pqc` |
| LLM protocol | `mambaguard` |

Recommended defaults auto-load per template. One click *"↻ apply
recommended"* seeds the picks.

**Contextual side-tips** (right column) update per (step, archetype)
and surface cross-vertical **bridges** — e.g. a UAV Swarm Coordinator
build points to `/uav/mission-plan`, `/uav/swarm`, `/uav/fleet-demo`;
a Network Traffic Monitor build points to `/live-monitor`,
`/analytics`, `/threat-response`.

**Save your workspace** — the top toolbar has Save / Save as… / Load /
Export / Import. Workspaces persist server-side under your identity;
resume from any device after sign-in.

### Step 2 — Configure environment

Review the runtime, network policy, packages, MCP servers, env vars,
secrets. Change what you need. Same JSON editor + summary card.

### Step 3 — Test session

Paste your API key, click **Start session**, send a probe. Every turn
is Aegis pre-checked (input) and post-checked (output). Verdict bubbles
show `allow / warn / block` per turn with finding codes.

The chip at the top of Step 3 tells you which LLM provider your
sessions are hitting:
- 🟢 `live LLM dispatch · anthropic/claude-sonnet-4-6` (or openai / google / deepseek)
- 🟡 `synthetic dispatcher (no LLM provider key set)`

### Step 4 — Integrate + ship

Three integration paths — copy any snippet:
- **Python** (LangGraph or OpenAI Agents + Aegis)
- **cURL** (any HTTP client)
- **Kubernetes** manifest stub

Three CTAs below the snippet:
- 🚀 **Register this deployment** — prefills the Deployments form
- 📋 Generate assurance dossier
- 🔧 Manage keys + tier

---

## 4. One-turn build → secure → ship (SOC Copilot)

Skip the wizard entirely. Ask the SOC Copilot:

> *"Build me a network traffic monitor and register it as a
> production deployment in eu-central-1."*

The Copilot calls `orchestrate_build_and_ship_agent` under the hood,
which chains in one turn:

1. Load the `network_traffic_monitor` template
2. Run 5-eval harness → returns overall_score + verdict
3. Run 12-probe Garak red-team → returns severity_breakdown + ATLAS chain
4. Run supply-chain scan on `cybersec_llm` → returns risk_level + SBOM
5. Save workspace as `network_traffic_monitor-orchestrated-<yyyymmdd>`
6. Register deployment (tier=production, cloud=docker_self, region=eu-central-1)
7. Return the bundle: run_ids, workspace_id, deployment_id, and deep-link
   URLs to `/agent-studio/{runtime,workspaces,deployments}` +
   `/dossier?vertical=agent_studio`

Same flow available as HTTP:

```bash
curl -sf -X POST $ROBUSTIDPS_API_BASE/api/agent-studio/orchestrate \
  -H "Authorization: Bearer $ROBUSTIDPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"template_id":"network_traffic_monitor",
        "cloud":"docker_self","tier":"production","region":"eu-central-1"}' \
  | python3 -m json.tool
```

---

## 5. Ship the agent binary

### 5a. Pick a starter repo (fastest path)

Four reference implementations live under `examples/agents/`:

| Folder | Template |
|---|---|
| `examples/agents/soc_triage/`        | SOC Triage |
| `examples/agents/billing_copilot/`   | Billing Copilot |
| `examples/agents/red_team_operator/` | Red-Team Operator |
| `examples/agents/docs_qa/`           | Docs Q&A |

Each ships `main.py + requirements.txt + Dockerfile + k8s.yaml + README.md`.
Plus per-runtime deploy recipes under `examples/agents/_deploy/` for
Fly.io, Modal, and Vercel.

### 5b. Wrap your own agent

```python
from robustidps.aegis import MambaGuardClient
from robustidps.aegis.langgraph import guard   # or crewai / openai_agents / …

client = MambaGuardClient(
    api_base="https://robustidps.ai",
    api_key="rids_live_…",
)
graph = guard(graph, client=client, policy="default",
              template_id="network_traffic_monitor",
              agent_id="net-mon-prod-eu-1")
```

Every tool call + LLM response ships a verdict envelope to
`/api/agent-studio/runtime/ingest` keyed by `agent_id`.

Supported wrapper modules (11):
`langgraph · crewai · mcp · a2a · anp · openai_agents · autogen · pydantic_ai · dspy · strands · smolagents`

---

## 6. Runtime monitoring

Two ingest paths:

- **Native verdict ingest** (already wired by `aegis.guard()`)
- **OTel-GenAI traces** — POST OTLP/JSON to
  `/api/agent-studio/runtime/otel/traces` or trimmed spans to
  `/runtime/otel/spans`

Watch on `/agent-studio/runtime` — per-agent block_rate / warn_rate /
p50 / p95 / top finding codes with 2 Hz polling.

Then register the deployment (matches your `runtime_agent_id`):

```bash
robustidps agent deployments register \
  --template network_traffic_monitor \
  --name "net-mon-prod-eu-1" \
  --agent-id "net-mon-prod-eu-1" \
  --cloud k8s_self --region eu-central-1 --tier production
```

Live status colour-coding on `/agent-studio/deployments`:
🟢 healthy · 🟡 degraded · ⚫ stale · ⚫ retired.

---

## 7. Add pytest gate to CI

```bash
pip install "robustidps[pytest]"
```

`tests/test_prompts.py`:

```python
def test_system_prompt_safe(aegis_assert_safe):
    from my_agent import SYSTEM_PROMPT
    aegis_assert_safe(SYSTEM_PROMPT, kind="system_prompt")
```

CI:

```yaml
- name: Aegis gate
  env:
    ROBUSTIDPS_API_KEY: ${{ secrets.ROBUSTIDPS_API_KEY }}
  run: pytest --aegis-fail-on-warn
```

---

## 8. Assurance dossier

UI: `https://robustidps.ai/dossier?vertical=agent_studio` → Print theme → Cmd-P → PDF.

CLI:

```bash
robustidps agent dossier --vertical agent_studio -o dossier.json
```

Packs: 5-SKU coverage matrix, OWASP Agentic Top 10 (ASI01–ASI10) findings,
MITRE ATLAS chain, CycloneDX-AI SBOM fragments, ISO 42001 / EU AI Act
Art. 15 / NIST AI RMF / GOST R 59276 mappings, eval verdicts, red-team
summary, live block-rate trend.

Ship this PDF to your auditor.

---

## 9. The `/agent-studio` hub

The Portal landing page is now a proper hub — a 3-column overview
above the SKU catalog:

- **Your workspaces** — top 4 saved BuildWizard sessions. Click any row
  to resume in-place.
- **Your deployments** — colour-coded status per registered instance.
- **What's next?** — contextual next-step card. Reads workspaces +
  deployments + activity and picks the highest-priority nudge (stale
  deployment → investigate; no workspace → open Quickstart; workspace
  but no deployment → register; missing evals → run; all green →
  generate dossier).

Everything deep-links, so the hub is the true starting point.

### Pick up where you left off

Every Agent Studio surface persists its state per-browser AND per-user
server-side. The Portal panel + SOC Copilot both call the same rollup:

```bash
curl -sf https://robustidps.ai/api/agent-studio/activity?limit=5 \
  -H "Authorization: Bearer $ROBUSTIDPS_API_KEY" \
  | python3 -m json.tool
```

In the SOC Copilot chat, try:
- `"summarise my agent studio activity"`
- `"show me my last red-team run"`
- `"list test sessions for the soc_triage template"`
- `"list my deployments"`
- `"which platform models should my network monitor use?"`
- `"build me a soc_triage agent"` (invokes the orchestrator)

CLI equivalent:

```bash
robustidps agent activity --limit 5
```

---

## 10. Workspaces (save / export / import / delete)

`/agent-studio/workspaces` — table view of everything you've saved.

- **Save / Save as…** — top toolbar of every BuildWizard
- **Export** — downloads the workspace as JSON you can archive on disk
- **Import** — upload a JSON dump (you become the owner regardless of
  what's inside)
- **Archive** — soft delete (recoverable)
- **Delete** — hard delete
- **Admin toggle** — platform admins see every user's workspaces

Strict isolation: a user with email `A@x` cannot list / fetch / delete
a workspace owned by `B@y`. Both the app-layer `scoped()` filter and
the Postgres RLS policy refuse cross-user reads.

Demo-mode visitors cannot save — the API returns 403.

---

## 11. End-to-end checklist

- [ ] Signed up via Stripe or admin grant · API key stored
- [ ] Picked role + template on `/agent-studio/quickstart`
- [ ] BuildWizard Step 1 (Express or JSON) · platform models attached
- [ ] Step 2 · environment reviewed
- [ ] Step 3 · sandboxed session shows verdict envelopes
- [ ] Step 4 · integration snippet copied
- [ ] Deployment registered · runtime telemetry flowing
- [ ] `pytest --aegis-fail-on-warn` green in CI
- [ ] Assurance dossier generated and archived
- [ ] Deployed; API key sourced from a secret manager

When all ten boxes are checked, you've shipped an agent that's
**provably** secure — not just claimed-secure.

---

## Reference: everything shipped

- **15 templates**: SOC Triage · Incident Commander · Compliance Auditor · Vuln Triage · MCP Auditor · Threat Hunter · Red-Team Operator · Pentest Recon · Phishing Trainer · Customer Support · Billing Copilot · Docs Q&A · Network Traffic Monitor · UAV Swarm Coordinator · Blank
- **17 platform models** attachable as special tools (see §3 table)
- **11 framework wrappers** in the AegisAgents Kit
- **34 scanner checks**: 12 MCP framing + 10 OWASP LLM Top-10 + 5 memory-store auditor + 5 credential-vault auditor + 2 hygiene
- **6 identity modes** (admin / platform user / API key / demo / env-bypass / locked)
- **61 SOC Copilot tools** including the orchestrator
- **Full 4-provider LLM dispatch** in test sessions (Anthropic / OpenAI / Google / DeepSeek)
- **Rust edge-agent** (see the technical documentation) for kernel-level XDP drop
- **CI dogfood** — `.github/workflows/aegis-gate.yml` runs the pytest plugin on every PR
