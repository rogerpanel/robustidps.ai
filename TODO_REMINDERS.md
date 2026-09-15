# Pinned TODOs

Persistent reminders the user has asked me to keep on file.

## ✅ Step-by-step "Build → Secure → Ship" agent guide

**Status (2026-06-20)**: Drafted at `papers/AGENT_SHIP_GUIDE.md`.
Audit + re-verify against the live `https://robustidps.ai` once Stripe
funding flips the Account console out of staging mode.

---

### Original brief (kept for context)

**Asked by**: user, in the session that landed `447b52e`.

**When to fire**: once all three Agent Studio proposals have shipped:

- [x] Proposal 1 — deeper capabilities (Garak / OTel-GenAI / live HF API)
- [x] Proposal 2 — commerce sprint (Stripe Checkout + API-key issuance + admin console)
- [x] Proposal 3 — SDK additions (DSPy / Strands / Smolagents + pytest plugin)

The user wants a **proper step-by-step guide** that walks a customer
through: build an agent → run pre-flight evals → scan supply chain →
secure with AegisAgents Kit → red-team it → enable runtime monitoring
→ generate the assurance dossier → ship it to production. End-to-end,
copy-pasteable commands, against the live `https://robustidps.ai`
platform.

Once item #2 (commerce) and #3 (SDK additions) are deployed and
verified in the browser, draft `papers/AGENT_SHIP_GUIDE.md` covering:

1. Sign up at `/agent-studio` (Stripe Checkout — staging or live)
2. Receive the API key on the success page
3. `pip install robustidps[aegis]` on the dev machine
4. Wrap a LangGraph / CrewAI / OpenAI Agents agent with `aegis.guard()`
5. Run the eval harness at `/agent-studio/eval` against the spec
6. Scan model supply chain at `/agent-studio/supply-chain`
7. Fire the red-team automation at `/agent-studio/red-team`
8. Enable runtime monitoring — wire OTel-GenAI traces to
   `/api/agent-studio/runtime/otel/traces`
9. Add the pytest plugin to CI: `pytest --aegis-fail-on-warn`
10. Generate the assurance dossier at `/dossier?vertical=agent_studio`
11. Ship: deploy your agent + ship the printed dossier to the auditor

Audience: a developer dropping their first agent into production with
RobustIDPS as the guardrail and the assurance evidence.
