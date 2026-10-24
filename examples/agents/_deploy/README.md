# Deployment recipes

Pick the runtime that matches your stack. Every recipe assumes you
have a Pro/Enterprise API key from `/agent-studio/account` available
in your secret manager.

| Recipe | File | Best for |
|---|---|---|
| **Docker** | `<agent>/Dockerfile` | Local dev, Compose, ECS task definition |
| **Kubernetes** | `<agent>/k8s.yaml` | Self-hosted k8s, EKS, GKE, AKS |
| **Fly.io** | `_deploy/fly.toml.template` | One-command cloud, autoscaling, free tier |
| **Modal** | `_deploy/modal_app.py.template` | Serverless Python, GPU-friendly |
| **Vercel** | `_deploy/vercel.json.template` | Edge / serverless functions |

Replace `<AGENT>` (uppercase) and `<agent>` (lowercase) tokens with
your agent's folder name, e.g. `SOC_TRIAGE` / `soc_triage`.

For all recipes:

```bash
export ROBUSTIDPS_API_KEY="rids_live_…"
export ROBUSTIDPS_API_BASE="https://robustidps.ai"
export RUNTIME_AGENT_ID="<agent>-prod-eu-1"
```

After your first verdict ships, register the deployment so it shows
up under `/agent-studio/deployments`:

```bash
robustidps agent deployments register \
  --template <agent> \
  --name "<agent>-prod-eu-1" \
  --agent-id "<agent>-prod-eu-1" \
  --cloud fly  # or modal / vercel / k8s_self
```
