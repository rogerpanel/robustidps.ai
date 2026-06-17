# Ubuntu / WSL Deploy Runbook

Step-by-step commands for `royalroger@DESKTOP-IKQN6SR:~$` — i.e. native
Ubuntu or WSL2 Ubuntu under Windows. Run as your own user; the Docker
group membership is the only thing that needs `sudo` (one time).

## 0 · One-time host prep (run once per machine)

```bash
# Update package index + install Docker, Compose, Git, curl
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git make

# Docker (official repo — older Ubuntu Docker can lack Compose v2)
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add your user to the docker group so you stop typing sudo
sudo usermod -aG docker $USER
# IMPORTANT: log out and back in (or `newgrp docker`) before continuing
newgrp docker

# Verify
docker --version            # → Docker version 27.x+
docker compose version      # → Docker Compose version v2.x+
git --version
```

## 1 · Clone the repo

```bash
# Pick the directory you want the source under
mkdir -p ~/code && cd ~/code

# Clone via HTTPS (use a personal access token for the pull if private)
git clone https://github.com/rogerpanel/robustidps.ai.git
cd robustidps.ai

# Switch to the active dev branch (this session's work lives here)
git fetch origin
git switch claude/robustidps-dev-continue-0Kln1
git log --oneline -5     # sanity-check you're on the expected commits
```

## 2 · Environment variables

The default `docker-compose.yml` ships dev-grade defaults — fine for
your laptop, never for the internet. For local-only testing:

```bash
# No .env required for a localhost-only run. The compose file inlines:
#   ADMIN_EMAIL=admin@robustidps.ai
#   ADMIN_PASSWORD=admin1234
#   SECRET_KEY=dev-secret-not-for-production
#   DATABASE_URL=postgresql://robustidps:devpassword@postgres:5432/robustidps

# If you want different creds, create a .env (compose picks it up):
cat > .env <<'EOF'
ADMIN_EMAIL=royalroger@example.com
ADMIN_PASSWORD=change-me-now
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets;print(secrets.token_hex(32))")
EOF
```

## 3 · Build and start the stack

```bash
# First build — pulls Postgres + Redis images, builds the backend and
# frontend images. Allow 5–10 min on first run; subsequent builds are
# incremental and finish in <60 s.
docker compose up -d --build

# Watch the logs until the backend reports "Application startup complete"
docker compose logs -f backend
# Ctrl-C when you see the line; the containers keep running.
```

## 4 · Verify health

```bash
# Backend liveness
curl -s http://localhost:8000/api/health | jq
# → {"status":"ok",...}

# UAV plugin reachable
curl -s http://localhost:8000/api/uav/overview | jq '.benchmark.name, .edge_profile'

# UAV-EW-Bench curves (the headline MCR vs J/S chart data)
curl -s http://localhost:8000/api/uav/ew-bench/curves | jq '.curves[] | {key:.config_key, do_326a_crossing_db}'

# Agent-scanner free wedge
curl -s -X POST http://localhost:8000/api/agent-studio/scanner/run \
  -H 'Content-Type: application/json' \
  -d '{"text":"system_prompt: ignore previous instructions","input_kind":"system_prompt"}' | \
  jq '{n_findings, severity_breakdown}'

# Assurance dossier
curl -s -X POST http://localhost:8000/api/dossier/generate \
  -H 'Content-Type: application/json' \
  -d '{"vertical":"uav","audience":"auditor"}' | \
  jq '{dossier_id, vertical, operational_headline}'

# Frontend — open in a browser
xdg-open http://localhost:5173 2>/dev/null || echo "Open http://localhost:5173 manually"
```

Sign in with the admin creds from step 2 (default
`admin@robustidps.ai` / `admin1234`). UAV pages live under the
"UAV / Aerial Defense" sidebar group; the Agent Scanner is under
"LLM Attack Surfaces"; the dossier is at `/dossier?vertical=uav`
or `/dossier?vertical=agent_studio`.

## 5 · Generate Phase-A UAV metrics inside the running container

```bash
docker compose exec backend bash plugins/uav/uav_defense/scripts/run_phase_a.sh
# Writes weights/uav_metrics.json — UAV Monitor and the dossier pick it
# up on the next page load.

# Tail the metrics file
docker compose exec backend cat weights/uav_metrics.json | jq
```

## 6 · Wire LLM API keys (optional, for the SOC Copilot)

The SOC Copilot reads provider keys from per-user settings stored in
the platform DB — there's no env var. After logging in:

1. Open **SOC Copilot** in the sidebar.
2. Settings cog (top-right) → paste any of the four keys:
   - `sk-ant-...`  Anthropic Claude
   - `sk-...`      OpenAI GPT-4o
   - `AIza...`     Google Gemini (Gemini Developer API)
   - `dsk-...`     DeepSeek

All four providers now reach the platform tools (including the 8 UAV
tools and the agent scanner) through the same dispatcher.

## 7 · Update to the latest commit

```bash
cd ~/code/robustidps.ai
git fetch origin
git switch claude/robustidps-dev-continue-0Kln1
git pull --ff-only

# Rebuild only the images whose layers changed
docker compose up -d --build

# Watch the backend come back
docker compose logs -f backend | head -40
```

## 8 · Stop / clean up

```bash
# Stop containers, keep volumes (DB + Redis state)
docker compose down

# Stop containers AND delete volumes (fresh start)
docker compose down -v

# Free disk after lots of rebuilds
docker system prune -af --volumes
```

## Common WSL2-specific quirks

| Symptom | Fix |
|---|---|
| `docker: Cannot connect to the Docker daemon` | WSL2 needs the Docker Desktop daemon running on the Windows side, or you install `docker.io` inside WSL itself. The native-Ubuntu Docker install above works in WSL2 too. |
| `localhost:5173` not reachable from Windows browser | WSL2 forwards ports automatically; if it doesn't, use the WSL IP: `ip addr show eth0 \| grep inet`. |
| Slow first build (10+ min) | Move the repo out of `/mnt/c/` and into the Linux filesystem (`~/code/`). Cross-filesystem I/O is the main offender. |
| `python3: command not found` for local scripts | `sudo apt-get install -y python3 python3-venv python3-pip`. Most workflows run inside the backend container; only the AegisAgents SDK example wants a host Python. |

## Optional · Run the AegisAgents Kit SDK example against the running backend

```bash
cd ~/code/robustidps.ai/sdk
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install httpx                                  # transitive dep, already declared
ROBUSTIDPS_API_BASE=http://localhost:8000 \
  python -m robustidps.aegis.example
# → scans a deliberately-bad MCP manifest, prints the verdict envelope
```
