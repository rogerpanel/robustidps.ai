# Ubuntu / WSL Deploy Runbook

Step-by-step commands for `royalroger@DESKTOP-IKQN6SR:~$` — confirmed
target is **WSL2 Ubuntu under Windows 11 on an HP Envy**. Bare-metal
Ubuntu instructions are the same from §1 onward.

## 0a · WSL2 + Docker Desktop (recommended for Windows 11)

Cleanest path on WSL2 — the Docker daemon runs on the Windows side and
is exposed inside Ubuntu. No `usermod`, no systemd flag-flipping, no
`sudo service docker start` after every WSL session.

**One-time, in Windows 11 PowerShell as Administrator:**

```powershell
wsl --update
wsl --set-default-version 2
wsl -l -v          # confirm your Ubuntu shows VERSION 2
```

Install **Docker Desktop for Windows** from
<https://www.docker.com/products/docker-desktop/>. Launch once, open
**Settings → Resources → WSL Integration**, toggle **Enable integration
with my default WSL distro** and tick the box next to your Ubuntu
distro. Apply & Restart.

**Back in your Ubuntu terminal (`royalroger@DESKTOP-IKQN6SR:~$`):**

```bash
docker --version            # → Docker version 27.x
docker compose version      # → Docker Compose version v2.x
git --version               # ships with Ubuntu; install if missing
```

If those three commands print versions, skip §0b and go to §1.

## 0b · Native dockerd in WSL2 (no Docker Desktop)

Only do this if you specifically don't want Docker Desktop. WSL2 needs
**systemd** enabled or Docker won't auto-start.

```bash
# Enable systemd in WSL2 (one-time)
sudo tee /etc/wsl.conf > /dev/null <<'EOF'
[boot]
systemd=true
EOF
# Then from Windows PowerShell:  wsl --shutdown
# Reopen your Ubuntu terminal afterwards.
ps -p 1 -o comm=          # → systemd

# Install Docker from the official repo
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Confirm the docker group now exists, then add yourself
getent group docker            # → docker:x:998:
sudo usermod -aG docker $USER
newgrp docker

# Start dockerd via systemd (you enabled it above)
sudo systemctl enable --now docker
docker run --rm hello-world    # sanity check

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

## Common WSL2-specific quirks (HP Envy / Windows 11)

| Symptom | Fix |
|---|---|
| `usermod: group 'docker' does not exist` | `apt-get install -y docker-compose-plugin` rolled back because Ubuntu's stock repos don't carry that package — `docker.io` never installed either. Use §0a (Docker Desktop) or §0b in full (adds Docker's official repo first). |
| `docker: Cannot connect to the Docker daemon` | If on §0a: open Docker Desktop on Windows and confirm WSL Integration is on for your distro. If on §0b: `ps -p 1 -o comm=` should say `systemd`; if not, you skipped the `/etc/wsl.conf` step. |
| `localhost:5173` not reachable from Windows browser | WSL2 auto-forwards localhost. If it doesn't, check Windows Defender Firewall, and as a fallback use the WSL IP: `ip addr show eth0 \| grep inet`. |
| Slow first build (10+ min) | The repo MUST live under your Linux home (`~/code/robustidps.ai`), never under `/mnt/c/`. Cross-filesystem I/O is the main offender. |
| HP Envy RAM blows up after a long session | WSL2's `vmmem` defaults to 50% of host RAM. Create `C:\Users\<you>\.wslconfig` with `[wsl2]\nmemory=8GB\nswap=4GB` if your Envy has ≤16 GB total. `wsl --shutdown` from PowerShell to apply. |
| HP Envy battery drains while stack idles | The four containers idle at ~1.5 W combined. Plug in for long sessions, or `docker compose stop` when stepping away. |
| ext4.vhdx file keeps growing after rebuilds | WSL2's sparse-disk doesn't auto-shrink. From PowerShell: `wsl --shutdown` then `diskpart` → `select vdisk file="C:\Users\<you>\AppData\Local\Packages\<distro>\LocalState\ext4.vhdx"` → `compact vdisk`. Reclaim only after `docker system prune -af --volumes`. |
| `python3: command not found` for local scripts | `sudo apt-get install -y python3 python3-venv python3-pip`. Only needed for the host-side AegisAgents SDK example; everything else runs in containers. |

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
