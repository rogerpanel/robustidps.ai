#!/usr/bin/env bash
# Stop fail2ban banning the webmail container, restore webmail, verify.
#
#   sudo bash deploy/mail/apply-fail2ban-whitelist.sh
#
# Recreates the mailserver container once (about 2 minutes). Mail sent to
# you during that window is not lost: sending servers queue and retry.
# Mailboxes, accounts, DKIM keys, certificates and fail2ban state all live
# in volumes and bind mounts, so recreating loses nothing.
set -euo pipefail
cd "$(dirname "$0")/../.."

MAIL=robustidps-mail
WEB=robustidps-webmail
SRC=deploy/mail/fail2ban-jail.cf
DST=deploy/mail/config/fail2ban-jail.cf

ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
bad() { printf '  \033[31m✘\033[0m %s\n' "$*"; }
hdr() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run with sudo: sudo bash $0"; exit 1; }
[[ -f $SRC ]] || { bad "$SRC missing — git pull first"; exit 1; }

is_private() {
  local a b
  IFS=. read -r a b _ _ <<<"$1"
  [[ $a == 10 || $a == 127 || ( $a == 172 && $b -ge 16 && $b -le 31 ) || ( $a == 192 && $b == 168 ) ]]
}

# ── 1. Safety premise ────────────────────────────────────────────────────
# Whitelisting 172.16.0.0/12 is only safe if internet clients reach the
# mailserver with their real addresses. If Docker's userland proxy were
# rewriting sources, every attacker would appear as a 172.x gateway and
# the whitelist would exempt all of them. Refuse in that case.
hdr "1. Checking that external clients keep their real IPs"
ext=0; int=0
for ip in $(docker logs --since 72h "$MAIL" 2>&1 | grep -oE 'rip=[0-9]+(\.[0-9]+){3}' | cut -d= -f2 | sort -u); do
  if is_private "$ip"; then int=$((int + 1)); else ext=$((ext + 1)); fi
done
echo "    distinct client addresses in the last 72h: $ext external, $int internal"
if (( ext == 0 && int > 0 )); then
  bad "every client appears with an internal address — Docker is masking source IPs."
  bad "Whitelisting 172.16.0.0/12 would exempt all attackers. Aborting; nothing changed."
  exit 1
elif (( ext == 0 )); then
  echo "    no client connections logged recently; relying on the earlier ban list,"
  echo "    which held public attacker IPs and so shows real addresses are preserved."
else
  ok "external clients are logged with real public addresses"
fi

# ── 2. Install ───────────────────────────────────────────────────────────
hdr "2. Installing $DST"
mkdir -p "$(dirname "$DST")"
install -m 644 "$SRC" "$DST"
ok "installed"

# ── 3. Recreate so DMS runs full setup and copies it into jail.d ─────────
# NOT `docker restart`. docker-mailserver v15 start-mailserver.sh skips
# setup when /CONTAINER_START exists, i.e. on any restart of an existing
# container ("Container was restarted. Skipping most setup routines."), so
# the copy into jail.d never runs. Only a fresh container runs _setup. The
# first version of this script restarted, the server came back healthy,
# and the file was silently never applied.
hdr "3. Recreating $MAIL (full setup runs only in a fresh container)"
old_id=$(docker inspect -f '{{.Id}}' "$MAIL")
docker compose -f docker-compose.mail.yml --env-file deploy/mail/.env.mail \
  up -d --force-recreate --no-deps mailserver
new_id=$(docker inspect -f '{{.Id}}' "$MAIL")
if [[ $new_id == "$old_id" ]]; then
  bad "container ID unchanged — it was not recreated. Aborting."; exit 1
fi
ok "recreated (new container ${new_id:0:12})"
printf '    waiting for healthy'
healthy=0
for _ in $(seq 1 60); do
  h=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$MAIL" 2>/dev/null || true)
  [[ $h == healthy ]] && { healthy=1; break; }
  printf '.'; sleep 5
done
echo
if (( healthy )); then ok "healthy"
else bad "not healthy after 300s:"; docker logs --tail=30 "$MAIL" 2>&1 | sed 's/^/      /'; exit 1; fi

# Confirm setup actually copied the file, rather than inferring it from
# the container being healthy — healthy is exactly what misled the first run.
if docker exec "$MAIL" grep -qF '172.16.0.0/12' /etc/fail2ban/jail.d/user-jail.local 2>/dev/null; then
  ok "user-jail.local present in the container"
else
  bad "/etc/fail2ban/jail.d/user-jail.local missing or wrong after recreate."
  docker exec "$MAIL" ls -l /tmp/docker-mailserver/fail2ban-jail.cf 2>&1 | sed 's/^/      /'
  exit 1
fi

# ── 4. Lift the existing ban ─────────────────────────────────────────────
# fail2ban restores bans from its database on restart, so unban explicitly
# rather than assume the new ignoreip clears an already-recorded ban.
hdr "4. Removing bans on the webmail's own addresses"
for ip in $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}} {{end}}' "$WEB"); do
  docker exec "$MAIL" setup fail2ban unban "$ip" >/dev/null 2>&1 || true
  echo "    unbanned $ip (no-op if it was not banned)"
done

# ── 5. Verify the setting is live ────────────────────────────────────────
hdr "5. Verifying ignoreip is active"
got=$(docker exec "$MAIL" fail2ban-client get dovecot ignoreip 2>&1 || true)
printf '%s\n' "$got" | sed 's/^/    /'
if grep -qF '172.16.0.0/12' <<<"$got"; then
  ok "dovecot jail ignores 172.16.0.0/12"
else
  bad "172.16.0.0/12 is not in the dovecot ignore list — the file was not picked up."
  exit 1
fi

# ── 6. End-to-end ────────────────────────────────────────────────────────
hdr "6. Re-running the webmail diagnostic"
bash deploy/mail/diagnose-webmail.sh
