#!/usr/bin/env bash
# Diagnose Roundcube's "Connection to storage server failed".
#
#   sudo bash deploy/mail/diagnose-webmail.sh
#
# Read-only: changes nothing. That message is rendered by Roundcube
# itself, so the browser -> Cloudflare -> nginx -> Roundcube path is
# already proven working. The fault is the next hop, Roundcube -> IMAP
# (port 993). This checks every candidate for that hop in one pass and
# prints raw evidence alongside each verdict.
set -uo pipefail

MAIL=robustidps-mail
WEB=robustidps-webmail
HOST=mail.robustidps.ai

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✘\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
hdr()  { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run with sudo: sudo bash $0"; exit 1; }

FAULTS=()

# ── 1 ────────────────────────────────────────────────────────────────────
hdr "1. Containers"
for c in "$MAIL" "$WEB"; do
  st=$(docker inspect -f '{{.State.Status}}{{if .State.Health}} ({{.State.Health.Status}}){{end}}' "$c" 2>/dev/null || echo "missing")
  if [[ $st == running* && $st != *unhealthy* ]]; then ok "$c: $st"
  else bad "$c: $st"; FAULTS+=("container:$c"); fi
done

# ── 2 ────────────────────────────────────────────────────────────────────
hdr "2. Roundcube -> IMAP, reproduced exactly (TLS to $HOST:993 from inside webmail)"
resolved=$(docker exec "$WEB" getent hosts "$HOST" 2>/dev/null | awk '{print $1}' | head -1)
note "$HOST resolves inside the webmail container to: ${resolved:-<nothing>}"
[[ -n $resolved ]] || FAULTS+=("dns")

# Same transport Roundcube uses: PHP stream over TLS with peer-name check.
imap=$(docker exec -i -e H="$HOST" "$WEB" php 2>&1 <<'PHP'
<?php
$h = getenv('H');
$ctx = stream_context_create(['ssl' => ['peer_name' => $h, 'verify_peer' => true]]);
$c = @stream_socket_client("ssl://$h:993", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
if (!$c) { echo "FAIL errno=$errno: $errstr\n"; exit(1); }
stream_set_timeout($c, 8);
$greeting = trim((string) fgets($c));
echo $greeting === '' ? "FAIL: TLS up but no IMAP greeting\n" : "OK: $greeting\n";
PHP
)
if [[ $imap == OK:* ]]; then ok "IMAP reachable — ${imap#OK: }"
else bad "IMAP NOT reachable: $imap"; FAULTS+=("imap"); fi

# ── 3 ────────────────────────────────────────────────────────────────────
hdr "3. fail2ban — has the webmail container itself been banned?"
web_ips=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$WEB" 2>/dev/null)
gw_ips=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$WEB" 2>/dev/null)
pub_ip=$(getent hosts "$HOST" | awk '{print $1}' | head -1)
note "webmail container IP(s): ${web_ips:-?}   docker gateway(s): ${gw_ips:-?}   public: ${pub_ip:-?}"
bans=$(docker exec "$MAIL" setup fail2ban 2>&1 || true)
note "fail2ban reports:"
printf '%s\n' "$bans" | sed 's/^/      /' | head -20
banned_self=()
for ip in $web_ips $gw_ips $pub_ip; do
  # -w so 172.18.0.1 does not match inside 172.18.0.10
  grep -qwF "$ip" <<<"$bans" && banned_self+=("$ip")
done
if [[ ${#banned_self[@]} -gt 0 ]]; then
  bad "BANNED: ${banned_self[*]} — this blocks webmail for EVERY user"
  FAULTS+=("fail2ban")
else
  ok "none of the webmail's own addresses are banned"
fi

# ── 4 ────────────────────────────────────────────────────────────────────
hdr "4. Recent IMAP logins and failures (mailserver, last 6h)"
docker logs --since 6h "$MAIL" 2>&1 \
  | grep -iE 'imap-login|auth fail|authentication fail|disconnected|ban' \
  | tail -n 15 | sed 's/^/    /'

# ── 5 ────────────────────────────────────────────────────────────────────
hdr "5. Roundcube's own errors (last 6h)"
docker logs --since 6h "$WEB" 2>&1 \
  | grep -iE 'error|imap|storage|fail|refused|timed out|ssl' \
  | tail -n 15 | sed 's/^/    /'

# ── Verdict ──────────────────────────────────────────────────────────────
hdr "Verdict"
if [[ ${#FAULTS[@]} -eq 0 ]]; then
  ok "Roundcube can reach IMAP and nothing is banned."
  note "If login still fails, the cause is credentials or the session —"
  note "check section 4 for 'auth failed' against the address you used."
  exit 0
fi
for f in "${FAULTS[@]}"; do
  case $f in
    fail2ban)
      bad "fail2ban has banned the webmail. Restore service now with:"
      for ip in "${banned_self[@]}"; do note "sudo docker exec $MAIL setup fail2ban unban $ip"; done
      note "Then re-run this script. Ask before treating it as fixed: it will"
      note "recur on the next run of mistyped passwords unless prevented." ;;
    container:*)
      bad "${f#container:} is not healthy. Its log:"
      note "sudo docker logs --tail=40 ${f#container:}" ;;
    dns)
      bad "the webmail container cannot resolve $HOST." ;;
    imap)
      [[ " ${FAULTS[*]} " == *" fail2ban "* ]] \
        || bad "IMAP unreachable with no ban in place — send this full output." ;;
  esac
done
exit 1
