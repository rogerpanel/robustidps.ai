#!/usr/bin/env bash
# One-shot bootstrap for the self-hosted mail stack.
#
#   sudo bash deploy/mail/setup-mail.sh
#
# Idempotent: re-running skips accounts that already exist and reuses
# existing DKIM keys / certificates. Run from the repo root on the server.
set -euo pipefail

cd "$(dirname "$0")/../.."
ENV_FILE=deploy/mail/.env.mail
COMPOSE="docker compose -f docker-compose.mail.yml --env-file $ENV_FILE"
DOMAIN=robustidps.ai
ACCOUNTS=(roger admin support noreply)
ALIASES=("postmaster:admin" "abuse:admin" "hostmaster:admin" "webmaster:admin")

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# ── 0. Preconditions ─────────────────────────────────────────────────────
[[ -f $ENV_FILE ]] || { red "Missing $ENV_FILE — copy deploy/mail/.env.mail.example and fill it in."; exit 1; }
[[ -f deploy/mail/cloudflare.ini ]] || { red "Missing deploy/mail/cloudflare.ini — copy the .example and paste your Cloudflare API token."; exit 1; }
grep -q PASTE_TOKEN_HERE deploy/mail/cloudflare.ini && { red "deploy/mail/cloudflare.ini still has the placeholder token."; exit 1; }
chmod 600 deploy/mail/cloudflare.ini "$ENV_FILE"
docker network inspect robustidpsai_app >/dev/null 2>&1 || {
  red "Docker network robustidpsai_app not found. Start the app stack first:"
  red "  docker compose -f docker-compose.prod.yml up -d"
  exit 1
}
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
MAIL_HOSTNAME=${MAIL_HOSTNAME:-mail.$DOMAIN}
mkdir -p deploy/mail/config

# ── 1. Firewall ──────────────────────────────────────────────────────────
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  bold "[1/6] Opening mail ports in ufw"
  for p in 25 465 587 993; do ufw allow "$p/tcp" >/dev/null; done
  ufw status | grep -E '^(25|465|587|993)/tcp' || true
else
  bold "[1/6] ufw not active — make sure 25/465/587/993 are open in the Hetzner Cloud firewall"
fi

# ── 2. Certificate ───────────────────────────────────────────────────────
bold "[2/6] Issuing Let's Encrypt certificate for $MAIL_HOSTNAME (DNS-01 via Cloudflare)"
$COMPOSE up -d certbot
for i in $(seq 1 30); do
  if $COMPOSE exec -T certbot test -s "/etc/letsencrypt/live/$MAIL_HOSTNAME/fullchain.pem" 2>/dev/null; then
    green "  certificate ready"; break
  fi
  [[ $i -eq 30 ]] && { red "  certificate not issued after 5 min — check: $COMPOSE logs certbot"; exit 1; }
  sleep 10
done

# ── 3. Mail server + webmail ─────────────────────────────────────────────
bold "[3/6] Starting mailserver + roundcube"
$COMPOSE up -d mailserver roundcube
printf '  waiting for postfix'
for i in $(seq 1 30); do
  if $COMPOSE exec -T mailserver ss -ltn 2>/dev/null | grep -q ':25 '; then echo; green "  mailserver up"; break; fi
  [[ $i -eq 30 ]] && { echo; red "  mailserver did not come up — check: $COMPOSE logs mailserver"; exit 1; }
  printf '.'; sleep 5
done

# ── 4. Accounts + aliases ────────────────────────────────────────────────
bold "[4/6] Creating mailboxes"
declare -A NEWPW
for u in "${ACCOUNTS[@]}"; do
  addr="$u@$DOMAIN"
  if $COMPOSE exec -T mailserver setup email list 2>/dev/null | grep -q "^\* $addr"; then
    echo "  $addr exists — skipped"
  else
    pw=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
    $COMPOSE exec -T mailserver setup email add "$addr" "$pw" >/dev/null
    NEWPW[$addr]=$pw
    green "  created $addr"
  fi
done
for pair in "${ALIASES[@]}"; do
  src="${pair%%:*}@$DOMAIN"; dst="${pair##*:}@$DOMAIN"
  $COMPOSE exec -T mailserver setup alias add "$src" "$dst" >/dev/null 2>&1 || true
done
echo "  aliases: postmaster@, abuse@, hostmaster@, webmaster@ → admin@"

# ── 5. DKIM ──────────────────────────────────────────────────────────────
bold "[5/6] DKIM key (rspamd, selector 'mail', 2048-bit)"
DKIM_DNS=deploy/mail/config/rspamd/dkim/rsa-2048-mail-$DOMAIN.public.dns.txt
if [[ ! -f $DKIM_DNS ]]; then
  $COMPOSE exec -T mailserver setup config dkim keytype rsa keysize 2048 selector mail domain "$DOMAIN" >/dev/null
  $COMPOSE restart mailserver >/dev/null
fi
DKIM_VALUE=$(tr -d '\n' < "$DKIM_DNS" | sed -E 's/.*"(v=DKIM1[^"]*)".*/\1/; s/"[[:space:]]*"//g')

# ── 6. Webmail behind nginx ──────────────────────────────────────────────
bold "[6/6] Reloading app nginx so webmail.$DOMAIN is served"
docker compose -f docker-compose.prod.yml exec -T frontend nginx -t >/dev/null 2>&1 \
  && docker compose -f docker-compose.prod.yml exec -T frontend nginx -s reload >/dev/null \
  || docker compose -f docker-compose.prod.yml restart frontend >/dev/null
green "  done"

# ── Summary ──────────────────────────────────────────────────────────────
SPF_INCLUDE=""
case "${RELAY_HOST:-}" in
  *smtp2go*) SPF_INCLUDE=" include:spf.smtp2go.com" ;;
  *brevo*)   SPF_INCLUDE=" include:spf.brevo.com" ;;
  *amazonaws*) SPF_INCLUDE=" include:amazonses.com" ;;
esac

echo
bold "════════════ DNS RECORDS — add these in Cloudflare → $DOMAIN → DNS ════════════"
cat <<EOF

  Type   Name                       Content                                              Proxy
  ----   ----                       -------                                              -----
  A      mail                       $(curl -4 -s https://ifconfig.me || echo 37.27.31.70)                                        DNS only (grey)
  A      webmail                    $(curl -4 -s https://ifconfig.me || echo 37.27.31.70)                                        Proxied (orange)
  MX     @                          mail.$DOMAIN   (priority 10)                 —
  TXT    @                          v=spf1 mx${SPF_INCLUDE} -all
  TXT    mail._domainkey            $DKIM_VALUE
  TXT    _dmarc                     v=DMARC1; p=quarantine; rua=mailto:admin@$DOMAIN; adkim=s; aspf=s; pct=100

  Delete the three route*.mx.cloudflare.net MX records first (disable
  Cloudflare Email Routing if they are locked).
EOF

if [[ ${#NEWPW[@]} -gt 0 ]]; then
  echo
  bold "════════════ NEW MAILBOX PASSWORDS — shown once, store them now ════════════"
  for a in "${!NEWPW[@]}"; do printf '  %-28s %s\n' "$a" "${NEWPW[$a]}"; done
  echo
  echo "  Reset later with:  $COMPOSE exec mailserver setup email update <address> <new-password>"
fi

echo
bold "Webmail:  https://webmail.$DOMAIN   (after the webmail A record propagates)"
bold "Clients:  IMAP $MAIL_HOSTNAME:993 (SSL)   SMTP $MAIL_HOSTNAME:587 (STARTTLS)   user = full address"
echo
echo "Verify once DNS has propagated:  bash deploy/mail/check-mail.sh"
