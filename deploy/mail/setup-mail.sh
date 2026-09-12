#!/usr/bin/env bash
# One-shot bootstrap for the self-hosted mail stack.
#
#   sudo bash deploy/mail/setup-mail.sh
#
# Idempotent: re-running skips accounts that already exist and reuses
# existing DKIM keys / certificates. Run from the repo root on the server.
#
# Flags:
#   --check   Run preconditions + Cloudflare token verification only, then
#             stop. Changes nothing. Use this to diagnose credential
#             problems without starting containers or contacting Let's
#             Encrypt. Exists so operators never have to paste complex
#             shell one-liners into a web console, which silently mangles
#             bracket and quote characters.
set -euo pipefail

CHECK_ONLY=0
[[ ${1:-} == --check ]] && CHECK_ONLY=1

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

# ── 0b. Migrate containers from the pre-rename compose project ───────────
# Before the project was pinned to "robustidps-mail" it inherited the
# directory name, colliding with the prod stack. Containers created then
# are invisible to compose now, so remove them and let this project
# recreate them. Their logs are still reachable via `docker logs <name>`.
for c in robustidps-certbot robustidps-mail robustidps-webmail; do
  [[ $CHECK_ONLY -eq 1 ]] && break          # --check must not remove anything
  docker inspect "$c" >/dev/null 2>&1 || continue
  owner=$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$c" 2>/dev/null || true)
  [[ -z $owner || $owner == robustidps-mail ]] && continue
  bold "[0/6] Removing stale container $c left by old compose project '$owner'"
  docker logs --tail=25 "$c" > "deploy/mail/${c}.last.log" 2>&1 || true
  echo "      previous output saved to deploy/mail/${c}.last.log"
  docker rm -f "$c" >/dev/null
done
# Empty cert volume from that project; refuses if still referenced, which is fine.
[[ $CHECK_ONLY -eq 1 ]] || docker volume rm robustidpsai_letsencrypt >/dev/null 2>&1 || true

# ── 0c. Verify the Cloudflare token BEFORE involving Let's Encrypt ───────
# Two cheap API calls that distinguish the two failure modes Cloudflare
# reports identically as error 9109. Without this, a bad credential sends
# certbot into repeated failed lookups, trips Cloudflare's auth rate
# limiter (10502/429), and burns ACME attempts for nothing.
bold "[0/6] Verifying Cloudflare API token"
CF_TOKEN=$(sed -n 's/^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=[[:space:]]*//p' \
           deploy/mail/cloudflare.ini | tr -d '"'\''\r\n[:space:]')
[[ -n $CF_TOKEN ]] || { red "  no dns_cloudflare_api_token found in deploy/mail/cloudflare.ini"; exit 1; }
echo "      token length: ${#CF_TOKEN} chars (Cloudflare API tokens are 40)"

CF_CODE=$(curl -s -o /tmp/cf_verify.$$ -w '%{http_code}' \
  https://api.cloudflare.com/client/v4/user/tokens/verify \
  -H "Authorization: Bearer $CF_TOKEN") || true
case "$CF_CODE" in
  200) green "  [1/2] token string is valid" ;;
  429) red "  Cloudflare is rate-limiting this IP: 'too many authentication failures'."
       red "  This clears on its own — wait 30-60 min and re-run. Do NOT retry in a loop."
       rm -f /tmp/cf_verify.$$; exit 1 ;;
  *)   red "  [1/2] token REJECTED by Cloudflare (HTTP $CF_CODE)"
       sed 's/^/      /' /tmp/cf_verify.$$ 2>/dev/null | head -5
       red "  The token string itself is wrong — permissions are not the issue here."
       red "  Re-copy it from Cloudflare -> My Profile -> API Tokens (it is shown once;"
       red "  use 'Roll' to generate a fresh value), then ensure cloudflare.ini reads"
       red "  exactly:   dns_cloudflare_api_token = <40 chars>"
       red "  with no quotes, trailing spaces, or line break inside the token."
       rm -f /tmp/cf_verify.$$; exit 1 ;;
esac
rm -f /tmp/cf_verify.$$

# The token can be valid yet unable to resolve the zone by name, which is
# precisely the call certbot makes first. Test that exact capability.
CF_ZONES=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  -H "Authorization: Bearer $CF_TOKEN") || true
if grep -q '"id"' <<<"$CF_ZONES" && grep -q '"success":true' <<<"$CF_ZONES"; then
  green "  [2/2] token can resolve zone $DOMAIN"
else
  red "  [2/2] token is valid but CANNOT look up zone '$DOMAIN'"
  sed 's/^/      /' <<<"$CF_ZONES" | head -5
  red "  certbot resolves the zone by name before writing the challenge record."
  red "  Add 'Zone / Zone / Read' to the token (keep 'Zone / DNS / Edit'), or confirm"
  red "  the token's Zone Resources include robustidps.ai. Then re-run this script."
  exit 1
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  echo
  green "All preconditions pass. Re-run without --check to install."
  exit 0
fi

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
  [[ $i -eq 30 ]] && {
    red "  certificate not issued after 5 min — certbot output follows:"
    echo
    $COMPOSE logs --no-log-prefix --tail=40 certbot | sed 's/^/    /'
    echo
    red "  Most common cause: the Cloudflare API token needs BOTH"
    red "    Zone / Zone / Read     and     Zone / DNS / Edit"
    red "  The 'Edit zone DNS' template includes both; a hand-built token often omits Zone:Read."
    red "  Fix the token, update deploy/mail/cloudflare.ini, then re-run this script."
    exit 1
  }
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
# The generated file splits the record across several quoted chunks:
#   mail._domainkey IN TXT ( "v=DKIM1; k=rsa; "
#           "p=MIIBIjANBg..." ) ;
# Concatenate every quoted chunk — a single-chunk regex silently drops p=.
DKIM_VALUE=$(grep -oE '"[^"]*"' "$DKIM_DNS" | tr -d '"' | tr -d '\n')
[[ $DKIM_VALUE == v=DKIM1*p=?* ]] || { red "DKIM extraction failed — inspect $DKIM_DNS manually"; exit 1; }

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
