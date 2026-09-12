#!/usr/bin/env bash
# Post-DNS sanity check for the mail stack. Safe to run any time.
#   bash deploy/mail/check-mail.sh
set -uo pipefail
DOMAIN=robustidps.ai
HOST=mail.$DOMAIN
command -v dig >/dev/null || { echo "dig not found — install it first:  apt-get install -y dnsutils"; exit 1; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✘\033[0m %s\n' "$*"; }
info() { printf '  \033[2m  %s\033[0m\n' "$*"; }

echo "DNS"
mx=$(dig +short MX "$DOMAIN" | sort -n | head -1)
[[ $mx == *"$HOST"* ]] && ok "MX → $mx" || bad "MX is '$mx' (expected 10 $HOST.)"
a=$(dig +short A "$HOST"); [[ -n $a ]] && ok "A $HOST → $a" || bad "no A record for $HOST"
ptr=$(dig +short -x "${a:-0.0.0.0}"); [[ $ptr == "$HOST." ]] && ok "PTR $a → $ptr" || bad "PTR is '$ptr' (expected $HOST.)"
spf=$(dig +short TXT "$DOMAIN" | grep v=spf1); [[ -n $spf ]] && ok "SPF $spf" || bad "no SPF record"
dkim=$(dig +short TXT "mail._domainkey.$DOMAIN" | grep -c v=DKIM1); [[ $dkim -gt 0 ]] && ok "DKIM mail._domainkey present" || bad "no DKIM record at mail._domainkey.$DOMAIN"
# Compare the published key against the one this server signs with. The
# record is ~400 base64 characters copied by hand into a web form, and a
# single altered character makes every signature fail verification while
# the record still *looks* correct. Presence alone proves nothing.
dkim_file=$(find deploy/mail/config -path '*dkim*' -name '*.public.dns.txt' 2>/dev/null | head -1)
if [[ -n $dkim_file && -r $dkim_file ]]; then
  pub=$(dig +short TXT "mail._domainkey.$DOMAIN" | tr -d '" ' | grep -oE 'p=[A-Za-z0-9+/=]+' | head -1 | cut -d= -f2-)
  loc=$(tr -d '\n\r" ' < "$dkim_file" | grep -oE 'p=[A-Za-z0-9+/=]+' | head -1 | cut -d= -f2-)
  if [[ -z $pub ]]; then
    bad "DKIM published record has no p= key"
  elif [[ "$pub" == "$loc" ]]; then
    ok "DKIM key in DNS matches this server (${#loc} chars)"
  else
    bad "DKIM key MISMATCH — signatures will fail verification"
    info "published: ${#pub} chars, server: ${#loc} chars"
    info "re-copy the value from $dkim_file into the mail._domainkey TXT record"
  fi
elif [[ -n $dkim_file ]]; then
  info "DKIM key file not readable as $(id -un); re-run with sudo to compare it against DNS"
fi
dmarc=$(dig +short TXT "_dmarc.$DOMAIN" | grep v=DMARC1); [[ -n $dmarc ]] && ok "DMARC $dmarc" || bad "no DMARC record"

echo "Ports (from this host)"
for p in 25 465 587 993; do
  timeout 5 bash -c "</dev/tcp/$HOST/$p" 2>/dev/null && ok "$HOST:$p open" || bad "$HOST:$p closed"
done

echo "TLS"
exp=$(echo | timeout 8 openssl s_client -connect "$HOST:993" -servername "$HOST" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
[[ -n $exp ]] && ok "IMAPS cert valid until $exp" || bad "could not read IMAPS certificate"
cn=$(echo | timeout 8 openssl s_client -connect "$HOST:993" -servername "$HOST" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
[[ $cn == *"$HOST"* ]] && ok "cert subject matches $HOST" || bad "cert subject: ${cn:-none}"

echo "Outbound"
if timeout 5 bash -c '</dev/tcp/gmail-smtp-in.l.google.com/25' 2>/dev/null; then
  ok "port 25 outbound open — direct delivery possible"
else
  bad "port 25 outbound blocked (Hetzner) — relay required until support unblocks it"
fi

echo "Containers"
docker compose -f docker-compose.mail.yml --env-file deploy/mail/.env.mail ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null | sed 's/^/  /'

echo
info "Send a test to a Gmail address, then check the headers: SPF=pass, DKIM=pass, DMARC=pass."
info "Or mail check-auth@verifier.port25.com and read the automated report."
