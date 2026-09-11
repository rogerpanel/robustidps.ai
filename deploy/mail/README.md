# Self-hosted mail for robustidps.ai

Mailboxes for `roger@`, `admin@`, `support@`, `noreply@` on the Hetzner
box (37.27.31.70), fully under our control: Postfix + Dovecot + Rspamd
(docker-mailserver) with Roundcube webmail at `https://webmail.robustidps.ai`.

```
Internet ──25──▶ mail.robustidps.ai (DNS-only)  ┐
Clients ─465/587/993─▶                          ├─ robustidps-mail container
Roundcube ────────────▶                          ┘
Browser ──443─▶ webmail.robustidps.ai (Cloudflare) ─▶ app nginx ─▶ roundcube container
certbot (DNS-01 via Cloudflare API) ─▶ Let's Encrypt cert for mail.robustidps.ai
```

## Prerequisites (one-time, outside the server)

| # | Where | What |
|---|-------|------|
| 1 | Hetzner → server → Networking | Reverse DNS for 37.27.31.70 = `mail.robustidps.ai` ✅ done |
| 2 | Hetzner → Support / Limits | Request unblock of outbound port 25 ✅ requested |
| 3 | Cloudflare → My Profile → API Tokens | Token with **Zone / DNS / Edit** on `robustidps.ai` only (for certbot) |
| 4 | Cloudflare → SSL/TLS → Origin Server | Confirm the origin cert covers `*.robustidps.ai` (needed for webmail.) |
| 5 | Optional relay | SMTP2GO / Brevo / SES account → SMTP username + password |

## Install (on the server, ~10 min)

```bash
cd /home/robustidps/robustidps.ai
cp deploy/mail/.env.mail.example    deploy/mail/.env.mail        # edit: relay creds if using one
cp deploy/mail/cloudflare.ini.example deploy/mail/cloudflare.ini # edit: paste API token
chmod 600 deploy/mail/.env.mail deploy/mail/cloudflare.ini
sudo bash deploy/mail/setup-mail.sh
```

The script opens the firewall ports, issues the certificate, starts the
containers, creates the four mailboxes (prints their passwords **once**),
adds RFC-2142 aliases (`postmaster@`, `abuse@` → `admin@`), generates
the DKIM key, reloads nginx, and prints the exact DNS records to add.

## DNS cut-over (Cloudflare → robustidps.ai → DNS → Records)

1. **Remove Cloudflare Email Routing.** The `route1/2/3.mx.cloudflare.net`
   MX records belong to it. If they show a lock icon, click it — that
   opens the Email Routing page — disable routing there, then delete the
   three MX rows. Forwarding to Gmail stops at this point.
2. Add the records printed by the setup script:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | `mail` | `37.27.31.70` | **DNS only** |
| A | `webmail` | `37.27.31.70` | Proxied |
| MX | `@` | `mail.robustidps.ai` · priority 10 | — |
| TXT | `@` | `v=spf1 mx include:<relay-spf> -all` (drop `include:` if no relay) | — |
| TXT | `mail._domainkey` | `v=DKIM1; k=rsa; p=…` (from script output) | — |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:admin@robustidps.ai; adkim=s; aspf=s; pct=100` | — |

`mail` **must** stay DNS-only: Cloudflare's proxy only carries HTTP(S),
so an orange-clouded MX target silently breaks SMTP and IMAP.

3. Wait ~5 min, then `bash deploy/mail/check-mail.sh` — everything should be ✔.
4. Send a test from Roundcube to a Gmail address and open *Show original*:
   SPF, DKIM and DMARC must all say `PASS`.

## Day-to-day

```bash
M="docker compose -f docker-compose.mail.yml --env-file deploy/mail/.env.mail"
$M ps                                       # status
$M logs -f mailserver                       # live log
$M exec mailserver setup email list         # mailboxes
$M exec mailserver setup email add  x@robustidps.ai 'password'
$M exec mailserver setup email update x@robustidps.ai 'new-password'
$M exec mailserver setup alias add  sales@robustidps.ai roger@robustidps.ai
$M exec mailserver setup fail2ban   # banned IPs
$M exec mailserver setup email del  x@robustidps.ai
```

Mail clients (Thunderbird, Apple Mail, Outlook, phones):

| | Server | Port | Security | Username |
|---|---|---|---|---|
| Incoming IMAP | `mail.robustidps.ai` | 993 | SSL/TLS | full address |
| Outgoing SMTP | `mail.robustidps.ai` | 587 | STARTTLS | full address |

## Outbound relay vs direct send

Hetzner blocks outbound port 25 on this account today (`nc` to Gmail
times out). Two ways to send:

- **Relay (now):** fill `RELAY_*` in `.env.mail`; all outbound goes over
  587 to SMTP2GO/Brevo/SES. Add their `include:` to SPF. Inbound and
  storage remain entirely on our server.
- **Direct (after the Hetzner ticket clears):** blank out `RELAY_HOST`,
  remove the `include:` from SPF, `$M up -d mailserver`. Expect Gmail to
  route the first days of mail from a brand-new IP to spam; keep volume
  low and consistent while the reputation builds.

## The platform sending as noreply@

Backend SMTP settings for verification / privilege emails (wire-up is a
follow-up in `backend/`):

```
SMTP_HOST=robustidps-mail   # container name on the app network — or mail.robustidps.ai
SMTP_PORT=587
SMTP_STARTTLS=1
SMTP_USER=noreply@robustidps.ai
SMTP_PASSWORD=<from setup output>
SMTP_FROM="RobustIDPS <noreply@robustidps.ai>"
```

## Backups

Everything lives in three named volumes: `robustidpsai_dms-data` (mail),
`robustidpsai_dms-state` (rspamd/fail2ban state), `robustidpsai_roundcube-db`.
Plus `deploy/mail/config/` (accounts, aliases, **DKIM private key**) —
back this directory up and never commit it.

```bash
docker run --rm -v robustidpsai_dms-data:/data -v "$PWD/backups":/out alpine \
  tar czf /out/mail-$(date +%F).tgz -C /data .
```

## Later (optional hardening)

- **MTA-STS + TLS-RPT** — forces TLS on inbound; needs a tiny static
  site at `mta-sts.robustidps.ai`. Add once the basics are stable.
- **ClamAV** — `ENABLE_CLAMAV=1` in the compose file (+1.5 GB RAM).
- **IPv6** — assign an address from the /64, set its PTR in Hetzner, add
  an AAAA for `mail`, then set `*_INET_PROTOCOLS=all`.
- **Backup MX** — a second cheap VPS or a relay's inbound queue so mail
  is held rather than bounced while this box is down.
- **DMARC reports** — Cloudflare → Email → DMARC Management can ingest
  the `rua` reports if you point `rua` at the address it gives you.
