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
| 2 | Hetzner → Support / Limits | Unblock outbound port 25 ✅ **granted** — verified with `nc -zv gmail-smtp-in.l.google.com 25` |
| 3 | Cloudflare → My Profile → API Tokens | Use the **Edit zone DNS** template, scoped to `robustidps.ai`. It must carry **both** `Zone / Zone / Read` *and* `Zone / DNS / Edit` — certbot looks the zone up by name before writing the challenge record, so a DNS:Edit-only token fails. |
| 4 | Cloudflare → SSL/TLS → Origin Server | Origin cert covers `*.robustidps.ai` ✅ confirmed (webmail. is served under it) |
| 5 | Outbound relay | **Not needed** — port 25 is open, mail sends direct from 37.27.31.70 |

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
| TXT | `@` | `v=spf1 mx -all` | — |
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

## Outbound: direct send

Hetzner has unblocked outbound port 25 for this server, so mail is
delivered straight from 37.27.31.70 with no third party in the path.
`RELAY_*` in `.env.mail` stays empty and SPF stays `v=spf1 mx -all`.

The IP has no sending history, so warm it up: keep early volume low and
steady rather than sending a burst. Expect some providers to greylist or
spam-folder the first messages even with SPF, DKIM and DMARC all passing
— reputation accrues over days. rDNS is already set to mail.robustidps.ai,
which is the single biggest factor after authentication.

If deliverability ever needs a shortcut, `RELAY_HOST`/`RELAY_PORT`/
`RELAY_USER`/`RELAY_PASSWORD` route outbound through SMTP2GO, Brevo or
SES over port 587; add that provider's `include:` to SPF at the same
time. Inbound and storage stay on this server either way.

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

Everything lives in three named volumes: `robustidps-mail_dms-data` (mail),
`robustidps-mail_dms-state` (rspamd/fail2ban state), `robustidps-mail_roundcube-db`.
Plus `deploy/mail/config/` (accounts, aliases, **DKIM private key**) —
back this directory up and never commit it.

```bash
docker run --rm -v robustidps-mail_dms-data:/data -v "$PWD/backups":/out alpine \
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
