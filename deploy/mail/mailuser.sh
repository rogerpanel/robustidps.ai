#!/usr/bin/env bash
# Manage robustidps.ai mailboxes without hand-writing docker commands.
#
#   sudo bash deploy/mail/mailuser.sh <command> [args]
#
#   list                      show every mailbox and its disk usage
#   add     <user>            create a mailbox (prompts for a password,
#                             or press Enter to generate a strong one)
#   passwd  <user>            set a new password for an existing mailbox
#   delete  <user>            remove a mailbox and all of its mail
#   alias   <from> <to>       deliver <from> into the <to> mailbox
#   aliases                   list every alias
#   unalias <from> <to>       remove an alias
#   quota   <user> <size>     set a storage limit, e.g. 2G (0 = unlimited)
#
# <user> may be "sarah" or "sarah@robustidps.ai" — the domain is added
# when omitted. Requires root because it talks to the container.
set -euo pipefail

DOMAIN=robustidps.ai
CONTAINER=robustidps-mail
ACCOUNTS_FILE="$(cd "$(dirname "$0")/../.." && pwd)/deploy/mail/config/postfix-accounts.cf"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

[[ $# -ge 1 ]] || usage 1
[[ ${EUID:-$(id -u)} -eq 0 ]] || { red "Run with sudo: sudo bash $0 $*"; exit 1; }
docker inspect "$CONTAINER" >/dev/null 2>&1 || {
  red "Container $CONTAINER not found. Is the mail stack running?"
  red "  docker ps --filter name=$CONTAINER"
  exit 1
}
[[ $(docker inspect -f '{{.State.Status}}' "$CONTAINER") == running ]] || {
  red "Container $CONTAINER is not running."
  exit 1
}

# Accept a bare username or a full address.
qualify() { case $1 in *@*) printf '%s' "$1" ;; *) printf '%s@%s' "$1" "$DOMAIN" ;; esac; }

# Exact field match against the account store, not a substring search:
# "oger@d|" is a substring of "roger@d|" and would report the wrong answer.
exists() {
  [[ -f $ACCOUNTS_FILE ]] &&
    awk -F'|' -v a="$1" '$1 == a { f = 1 } END { exit !f }' "$ACCOUNTS_FILE"
}

read_password() {
  local p1 p2
  read -rsp "  Password (Enter to generate one): " p1; echo
  if [[ -z $p1 ]]; then
    p1=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)
    green "  Generated: $p1"
    echo   "  Copy it now — it is not stored anywhere retrievable."
  else
    read -rsp "  Confirm password: " p2; echo
    [[ $p1 == "$p2" ]] || { red "  Passwords do not match."; return 1; }
    [[ ${#p1} -ge 8 ]] || { red "  Use at least 8 characters."; return 1; }
  fi
  printf '%s' "$p1"
}

cmd=$1; shift || true

case $cmd in

  list)
    bold "Mailboxes on $DOMAIN"
    docker exec "$CONTAINER" setup email list 2>/dev/null | sed 's/^/  /' \
      || red "  could not read the mailbox list"
    ;;

  add)
    [[ $# -ge 1 ]] || { red "Usage: $0 add <user>"; exit 1; }
    addr=$(qualify "$1")
    exists "$addr" && { red "$addr already exists. Use 'passwd' to change its password."; exit 1; }
    bold "Creating $addr"
    pw=$(read_password) || exit 1
    docker exec "$CONTAINER" setup email add "$addr" "$pw" >/dev/null
    green "Created $addr"
    echo
    echo "  Webmail:  https://webmail.$DOMAIN"
    echo "  IMAP:     mail.$DOMAIN  port 993  SSL/TLS"
    echo "  SMTP:     mail.$DOMAIN  port 587  STARTTLS"
    echo "  Username: $addr  (the full address, not just the name)"
    ;;

  passwd)
    [[ $# -ge 1 ]] || { red "Usage: $0 passwd <user>"; exit 1; }
    addr=$(qualify "$1")
    exists "$addr" || { red "$addr does not exist. Use 'add' to create it."; exit 1; }
    bold "New password for $addr"
    pw=$(read_password) || exit 1
    docker exec "$CONTAINER" setup email update "$addr" "$pw" >/dev/null
    green "Password changed for $addr"
    echo "  Existing sessions stay signed in until they sign out."
    ;;

  delete)
    [[ $# -ge 1 ]] || { red "Usage: $0 delete <user>"; exit 1; }
    addr=$(qualify "$1")
    exists "$addr" || { red "$addr does not exist."; exit 1; }
    red "This permanently deletes $addr AND every message in it."
    read -rp "Type the full address to confirm: " confirm
    [[ $confirm == "$addr" ]] || { echo "Cancelled — nothing changed."; exit 1; }
    docker exec "$CONTAINER" setup email del -y "$addr" >/dev/null
    green "Deleted $addr"
    ;;

  alias)
    [[ $# -ge 2 ]] || { red "Usage: $0 alias <from> <to>"; exit 1; }
    src=$(qualify "$1"); dst=$(qualify "$2")
    exists "$dst" || red "Note: $dst is not a local mailbox — forwarding offsite."
    docker exec "$CONTAINER" setup alias add "$src" "$dst" >/dev/null
    green "$src now delivers to $dst"
    ;;

  aliases)
    bold "Aliases on $DOMAIN"
    docker exec "$CONTAINER" setup alias list 2>/dev/null | sed 's/^/  /' \
      || echo "  none"
    ;;

  unalias)
    [[ $# -ge 2 ]] || { red "Usage: $0 unalias <from> <to>"; exit 1; }
    src=$(qualify "$1"); dst=$(qualify "$2")
    docker exec "$CONTAINER" setup alias del "$src" "$dst" >/dev/null
    green "Removed alias $src -> $dst"
    ;;

  quota)
    [[ $# -ge 2 ]] || { red "Usage: $0 quota <user> <size>   e.g. quota sarah 2G"; exit 1; }
    addr=$(qualify "$1")
    exists "$addr" || { red "$addr does not exist."; exit 1; }
    if [[ $2 == 0 ]]; then
      docker exec "$CONTAINER" setup quota del "$addr" >/dev/null
      green "Quota removed for $addr (unlimited)"
    else
      docker exec "$CONTAINER" setup quota set "$addr" "$2" >/dev/null
      green "Quota for $addr set to $2"
    fi
    ;;

  -h|--help|help) usage 0 ;;
  *) red "Unknown command: $cmd"; echo; usage 1 ;;
esac
