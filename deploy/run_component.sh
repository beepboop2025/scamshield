#!/bin/zsh
set -euo pipefail

ROOT="/Users/mrinal/dev/scamshield"
PALIMPSEST_ROOT="/Users/mrinal/palimpsest-site"
KEYCHAIN_ACCOUNT="mrinal"
KEYCHAIN_SERVICE="com.scamshield.pseudonym-key"

component="${1:-}"
case "$component" in
  bot)
    program="bot.py"
    ;;
  monitor)
    program="monitor.py"
    if [[ ! -f "$ROOT/scamshield_monitor.session" ]]; then
      print -u2 "ScamShield monitor session is missing; run login.py once."
      exit 78
    fi
    ;;
  *)
    print -u2 "usage: $0 bot|monitor"
    exit 64
    ;;
esac

pseudonym_key="$(/usr/bin/security find-generic-password \
  -w -a "$KEYCHAIN_ACCOUNT" -s "$KEYCHAIN_SERVICE")"
if [[ -z "$pseudonym_key" ]]; then
  print -u2 "ScamShield pseudonym key is unavailable in Keychain."
  exit 78
fi

umask 077
export SCAMSHIELD_PSEUDONYM_KEY="$pseudonym_key"
export SCAMSHIELD_PALIMPSEST_ROOT="$PALIMPSEST_ROOT"
export SCAMSHIELD_PALIMPSEST_OUTBOX="var/scamshield-inbox"
export SCAMSHIELD_SHARE_MIN_TIER="WATCH"
export SCAMSHIELD_DB="$ROOT/scamshield.db"
export SCAMSHIELD_STORE_RAW_SAMPLES="0"
export SCAMSHIELD_GUARDIAN="0"
export PYTHONUNBUFFERED="1"
unset pseudonym_key

cd "$ROOT"
exec "$ROOT/.venv/bin/python" "$ROOT/$program"
