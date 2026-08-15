#!/usr/bin/env bash
set -euo pipefail

component="${1:-}"
case "$component" in
  bot|monitor|dragon-den) ;;
  *) echo "usage: $0 bot|monitor|dragon-den" >&2; exit 64 ;;
esac

fail() {
  echo "ScamShield $component preflight: $*" >&2
  exit 78
}

[[ "${SCAMSHIELD_STORE_RAW_SAMPLES:-0}" == "0" ]] || \
  fail "raw sample storage must remain disabled in production"

check_dragon_den() {
  token="${DRAGON_DEN_BOT_TOKEN:-}"
  [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || \
    fail "DRAGON_DEN_BOT_TOKEN is missing or malformed"
  [[ -z "${SCAMSHIELD_TOKEN:-}" || "$token" != "${SCAMSHIELD_TOKEN}" ]] || \
    fail "the Dragon Den bot must use a dedicated Bot API token"
  [[ "${DRAGON_DEN_PROTECT_CONTENT:-1}" =~ ^[01]$ ]] || \
    fail "DRAGON_DEN_PROTECT_CONTENT must be 0 or 1"
  routes="${DRAGON_DEN_ROUTES_FILE:-/etc/scamshield/dragon-den-routes.json}"
  [[ -r "$routes" ]] || fail "Dragon Den route registry is unreadable"
  dragon_db="${DRAGON_DEN_DB:-/var/lib/scamshield/dragon-den/dragon-den.db}"
  [[ -d "$(dirname "$dragon_db")" && -w "$(dirname "$dragon_db")" ]] || \
    fail "Dragon Den database parent is not writable"
  /opt/scamshield/current/.venv/bin/python - "$routes" <<'PY' || \
    fail "Dragon Den route registry is invalid"
import sys
from scamshield.dragon_den import load_routes
load_routes(sys.argv[1])
PY
}

relay_enabled="${DRAGON_DEN_RELAY_ENABLED:-0}"
[[ "$relay_enabled" =~ ^[01]$ ]] || \
  fail "DRAGON_DEN_RELAY_ENABLED must be 0 or 1"

if [[ "$component" == "dragon-den" ]]; then
  [[ "$relay_enabled" == "0" ]] || \
    fail "standalone bot service must stay disabled when the Telethon relay is enabled"
  check_dragon_den
  exit 0
fi

pseudonym_key="${SCAMSHIELD_PSEUDONYM_KEY:-}"
[[ ${#pseudonym_key} -ge 32 ]] || \
  fail "SCAMSHIELD_PSEUDONYM_KEY is missing or too short"
[[ -d "${SCAMSHIELD_PALIMPSEST_ROOT:-}" ]] || \
  fail "Palimpsest release is missing"
[[ -f "${SCAMSHIELD_PALIMPSEST_ROOT}/scripts/scamshield_bridge.py" ]] || \
  fail "Palimpsest bridge is missing"

db="${SCAMSHIELD_DB:-/var/lib/scamshield/scamshield.db}"
[[ -d "$(dirname "$db")" && -w "$(dirname "$db")" ]] || \
  fail "database parent is not writable"

if [[ "$component" == "monitor" && "$relay_enabled" == "1" ]]; then
  check_dragon_den
fi

if [[ "$component" == "bot" ]]; then
  [[ "${SCAMSHIELD_TOKEN:-}" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || \
    fail "SCAMSHIELD_TOKEN is missing or malformed"
  [[ "${SCAMSHIELD_OWNER_ID:-}" =~ ^[0-9]+$ ]] || \
    fail "SCAMSHIELD_OWNER_ID must be numeric"
  exit 0
fi

[[ "${TELETHON_API_ID:-}" =~ ^[0-9]+$ ]] || \
  fail "TELETHON_API_ID must be numeric"
[[ "${TELETHON_API_HASH:-}" =~ ^[0-9A-Fa-f]{32}$ ]] || \
  fail "TELETHON_API_HASH must be 32 hexadecimal characters"

session_base="${SCAMSHIELD_SESSION:-/var/lib/scamshield/telegram/scamshield_monitor}"
if [[ "$session_base" == *.session ]]; then
  session_file="$session_base"
else
  session_file="${session_base}.session"
fi
[[ -s "$session_file" ]] || fail "authorized Telethon session is missing"
if ! session_mode="$(stat -c '%a' "$session_file" 2>/dev/null)"; then
  session_mode="$(stat -f '%Lp' "$session_file")"
fi
[[ "$session_mode" == "600" ]] || \
  fail "Telethon session permissions must be 0600"

channels="${SCAMSHIELD_CHANNELS_FILE:-/etc/scamshield/channels.txt}"
[[ -r "$channels" ]] || fail "channel registry is unreadable"
awk '
  /^[[:space:]]*#/ { next }
  /^[[:space:]]*$/ { next }
  { found=1; exit }
  END { exit(found ? 0 : 1) }
' "$channels" || fail "channel registry has no active sources"
