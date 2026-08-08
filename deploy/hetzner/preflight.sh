#!/usr/bin/env bash
set -euo pipefail

component="${1:-}"
case "$component" in
  bot|monitor) ;;
  *) echo "usage: $0 bot|monitor" >&2; exit 64 ;;
esac

fail() {
  echo "ScamShield $component preflight: $*" >&2
  exit 78
}

[[ "${SCAMSHIELD_STORE_RAW_SAMPLES:-0}" == "0" ]] || \
  fail "raw sample storage must remain disabled in production"
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
