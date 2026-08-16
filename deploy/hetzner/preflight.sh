#!/usr/bin/env bash
set -euo pipefail

component="${1:-}"
case "$component" in
  bot|monitor|dragon-den|social-export) ;;
  *) echo "usage: $0 bot|monitor|dragon-den|social-export" >&2; exit 64 ;;
esac

fail() {
  echo "ScamShield $component preflight: $*" >&2
  exit 78
}

[[ "${SCAMSHIELD_STORE_RAW_SAMPLES:-0}" == "0" ]] || \
  fail "raw sample storage must remain disabled in production"

social_enabled="${SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED:-0}"
[[ "$social_enabled" =~ ^[01]$ ]] || \
  fail "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED must be 0 or 1"

check_social_collection() {
  social_db=/var/lib/scamshield/social/social-observations.db
  social_registry=/etc/scamshield/palimpsest-social-sources.json
  social_public_registry=/opt/palimpsest/current/config/social_sources.json
  social_output=/var/lib/scamshield/social-export
  [[ "${SCAMSHIELD_SOCIAL_DB:-$social_db}" == "$social_db" ]] || \
    fail "SCAMSHIELD_SOCIAL_DB cannot override the private production path"
  [[ "${SCAMSHIELD_SOCIAL_SOURCES_FILE:-$social_registry}" == "$social_registry" ]] || \
    fail "SCAMSHIELD_SOCIAL_SOURCES_FILE cannot override the production registry"
  [[ "${SCAMSHIELD_SOCIAL_OUTPUT_DIR:-$social_output}" == "$social_output" ]] || \
    fail "SCAMSHIELD_SOCIAL_OUTPUT_DIR cannot override the public production path"
  [[ "$(stat -c '%a:%U:%G' /var/lib/scamshield)" == \
     "3771:root:scamshield" ]] || \
    fail "state parent ownership/mode must be root:scamshield 3771"
  [[ -f "$social_registry" && ! -L "$social_registry" && -r "$social_registry" ]] || \
    fail "social publisher registry must be a readable regular file"
  [[ "$(stat -c '%a:%U:%G' "$social_registry")" == \
     "640:root:scamshield-runtime" ]] || \
    fail "social publisher registry ownership/mode must be root:scamshield-runtime 0640"
  social_signing_origin=/etc/scamshield/social-export-hmac.key
  [[ -f "$social_signing_origin" && ! -L "$social_signing_origin" && \
     "$(stat -c '%a:%U:%G' "$social_signing_origin")" == "600:root:root" ]] || \
    fail "social export signing credential ownership/mode must be root:root 0600"
  social_signing_size="$(stat -c '%s' "$social_signing_origin")"
  (( social_signing_size >= 32 && social_signing_size <= 4096 )) || \
    fail "enabled social lane requires a bounded dedicated signing credential"
  [[ -f "$social_public_registry" && ! -L "$social_public_registry" && \
     -r "$social_public_registry" ]] || \
    fail "pinned Palimpsest social publisher registry must be a readable regular file"
  [[ ! -e /var/lib/scamshield/social-observations.db && \
     ! -L /var/lib/scamshield/social-observations.db ]] || \
    fail "legacy social database requires a quiesced migration to the private path"
  social_db_parent="$(dirname "$social_db")"
  [[ -d "$social_db_parent" && ! -L "$social_db_parent" && \
     -r "$social_db_parent" && -x "$social_db_parent" ]] || \
    fail "private social database parent is not accessible"
  [[ "$(stat -c '%a:%U:%G' "$social_db_parent")" == \
     "2750:scamshield:scamshield-social" ]] || \
    fail "private social database parent ownership/mode is invalid"
  [[ -d "$social_output" && ! -L "$social_output" && \
     "$(stat -c '%a:%U:%G' "$social_output")" == \
     "2750:scamshield-social-export:caddy" ]] || \
    fail "social export directory ownership/mode is invalid"
  social_generations="$social_output/generations"
  [[ -d "$social_generations" && ! -L "$social_generations" && \
     "$(stat -c '%a:%U:%G' "$social_generations")" == \
     "2750:scamshield-social-export:caddy" ]] || \
    fail "social export generations ownership/mode is invalid"
  if [[ "$component" == "monitor" ]]; then
    [[ -w "$social_db_parent" ]] || \
      fail "monitor cannot write the private social database parent"
  fi
  if [[ -e "$social_db" ]]; then
    [[ -f "$social_db" && ! -L "$social_db" ]] || \
      fail "social observation spool must be a regular file"
    [[ "$(stat -c '%a:%U:%G' "$social_db")" == \
       "640:scamshield:scamshield-social" ]] || \
      fail "social observation spool ownership/mode is invalid"
  fi
  for social_db_aux in "${social_db}-wal" "${social_db}-shm"; do
    if [[ -e "$social_db_aux" || -L "$social_db_aux" ]]; then
      [[ -f "$social_db_aux" && ! -L "$social_db_aux" && \
         "$(stat -c '%a:%U:%G' "$social_db_aux")" == \
         "640:scamshield:scamshield-social" ]] || \
        fail "social observation WAL member ownership/mode is invalid"
    fi
  done
  social_staleness="${SCAMSHIELD_SOCIAL_MAX_STALENESS_SECONDS:-900}"
  [[ "$social_staleness" =~ ^[0-9]+$ ]] || \
    fail "social export staleness must be numeric"
  (( social_staleness >= 60 && social_staleness <= 86400 )) || \
    fail "social export staleness must be 60..86400 seconds"
  PYTHONPATH=/opt/scamshield/current \
    /opt/scamshield/current/.venv/bin/python - \
      "$social_registry" "$social_public_registry" <<'PY' || \
    fail "social registry projection does not match pinned Palimpsest"
import sys
from scamshield.social_observation_spool import validate_public_registry_projection
validate_public_registry_projection(sys.argv[1], sys.argv[2])
PY
}

if [[ "$social_enabled" == "1" && \
      ( "$component" == "monitor" || "$component" == "social-export" ) ]]; then
  check_social_collection
fi

if [[ "$component" == "social-export" ]]; then
  # A disabled opt-in lane is a successful no-op. This allows the hardened
  # timer to be installed before the separately managed credential is filled.
  [[ "$social_enabled" == "1" ]] || exit 0
  [[ -r /var/lib/scamshield/social/social-observations.db ]] || \
    fail "social observation spool is unreadable"
  [[ -w /var/lib/scamshield/social-export ]] || \
    fail "social export directory is not writable"
  social_credential="${CREDENTIALS_DIRECTORY:-}/social_export_hmac"
  if [[ -z "${CREDENTIALS_DIRECTORY:-}" ]]; then
    social_credential=/etc/scamshield/social-export-hmac.key
  fi
  [[ -f "$social_credential" && ! -L "$social_credential" && \
     -r "$social_credential" ]] || \
    fail "social export signing credential is unreadable"
  (( $(stat -c '%s' "$social_credential") <= 4096 )) || \
    fail "social export signing credential is too large"
  (( $(tr -d '[:space:]' < "$social_credential" | wc -c) >= 32 )) || \
    fail "social export signing credential is too short"
  exit 0
fi

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
