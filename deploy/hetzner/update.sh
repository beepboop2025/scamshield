#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ScamShield deployment must run as root" >&2
  exit 77
fi

target="${1:-}"
mode="${2:-}"
[[ "$target" =~ ^[0-9a-f]{40}$ ]] || {
  echo "usage: $0 <40-character-scamshield-commit> [--no-restart]" >&2
  exit 64
}
[[ -z "$mode" || "$mode" == "--no-restart" ]] || {
  echo "unknown mode: $mode" >&2
  exit 64
}

exec 9>/run/lock/scamshield-deploy.lock
flock -n 9 || {
  echo "another ScamShield deployment is in progress" >&2
  exit 75
}

scam_source=/opt/scamshield/source
scam_releases=/opt/scamshield/releases
scam_current=/opt/scamshield/current
pal_source=/opt/palimpsest/source
pal_releases=/opt/palimpsest/releases
pal_current=/opt/palimpsest/current

[[ -d "$scam_source/.git" && -d "$pal_source/.git" ]] || {
  echo "source clones are missing; run deploy/hetzner/install.sh first" >&2
  exit 78
}

getent group intelligence-review >/dev/null 2>&1 || \
  groupadd --system intelligence-review
getent group caddy >/dev/null 2>&1 || groupadd --system caddy
getent group scamshield-social >/dev/null 2>&1 || \
  groupadd --system scamshield-social
if ! command -v setfacl >/dev/null || ! command -v getfacl >/dev/null; then
  echo "ACL utilities are required; rerun deploy/hetzner/install.sh" >&2
  exit 78
fi
if ! getent passwd scamshield-social-export >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
    --gid scamshield-social scamshield-social-export
fi
usermod --append --groups intelligence-review scamshield
usermod --append --groups scamshield-social scamshield
usermod --gid scamshield-social scamshield-social-export
gpasswd --delete scamshield-social-export scamshield-runtime \
  >/dev/null 2>&1 || true
if id -nG scamshield-social-export | tr ' ' '\n' | \
    grep -Fxq scamshield-runtime; then
  echo "refusing social exporter access to the shared runtime-secret group" >&2
  exit 65
fi
chown root:scamshield /var/lib/scamshield
chmod 3771 /var/lib/scamshield
install -d -o scamshield -g intelligence-review -m 2750 \
  /var/lib/scamshield/handoffs/narcoscope

git -C "$scam_source" fetch --prune origin master
git -C "$scam_source" cat-file -e "${target}^{commit}"
git -C "$scam_source" merge-base --is-ancestor "$target" origin/master || {
  echo "refusing a commit that is not on origin/master" >&2
  exit 65
}

scam_release="$scam_releases/$target"
if [[ ! -f "$scam_release/.deploy-ready" ]]; then
  if [[ -e "$scam_release" ]]; then
    mv "$scam_release" "${scam_release}.failed.$(date -u +%Y%m%dT%H%M%SZ)"
    git -C "$scam_source" worktree prune
  fi
  git -C "$scam_source" worktree add --detach "$scam_release" "$target"
  python3 -m venv "$scam_release/.venv"
  "$scam_release/.venv/bin/pip" install -q --disable-pip-version-check \
    -r "$scam_release/requirements.txt" pytest
  "$scam_release/.venv/bin/python" -m unittest discover \
    -s "$scam_release/tests" -v
  "$scam_release/.venv/bin/python" -m compileall -q \
    "$scam_release/scamshield" "$scam_release/bot.py" \
    "$scam_release/dragon_den_bot.py" \
    "$scam_release/monitor.py" "$scam_release/login.py" \
    "$scam_release/export_monitoring_summary.py" \
    "$scam_release/export_social_observations.py" \
    "$scam_release/manage_sources.py"
  touch "$scam_release/.deploy-ready"
fi

pal_revision="$(tr -d '[:space:]' < "$scam_release/deploy/hetzner/palimpsest.rev")"
[[ "$pal_revision" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid Palimpsest revision pin" >&2
  exit 65
}
git -C "$pal_source" fetch --prune origin main
git -C "$pal_source" cat-file -e "${pal_revision}^{commit}"
git -C "$pal_source" merge-base --is-ancestor "$pal_revision" origin/main || {
  echo "pinned Palimpsest revision is not on origin/main" >&2
  exit 65
}

pal_release="$pal_releases/$pal_revision"
if [[ ! -f "$pal_release/.deploy-ready" ]]; then
  if [[ -e "$pal_release" ]]; then
    mv "$pal_release" "${pal_release}.failed.$(date -u +%Y%m%dT%H%M%SZ)"
    git -C "$pal_source" worktree prune
  fi
  git -C "$pal_source" worktree add --detach "$pal_release" "$pal_revision"
  mkdir -p "$pal_release/var/scamshield-inbox"
  "$scam_release/.venv/bin/python" -m pytest -q \
    "$pal_release/tests/test_scamshield_adapter.py" \
    "$pal_release/tests/test_evidence_capsule_adapter_hardening.py"
  touch "$pal_release/.deploy-ready"
fi

chmod -R a+rX "$scam_release" "$pal_release"

social_parent_locked=1
restore_social_parent_mode() {
  if (( social_parent_locked )); then
    chmod 3771 /var/lib/scamshield >/dev/null 2>&1 || true
  fi
}
trap restore_social_parent_mode EXIT
chmod 3751 /var/lib/scamshield
for social_path in /var/lib/scamshield/social \
                   /var/lib/scamshield/social-export; do
  if [[ -e "$social_path" || -L "$social_path" ]]; then
    [[ -d "$social_path" && ! -L "$social_path" ]] || {
      echo "refusing unsafe social path: $social_path" >&2
      exit 65
    }
  fi
done
social_output=/var/lib/scamshield/social-export
legacy_output=""
legacy_output_owner=""
legacy_output_mode=""
install -d -o scamshield -g scamshield-social -m 2750 \
  /var/lib/scamshield/social
social_db=/var/lib/scamshield/social/social-observations.db
harden_social_database_members() {
  python3 - "$(dirname "$social_db")" <<'PY'
import grp
import os
import pwd
import stat
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


if not hasattr(os, "O_NOFOLLOW"):
    fail("this host cannot safely open private social database members")

directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
try:
    directory_fd = os.open(sys.argv[1], directory_flags)
except OSError:
    fail("private social database directory is unsafe")

try:
    directory = os.fstat(directory_fd)
    expected_uid = pwd.getpwnam("scamshield").pw_uid
    expected_gid = grp.getgrnam("scamshield-social").gr_gid
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != expected_uid
        or directory.st_gid != expected_gid
        or stat.S_IMODE(directory.st_mode) != 0o2750
    ):
        fail("private social database directory ownership or mode is unsafe")

    member_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    for member in ("social-observations.db", "social-observations.db-wal", "social-observations.db-shm"):
        try:
            descriptor = os.open(member, member_flags, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        except OSError:
            fail("private social database member cannot be opened safely")
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail("private social database member is not a unique regular file")
            os.fchown(descriptor, expected_uid, expected_gid)
            os.fchmod(descriptor, 0o640)
        finally:
            os.close(descriptor)
finally:
    os.close(directory_fd)
PY
}
if ! harden_social_database_members; then
  echo "refusing unsafe private social database state" >&2
  exit 65
fi
if [[ -e /etc/scamshield || -L /etc/scamshield ]]; then
  [[ -d /etc/scamshield && ! -L /etc/scamshield ]] || {
    echo "refusing unsafe ScamShield configuration directory" >&2
    exit 65
  }
fi
install -d -o root -g scamshield-runtime -m 0750 /etc/scamshield
if [[ -L /etc/scamshield/social-export-hmac.key ]]; then
  echo "social export signing credential must not be a symlink" >&2
  exit 65
elif [[ ! -e /etc/scamshield/social-export-hmac.key ]]; then
  install -o root -g root -m 0600 /dev/null \
    /etc/scamshield/social-export-hmac.key
fi
[[ -f /etc/scamshield/social-export-hmac.key && \
   ! -L /etc/scamshield/social-export-hmac.key ]] || {
  echo "social export signing credential must be a regular file" >&2
  exit 65
}
chown root:root /etc/scamshield/social-export-hmac.key
chmod 0600 /etc/scamshield/social-export-hmac.key
social_registry=/etc/scamshield/palimpsest-social-sources.json
if [[ -L "$social_registry" ]]; then
  echo "refusing symlinked social publisher registry: $social_registry" >&2
  exit 65
elif [[ ! -e "$social_registry" ]]; then
  install -o root -g scamshield-runtime -m 0640 \
    "$scam_release/palimpsest-social-sources.example.json" \
    "$social_registry"
elif [[ ! -f "$social_registry" ]]; then
  echo "social publisher registry is not a regular file: $social_registry" >&2
  exit 65
else
  # Preserve operator-reviewed contents while restoring the deployment-owned
  # access boundary if permissions drifted.
  chown root:scamshield-runtime "$social_registry"
  chmod 0640 "$social_registry"
fi
# Grant the exporter only search permission on the configuration directory and
# read permission on this one public-projection registry. It is not a member of
# scamshield-runtime and therefore cannot read the shared environment, channel
# allowlist, session, routes, or any future runtime-group secret.
setfacl -m u:scamshield-social-export:--x /etc/scamshield
setfacl -m u:scamshield-social-export:r-- "$social_registry"

if ! social_enabled="$(awk -F= '
  {
    key = $1
    sub(/^[ \t]+/, "", key)
    sub(/[ \t]+$/, "", key)
  }
  key == "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED" {
    if (++seen > 1) {
      exit 2
    }
    value = substr($0, index($0, "=") + 1)
    sub(/\r$/, "", value)
    sub(/^[ \t]+/, "", value)
    sub(/[ \t]+$/, "", value)
    first = substr(value, 1, 1)
    last = substr(value, length(value), 1)
    if (length(value) >= 2 && first == last && (first == "\"" || first == "\047")) {
      value = substr(value, 2, length(value) - 2)
    }
    print value
  }
' /etc/scamshield/scamshield.env)"; then
  echo "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED must be assigned at most once" >&2
  exit 65
fi
social_enabled="${social_enabled:-0}"
[[ "$social_enabled" =~ ^[01]$ ]] || {
  echo "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED must be 0 or 1" >&2
  exit 65
}
if [[ "$social_enabled" == "1" ]]; then
  social_credential=/etc/scamshield/social-export-hmac.key
  (( $(stat -c '%s' "$social_credential") <= 4096 )) || {
    echo "social export signing credential is too large" >&2
    exit 65
  }
  (( $(tr -d '[:space:]' < "$social_credential" | wc -c) >= 32 )) || {
    echo "enabled social lane requires a dedicated signing credential" >&2
    exit 65
  }
  if [[ -e /var/lib/scamshield/social-observations.db ]]; then
    echo "enabled social lane requires a quiesced migration of the legacy database" >&2
    exit 65
  fi
  pal_social_registry="$pal_release/config/social_sources.json"
  [[ -f "$pal_social_registry" && ! -L "$pal_social_registry" ]] || {
    echo "enabled social lane requires the pinned Palimpsest registry" >&2
    exit 65
  }
  PYTHONPATH="$scam_release" "$scam_release/.venv/bin/python" - \
      "$social_registry" "$pal_social_registry" <<'PY' || {
import sys
from scamshield.social_observation_spool import validate_public_registry_projection
validate_public_registry_projection(sys.argv[1], sys.argv[2])
PY
    echo "social registry projection differs from pinned Palimpsest" >&2
    exit 65
  }
fi

old_scam="$(readlink -f "$scam_current" 2>/dev/null || true)"
old_pal="$(readlink -f "$pal_current" 2>/dev/null || true)"
bot_was_active=0
monitor_was_active=0
dragon_was_active=0
social_export_failed=0
if systemctl is-active --quiet scamshield-bot.service; then
  bot_was_active=1
fi
if systemctl is-active --quiet scamshield-monitor.service; then
  monitor_was_active=1
fi
if systemctl is-active --quiet scamshield-dragon-den.service; then
  dragon_was_active=1
fi

atomic_link() {
  local destination="$1" target_path="$2" temporary
  temporary="${destination}.next.$$"
  rm -f "$temporary"
  ln -s "$target_path" "$temporary"
  mv -Tf "$temporary" "$destination"
}

install_runtime_contract() {
  local release="$1"
  install -o root -g root -m 0755 \
    "$release/deploy/hetzner/deploy-wrapper.sh" \
    /usr/local/sbin/scamshield-deploy-wrapper
  for unit in scamshield-bot.service scamshield-monitor.service \
              scamshield-dragon-den.service \
              scamshield-feed.service scamshield-feed.timer; do
    install -o root -g root -m 0644 \
      "$release/deploy/hetzner/$unit" "/etc/systemd/system/$unit"
  done
  for unit in scamshield-source-expansion.service \
              scamshield-source-expansion.timer \
              scamshield-social-export.service \
              scamshield-social-export.timer; do
    if [[ -f "$release/deploy/hetzner/$unit" ]]; then
      install -o root -g root -m 0644 \
        "$release/deploy/hetzner/$unit" "/etc/systemd/system/$unit"
    else
      rm -f "/etc/systemd/system/$unit"
    fi
  done
  if [[ ! -f \
      "$release/deploy/hetzner/scamshield-source-expansion.timer" ]]; then
    systemctl disable --now scamshield-source-expansion.timer \
      >/dev/null 2>&1 || true
  fi
  if [[ ! -f \
      "$release/deploy/hetzner/scamshield-social-export.timer" ]]; then
    systemctl disable --now scamshield-social-export.timer \
      >/dev/null 2>&1 || true
    systemctl stop scamshield-social-export.service \
      >/dev/null 2>&1 || true
  fi
  systemctl daemon-reload
}

rollback() {
  trap - ERR
  # Keep the well-known export name uncreatable by the scamshield group for
  # the entire rollback. The EXIT trap restores the steady-state mode even if
  # an intermediate recovery command itself fails under `set -e`.
  trap 'chmod 3771 /var/lib/scamshield >/dev/null 2>&1 || true' EXIT
  chmod 3751 /var/lib/scamshield
  echo "deployment health gate failed; restoring previous release" >&2
  [[ -n "$old_scam" ]] && atomic_link "$scam_current" "$old_scam"
  [[ -n "$old_pal" ]] && atomic_link "$pal_current" "$old_pal"
  if [[ -n "$old_scam" ]]; then
    install_runtime_contract "$old_scam"
  fi
  if [[ -n "$legacy_output" && -d "$legacy_output" ]]; then
    failed_output="${social_output}.failed.$(date -u +%Y%m%dT%H%M%SZ).$$"
    if [[ -d "$social_output" && ! -L "$social_output" ]]; then
      mv "$social_output" "$failed_output"
      chown root:root "$failed_output"
      chmod 0700 "$failed_output"
    fi
    mv "$legacy_output" "$social_output"
    chown "$legacy_output_owner" "$social_output"
    chmod "$legacy_output_mode" "$social_output"
  fi
  chmod 3771 /var/lib/scamshield
  trap - EXIT
  if (( bot_was_active )); then
    systemctl restart scamshield-bot.service || true
  fi
  if (( monitor_was_active )); then
    systemctl restart scamshield-monitor.service || true
  fi
  if (( dragon_was_active )); then
    systemctl restart scamshield-dragon-den.service || true
  fi
  exit 1
}

# The old monitor-owned public tree is not recursively re-owned: it may contain
# attacker-controlled links/hardlinks. Quarantine it recoverably, then create a
# clean exporter-owned boundary. Rollback is armed before this mutation. Group
# write is briefly removed from the root-owned parent to close the rename/create
# race while an older unit might still be running.
trap rollback ERR
if [[ -d "$social_output" && \
      "$(stat -c '%U:%G' "$social_output")" != \
      "scamshield-social-export:caddy" ]]; then
  legacy_output_owner="$(stat -c '%U:%G' "$social_output")"
  legacy_output_mode="$(stat -c '%a' "$social_output")"
  legacy_output="${social_output}.legacy.$(date -u +%Y%m%dT%H%M%SZ).$$"
  # With parent writes suspended, recheck and take ownership of the boundary
  # itself before moving it. Never recurse into potentially hostile contents.
  [[ -d "$social_output" && ! -L "$social_output" ]] || rollback
  chown root:root "$social_output"
  chmod 0700 "$social_output"
  mv "$social_output" "$legacy_output"
  echo "quarantined legacy social export tree at $legacy_output" >&2
fi
install -d -o scamshield-social-export -g caddy -m 2750 "$social_output"
social_generations="$social_output/generations"
if [[ -e "$social_generations" || -L "$social_generations" ]]; then
  [[ -d "$social_generations" && ! -L "$social_generations" ]] || {
    echo "social export generations path is unsafe" >&2
    rollback
  }
fi
install -d -o scamshield-social-export -g caddy -m 2750 "$social_generations"
chmod 3771 /var/lib/scamshield
social_parent_locked=0
trap - EXIT

atomic_link "$pal_current" "$pal_release"
atomic_link "$scam_current" "$scam_release"
install_runtime_contract "$scam_release"
systemctl enable scamshield-bot.service scamshield-feed.timer \
  scamshield-source-expansion.timer \
  scamshield-social-export.timer >/dev/null

if [[ "$mode" != "--no-restart" ]]; then
  started_at="$(date --iso-8601=seconds)"
  (( bot_was_active )) && systemctl restart scamshield-bot.service
  (( monitor_was_active )) && systemctl restart scamshield-monitor.service
  (( dragon_was_active )) && systemctl restart scamshield-dragon-den.service
  systemctl enable --now scamshield-feed.timer >/dev/null
  systemctl enable --now scamshield-source-expansion.timer >/dev/null
  systemctl enable --now scamshield-social-export.timer >/dev/null
  if [[ "$social_enabled" == "1" ]] && (( monitor_was_active )); then
    if ! systemctl start scamshield-social-export.service; then
      echo "social export failed; release remains active and last good bundle is preserved" >&2
      social_export_failed=1
    fi
  fi
  sleep 8
  if (( bot_was_active )) && \
      ! systemctl is-active --quiet scamshield-bot.service; then
    rollback
  fi
  if (( monitor_was_active )) && \
      ! systemctl is-active --quiet scamshield-monitor.service; then
    rollback
  fi
  if (( dragon_was_active )) && \
      ! systemctl is-active --quiet scamshield-dragon-den.service; then
    rollback
  fi
  if (( bot_was_active )) && journalctl -u scamshield-bot.service \
      --since "$started_at" --no-pager 2>/dev/null | \
      grep -Eqi 'Conflict.*getUpdates|terminated by other getUpdates'; then
    echo "a competing Bot API poller was detected" >&2
    rollback
  fi
  if (( dragon_was_active )) && journalctl -u scamshield-dragon-den.service \
      --since "$started_at" --no-pager 2>/dev/null | \
      grep -Eqi 'Conflict.*getUpdates|terminated by other getUpdates'; then
    echo "a competing Dragon Den Bot API poller was detected" >&2
    rollback
  fi
fi

trap - ERR
echo "ScamShield release active: $target"
echo "Palimpsest bridge pinned: $pal_revision"
if (( monitor_was_active )); then
  monitor_status="$(systemctl show scamshield-monitor.service \
    --property=StatusText --value 2>/dev/null || true)"
  echo "ScamShield monitor: ${monitor_status:-status unavailable}"
fi
if (( dragon_was_active )); then
  dragon_status="$(systemctl show scamshield-dragon-den.service \
    --property=SubState --value 2>/dev/null || true)"
  echo "Dragon Den raw mirror: ${dragon_status:-status unavailable}"
fi
if [[ "$mode" == "--no-restart" ]]; then
  echo "Services were not started; complete /etc/scamshield/scamshield.env first."
fi
if (( social_export_failed )); then
  echo "deployment completed with a failed social export" >&2
  exit 1
fi
