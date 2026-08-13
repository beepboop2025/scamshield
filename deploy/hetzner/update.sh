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
usermod --append --groups intelligence-review scamshield
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
    "$scam_release/monitor.py" "$scam_release/login.py" \
    "$scam_release/export_monitoring_summary.py" \
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
old_scam="$(readlink -f "$scam_current" 2>/dev/null || true)"
old_pal="$(readlink -f "$pal_current" 2>/dev/null || true)"
bot_was_active=0
monitor_was_active=0
if systemctl is-active --quiet scamshield-bot.service; then
  bot_was_active=1
fi
if systemctl is-active --quiet scamshield-monitor.service; then
  monitor_was_active=1
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
              scamshield-feed.service scamshield-feed.timer; do
    install -o root -g root -m 0644 \
      "$release/deploy/hetzner/$unit" "/etc/systemd/system/$unit"
  done
  for unit in scamshield-source-expansion.service \
              scamshield-source-expansion.timer; do
    if [[ -f "$release/deploy/hetzner/$unit" ]]; then
      install -o root -g root -m 0644 \
        "$release/deploy/hetzner/$unit" "/etc/systemd/system/$unit"
    else
      systemctl disable --now scamshield-source-expansion.timer \
        >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$unit"
    fi
  done
  systemctl daemon-reload
}

rollback() {
  echo "deployment health gate failed; restoring previous release" >&2
  [[ -n "$old_scam" ]] && atomic_link "$scam_current" "$old_scam"
  [[ -n "$old_pal" ]] && atomic_link "$pal_current" "$old_pal"
  if [[ -n "$old_scam" ]]; then
    install_runtime_contract "$old_scam"
  fi
  if (( bot_was_active )); then
    systemctl restart scamshield-bot.service || true
  fi
  if (( monitor_was_active )); then
    systemctl restart scamshield-monitor.service || true
  fi
  exit 1
}

atomic_link "$pal_current" "$pal_release"
atomic_link "$scam_current" "$scam_release"
install_runtime_contract "$scam_release"
systemctl enable scamshield-bot.service scamshield-feed.timer \
  scamshield-source-expansion.timer >/dev/null

if [[ "$mode" != "--no-restart" ]]; then
  started_at="$(date --iso-8601=seconds)"
  (( bot_was_active )) && systemctl restart scamshield-bot.service
  (( monitor_was_active )) && systemctl restart scamshield-monitor.service
  systemctl enable --now scamshield-feed.timer >/dev/null
  systemctl enable --now scamshield-source-expansion.timer >/dev/null
  sleep 8
  if (( bot_was_active )) && \
      ! systemctl is-active --quiet scamshield-bot.service; then
    rollback
  fi
  if (( monitor_was_active )) && \
      ! systemctl is-active --quiet scamshield-monitor.service; then
    rollback
  fi
  if (( bot_was_active )) && journalctl -u scamshield-bot.service \
      --since "$started_at" --no-pager 2>/dev/null | \
      grep -Eqi 'Conflict.*getUpdates|terminated by other getUpdates'; then
    echo "a competing Bot API poller was detected" >&2
    rollback
  fi
fi

echo "ScamShield release active: $target"
echo "Palimpsest bridge pinned: $pal_revision"
if (( monitor_was_active )); then
  monitor_status="$(systemctl show scamshield-monitor.service \
    --property=StatusText --value 2>/dev/null || true)"
  echo "ScamShield monitor: ${monitor_status:-status unavailable}"
fi
if [[ "$mode" == "--no-restart" ]]; then
  echo "Services were not started; complete /etc/scamshield/scamshield.env first."
fi
