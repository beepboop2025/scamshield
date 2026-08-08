#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 77
fi

env_file=/etc/scamshield/scamshield.env
[[ -r "$env_file" ]] || {
  echo "Missing $env_file" >&2
  exit 78
}

systemctl stop scamshield-monitor.service 2>/dev/null || true
runuser -u scamshield -- /usr/bin/bash -c '
  set -a
  source /etc/scamshield/scamshield.env
  set +a
  umask 077
  cd /var/lib/scamshield
  exec /opt/scamshield/current/.venv/bin/python /opt/scamshield/current/login.py
'

session=/var/lib/scamshield/telegram/scamshield_monitor.session
[[ -s "$session" ]] || {
  echo "Authorization did not create $session" >&2
  exit 1
}
chown scamshield:scamshield "$session"
chmod 0600 "$session"
systemctl enable --now scamshield-monitor.service
sleep 3
systemctl is-active --quiet scamshield-monitor.service || {
  journalctl -u scamshield-monitor.service -n 50 --no-pager >&2
  exit 1
}
echo "ScamShield monitor authorized and running."
