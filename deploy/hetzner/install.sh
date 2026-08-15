#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo $0 [scamshield-repo-url] [deploy-public-key-file]" >&2
  exit 77
fi

scamshield_repo="${1:-https://github.com/beepboop2025/scamshield.git}"
deploy_key_file="${2:-}"
palimpsest_repo="${PALIMPSEST_REPO_URL:-https://github.com/beepboop2025/palimpsest.git}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git python3 python3-venv ca-certificates openssl util-linux >/dev/null

getent group scamshield >/dev/null 2>&1 || groupadd --system scamshield
getent group scamshield-runtime >/dev/null 2>&1 || \
  groupadd --system scamshield-runtime
getent group intelligence-review >/dev/null 2>&1 || \
  groupadd --system intelligence-review
if ! getent passwd scamshield >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/scamshield --shell /usr/sbin/nologin \
    --gid scamshield-runtime --groups scamshield scamshield
else
  usermod --gid scamshield-runtime --append --groups scamshield scamshield
fi
usermod --append --groups intelligence-review scamshield

install -d -o root -g root -m 0755 \
  /opt/scamshield /opt/scamshield/releases \
  /opt/palimpsest /opt/palimpsest/releases
install -d -o scamshield -g scamshield -m 2770 /var/lib/scamshield
install -d -o scamshield -g scamshield-runtime -m 0700 \
  /var/lib/scamshield/telegram \
  /var/lib/scamshield/dragon-den \
  /var/lib/scamshield/palimpsest-inbox \
  /var/lib/scamshield/review
install -d -o scamshield -g intelligence-review -m 2750 \
  /var/lib/scamshield/handoffs/narcoscope
install -d -o root -g scamshield-runtime -m 0750 /etc/scamshield
if [[ -f /var/lib/scamshield/scamshield.db ]]; then
  chgrp scamshield /var/lib/scamshield/scamshield.db
  chmod g+rw /var/lib/scamshield/scamshield.db
fi

if [[ ! -d /opt/scamshield/source/.git ]]; then
  git clone "$scamshield_repo" /opt/scamshield/source
fi
git -C /opt/scamshield/source remote set-url origin "$scamshield_repo"
git -C /opt/scamshield/source fetch --prune origin master

if [[ ! -d /opt/palimpsest/source/.git ]]; then
  git clone "$palimpsest_repo" /opt/palimpsest/source
fi
git -C /opt/palimpsest/source remote set-url origin "$palimpsest_repo"
git -C /opt/palimpsest/source fetch --prune origin main

if [[ ! -f /etc/scamshield/scamshield.env ]]; then
  example=/opt/scamshield/source/deploy/hetzner/scamshield.env.example
  legacy=/etc/scamshield.env
  stage="$(mktemp)"
  awk '
    !/^(SCAMSHIELD_TOKEN|SCAMSHIELD_OWNER_ID|SCAMSHIELD_DB|SCAMSHIELD_FORCE_IPV4|SCAMSHIELD_PSEUDONYM_KEY)=/
  ' "$example" > "$stage"
  for key in SCAMSHIELD_TOKEN SCAMSHIELD_OWNER_ID SCAMSHIELD_DB SCAMSHIELD_FORCE_IPV4; do
    value=""
    if [[ -f "$legacy" ]]; then
      value="$(awk -F= -v wanted="$key" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' "$legacy")"
    fi
    case "$key" in
      SCAMSHIELD_DB) value="${value:-/var/lib/scamshield/scamshield.db}" ;;
      SCAMSHIELD_FORCE_IPV4) value="${value:-1}" ;;
    esac
    printf '%s=%s\n' "$key" "$value" >> "$stage"
  done
  printf 'SCAMSHIELD_PSEUDONYM_KEY=%s\n' "$(openssl rand -hex 32)" >> "$stage"
  install -o root -g scamshield-runtime -m 0640 \
    "$stage" /etc/scamshield/scamshield.env
  rm -f "$stage"

  if [[ -f "$legacy" || -f /etc/systemd/system/scamshield-bot.service ]]; then
    backup=/var/lib/scamshield/migration-backups/"$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -o root -g scamshield-runtime -m 0700 "$backup"
    if [[ -f "$legacy" ]]; then
      install -o root -g root -m 0600 \
        "$legacy" "$backup/scamshield.env"
    fi
    if [[ -f /etc/systemd/system/scamshield-bot.service ]]; then
      install -o root -g root -m 0600 \
        /etc/systemd/system/scamshield-bot.service \
        "$backup/scamshield-bot.service"
    fi
    if [[ -f /var/lib/scamshield/scamshield.db ]]; then
      python3 - /var/lib/scamshield/scamshield.db "$backup/scamshield.db" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(sys.argv[1])
target = sqlite3.connect(sys.argv[2])
with target:
    source.backup(target)
target.close()
source.close()
PY
      chmod 0600 "$backup/scamshield.db"
    fi
  fi
fi
if [[ ! -f /etc/scamshield/channels.txt ]]; then
  channels_source=/opt/scamshield/source/channels.txt
  [[ -f /opt/scamshield/channels.txt ]] && \
    channels_source=/opt/scamshield/channels.txt
  install -o root -g scamshield-runtime -m 0640 \
    "$channels_source" /etc/scamshield/channels.txt
fi
if [[ ! -f /etc/scamshield/dragon-den-routes.json ]]; then
  install -o root -g scamshield-runtime -m 0640 \
    /opt/scamshield/source/dragon-den-routes.example.json \
    /etc/scamshield/dragon-den-routes.json
fi

target="$(git -C /opt/scamshield/source rev-parse origin/master)"
bash /opt/scamshield/source/deploy/hetzner/update.sh "$target" --no-restart

if [[ -n "$deploy_key_file" ]]; then
  [[ -f "$deploy_key_file" ]] || {
    echo "Deploy public key does not exist: $deploy_key_file" >&2
    exit 66
  }
  public_key="$(<"$deploy_key_file")"
  [[ "$public_key" =~ ^ssh-ed25519[[:space:]] ]] || {
    echo "Deploy key must be an Ed25519 public key" >&2
    exit 65
  }
  install -d -o root -g root -m 0700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 0600 /root/.ssh/authorized_keys
  if ! grep -Fq "scamshield-github-deploy" /root/.ssh/authorized_keys; then
    printf 'restrict,command="/usr/local/sbin/scamshield-deploy-wrapper" %s scamshield-github-deploy\n' \
      "$public_key" >> /root/.ssh/authorized_keys
  fi
fi

cat <<'EOF'

ScamShield code and hardened services are installed. A previously running bot
was not restarted; on a fresh host the services remain stopped.

Next:
  1. Edit /etc/scamshield/scamshield.env and keep it root:scamshield-runtime 0640.
  2. Confirm /etc/scamshield/channels.txt contains only public or authorized sources.
  3. Edit /etc/scamshield/dragon-den-routes.json. For Telethon relay mode, add
     the dedicated bot as a post-only administrator in every destination; the
     authenticated monitor account observes the configured public sources.
  4. Retire any old poller using either Bot API token.
  5. systemctl enable --now scamshield-bot scamshield-feed.timer
  6. For third-party sources, set DRAGON_DEN_RELAY_ENABLED=1 and keep the
     standalone scamshield-dragon-den service disabled.
  7. Run /opt/scamshield/current/deploy/hetzner/authorize-monitor.sh once when
     Telegram authorization is available. Until then the monitor stays disabled.

The Telethon session will then live under /var/lib/scamshield and will not be
replaced by future GitHub deployments.
EOF
