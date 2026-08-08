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
apt-get install -y -qq git python3 python3-venv ca-certificates util-linux >/dev/null

id scamshield >/dev/null 2>&1 || \
  useradd --system --home-dir /var/lib/scamshield --shell /usr/sbin/nologin scamshield

install -d -o root -g root -m 0755 \
  /opt/scamshield /opt/scamshield/releases \
  /opt/palimpsest /opt/palimpsest/releases
install -d -o scamshield -g scamshield -m 0700 \
  /var/lib/scamshield \
  /var/lib/scamshield/telegram \
  /var/lib/scamshield/palimpsest-inbox \
  /var/lib/scamshield/review
install -d -o root -g scamshield -m 0750 /etc/scamshield

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
  install -o root -g scamshield -m 0640 \
    /opt/scamshield/source/deploy/hetzner/scamshield.env.example \
    /etc/scamshield/scamshield.env
fi
if [[ ! -f /etc/scamshield/channels.txt ]]; then
  install -o root -g scamshield -m 0640 \
    /opt/scamshield/source/channels.txt /etc/scamshield/channels.txt
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

ScamShield code and hardened services are installed but intentionally stopped.

Next:
  1. Edit /etc/scamshield/scamshield.env and keep it root:scamshield 0640.
  2. Confirm /etc/scamshield/channels.txt contains only public or authorized sources.
  3. Retire any old poller using the same Bot API token.
  4. systemctl enable --now scamshield-bot scamshield-feed.timer
  5. Run /opt/scamshield/current/deploy/hetzner/authorize-monitor.sh once.

The Telethon session will then live under /var/lib/scamshield and will not be
replaced by future GitHub deployments.
EOF
