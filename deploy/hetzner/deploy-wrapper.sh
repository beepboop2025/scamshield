#!/usr/bin/env bash
set -euo pipefail
umask 077

original="${SSH_ORIGINAL_COMMAND:-}"
if [[ ! "$original" =~ ^deploy[[:space:]]([0-9a-f]{40})$ ]]; then
  logger -t scamshield-deploy "rejected forced-command request"
  echo "Only 'deploy <commit>' is permitted." >&2
  exit 65
fi

target="${BASH_REMATCH[1]}"
logger -t scamshield-deploy "requested release $target"
exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/bin/bash /opt/scamshield/current/deploy/hetzner/update.sh "$target"
