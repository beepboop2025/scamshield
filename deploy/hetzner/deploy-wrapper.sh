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

source_repo=/opt/scamshield/source
[[ -d "$source_repo/.git" ]] || {
  logger -t scamshield-deploy "source clone is missing"
  exit 78
}
git -C "$source_repo" fetch --quiet --prune origin master
git -C "$source_repo" cat-file -e "${target}^{commit}"
git -C "$source_repo" merge-base --is-ancestor "$target" origin/master || {
  logger -t scamshield-deploy "rejected non-master release $target"
  exit 65
}

target_updater="$(mktemp /run/scamshield-update.XXXXXX)"
trap 'rm -f "$target_updater"' EXIT
git -C "$source_repo" show "${target}:deploy/hetzner/update.sh" > "$target_updater"
chmod 0700 "$target_updater"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/bin/bash "$target_updater" "$target"
