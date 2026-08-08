#!/usr/bin/env bash
set -euo pipefail

review_dir=/var/lib/scamshield/review
target="$review_dir/scamshield-review.jsonl"
mkdir -p "$review_dir"
temporary="$(mktemp "$review_dir/.scamshield-review.XXXXXX")"
trap 'rm -f "$temporary"' EXIT

/opt/scamshield/current/.venv/bin/python \
  /opt/palimpsest/current/scripts/scamshield_feed.py \
  --inbox var/scamshield-inbox > "$temporary"

chmod 0600 "$temporary"
mv -f "$temporary" "$target"
trap - EXIT
