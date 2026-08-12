#!/usr/bin/env bash
set -euo pipefail

review_dir=/var/lib/scamshield/review
handoff_dir=/var/lib/scamshield/handoffs/narcoscope
feed_target="$review_dir/scamshield-review.jsonl"
summary_target="$review_dir/scamshield-monitoring-summary.json"
handoff_target="$handoff_dir/scamshield-monitoring-summary.json"
mkdir -p "$review_dir" "$handoff_dir"
temporary_feed="$(mktemp "$review_dir/.scamshield-review.XXXXXX")"
temporary_summary="$(mktemp "$review_dir/.scamshield-summary.XXXXXX")"
temporary_handoff="$(mktemp "$handoff_dir/.scamshield-summary.XXXXXX")"
trap 'rm -f "$temporary_feed" "$temporary_summary" "$temporary_handoff"' EXIT

/opt/scamshield/current/.venv/bin/python \
  /opt/palimpsest/current/scripts/scamshield_feed.py \
  --inbox var/scamshield-inbox > "$temporary_feed"
/opt/scamshield/current/.venv/bin/python \
  /opt/scamshield/current/export_monitoring_summary.py \
  --db "${SCAMSHIELD_DB:-/var/lib/scamshield/scamshield.db}" \
  > "$temporary_summary"

cp "$temporary_summary" "$temporary_handoff"
chmod 0600 "$temporary_feed" "$temporary_summary"
chmod 0640 "$temporary_handoff"
mv -f "$temporary_feed" "$feed_target"
mv -f "$temporary_summary" "$summary_target"
mv -f "$temporary_handoff" "$handoff_target"
trap - EXIT
