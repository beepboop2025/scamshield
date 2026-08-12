# Telegram monitoring summary v1

`export_monitoring_summary.py` creates the private aggregate
`scamshield-telegram-monitoring-summary/v1` for Palimpsest review and a future
NarcoScope analyst import. It is a handoff artifact, not an automatic public
feed and not a shared database.

## Boundary

The summary carries one UTC-day coverage window, aggregate detector-tier and
threat-family counts, and explicit collection limitations. It never carries:

- raw Telegram text or media;
- usernames, chat IDs, source pseudonyms, or candidate-source references;
- wallets, phones, URLs, handles, or other exact IOCs;
- assessment IDs, matched fragments, or entity-to-entity allegations; or
- claims about Telegram-wide prevalence, proceeds, guilt, or network membership.

Detection counts are withheld until the configured minimum number of messages
and distinct observed sources is present. The default gate is 20 analyzed
messages across two sources. Coverage and error counts remain visible when the
gate is not met so missing data is not rendered as zero activity.

Every artifact is `PRIVATE_ANALYST_REVIEW`, `HUMAN_REVIEW_REQUIRED`, and
`publication_eligible: false`. Palimpsest and NarcoScope must apply their own
evidence, licensing, privacy, and publication review before using it beyond the
private analyst plane.

## Render

```bash
python3 export_monitoring_summary.py \
  --db /var/lib/scamshield/scamshield.db \
  --day 2026-08-12
```

On Hetzner, `scamshield-feed.timer` refreshes the current UTC-day summary at
`/var/lib/scamshield/review/scamshield-monitoring-summary.json` alongside the
existing Palimpsest capsule review queue.
