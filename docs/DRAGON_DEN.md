# Whispers from the Dragon Den

Whispers is ScamShield's ungated Telegram publication lane for explicit public
sources. The main feed is [@DragonDenWhispers](https://t.me/DragonDenWhispers),
with topic feeds at [@DragonDenCyber](https://t.me/DragonDenCyber) and
[@DragonDenBorderlands](https://t.me/DragonDenBorderlands). All three are raw,
automatic, and unverified. Reviewed and sanitized interpretation belongs on
Palimpsest's `/news/china/whispers/` surface.

The word *ungated* is precise: once the authenticated monitor receives an
enabled public-source event, its Telegram coordinates enter the Dragon Den
outbox before the separate analysis queue. A classifier result, rate lookup,
Palimpsest bridge, review decision, or full analysis queue cannot suppress or
rewrite the raw forward.

## Architecture

```text
configured public Telegram channel
  -> authenticated monitor.py Telethon user session
  -> reference-only DragonDenOutbox (enqueue first)
  -> dedicated bot posts a mandatory unverified-content receipt
  -> Telethon native forward preserves Telegram source attribution and albums
  -> catch-all destination + zero or more topic destinations

same source event
  -> bounded ScamShield analysis queue
  -> private evidence capsule when policy thresholds are met
  -> review + deterministic sanitization
  -> Palimpsest website
```

This design is necessary because a Bot API bot cannot subscribe to arbitrary
third-party public channels. The already-authorized Telethon user session can
observe those channels and native-forward their posts. The dedicated bot is
the visible warning/publisher identity and needs only post-message rights in
the destination channels.

`dragon_den_bot.py` remains an alternative standalone Bot API poller for the
special case where the bot itself administers every source. It must stay
disabled when `DRAGON_DEN_RELAY_ENABLED=1`.

## What “everything raw” guarantees

For each enabled route, the relay attempts every new message Telegram delivers,
including media-only posts, captions, polls, documents, links, and grouped
albums. Source edits get a distinct `SOURCE EDIT` receipt. A mandatory warning
appears before each forward batch and links to the original public post.

Live enqueue happens synchronously before analysis dispatch. The monitor's
durable history reconciliation uses the same enqueue callback, so ordinary
restart or connectivity gaps are recovered without depending on the analysis
result. A newly initialized source uses the bounded
`SCAMSHIELD_INITIAL_HISTORY` window; an existing source resumes from its durable
collector cursor. Completeness therefore begins at activation/that bounded
window, not at the channel's creation and not across all of Telegram.

The following are explicit limits, not filters:

- only public `@username` sources listed in both the monitor registry and the
  Dragon Den route registry are eligible;
- Telegram offers no universal firehose, and the relay does not discover or
  join sources automatically for publication;
- private channels, groups without a public username, DMs, invite links,
  numeric source IDs, and user submissions are ignored by the raw lane;
- if a source protects forwarding, deletes a post, or makes it unavailable,
  the destination receives an `UNFORWARDABLE` tombstone; the relay does not
  download, copy, or bypass the restriction;
- source deletions do not have a reliable universal recovery update;
- after Telegram accepts a forward but before SQLite commits success, a crash
  can create a duplicate. Stable receipts make that narrow ambiguity visible;
- each destination retries independently, so one unavailable topic channel
  cannot roll back the catch-all delivery.

No message text, caption, media, extracted IOC, username allegation, or copied
file is written to the Dragon Den database. It contains source/destination
coordinates, message IDs, receipt IDs, retry state, and destination message
IDs. Telegram remains the raw-content store.

## Route registry

`/etc/scamshield/dragon-den-routes.json` is root-owned, strict JSON. The
catch-all destination receives every enabled source; topic IDs add fan-out:

```json
{
  "schema_version": "scamshield-dragon-den-routes/v1",
  "destinations": [
    {
      "id": "dragon-den",
      "chat_id": "@DragonDenWhispers",
      "label": "Whispers from the Dragon Den — all raw signals"
    },
    {
      "id": "cyber",
      "chat_id": "@DragonDenCyber",
      "label": "Cyber and technology — raw signals"
    },
    {
      "id": "borderlands",
      "chat_id": "@DragonDenBorderlands",
      "label": "Regional and borderlands — raw signals"
    }
  ],
  "catch_all_destination_ids": ["dragon-den"],
  "sources": [
    {
      "source": "@falconfeedsio",
      "label": "FalconFeeds",
      "destination_ids": ["cyber"],
      "enabled": true
    },
    {
      "source": "@bbcnewsburmese",
      "label": "BBC News Burmese",
      "destination_ids": ["borderlands"],
      "enabled": true
    }
  ]
}
```

Unknown fields, duplicate keys/routes, missing destinations, invite links,
numeric/private sources, and an empty enabled-source list fail preflight. A
route source absent from the resolved monitor set is reported only as an
aggregate `missing_routes` count in systemd status; identities never enter
status text or logs.

## Telegram setup

Use a bot created specifically for Dragon Den; never reuse `SCAMSHIELD_TOKEN`.
For every destination channel:

1. Make the channel public and record its exact `@username` in the route file.
2. Add `@DragonDenWhispersBot` as an administrator.
3. Grant **Post Messages** only. Do not grant edit, delete, subscriber, or
   administrator-management rights.
4. Enable **Restrict Saving Content** in the channel itself. Bot API
   `protect_content` covers warning messages, while the channel setting covers
   the Telethon-native forwards.
5. Publish the permanent feed-level disclaimer. Per-forward receipts remain
   mandatory even when that disclaimer is pinned.

The Telethon monitoring account must be able to read every configured public
source and must own or have post rights in every destination. The dedicated bot
does not need administrator access to third-party sources.

## Production activation

Required environment in `/etc/scamshield/scamshield.env`:

```text
DRAGON_DEN_RELAY_ENABLED=1
DRAGON_DEN_BOT_TOKEN=<dedicated BotFather token>
DRAGON_DEN_ROUTES_FILE=/etc/scamshield/dragon-den-routes.json
DRAGON_DEN_DB=/var/lib/scamshield/dragon-den/dragon-den.db
DRAGON_DEN_PROTECT_CONTENT=1
```

Write the token through a secret-safe terminal or configuration channel; do not
put it in a commit, command argument, CI variable echo, or shell history. Keep
both files `root:scamshield-runtime` and mode `0640`:

```bash
chown root:scamshield-runtime \
  /etc/scamshield/scamshield.env \
  /etc/scamshield/dragon-den-routes.json
chmod 0640 \
  /etc/scamshield/scamshield.env \
  /etc/scamshield/dragon-den-routes.json
systemctl disable --now scamshield-dragon-den.service
systemctl restart scamshield-monitor.service
```

The monitor preflight validates the dedicated token shape, route schema,
reference-only database directory, authorized Telethon session, and all normal
ScamShield production invariants. At runtime the relay verifies the monitoring
account can post to every destination before declaring the monitor ready.

## Operations and proof

```bash
systemctl is-active scamshield-monitor.service
systemctl is-enabled scamshield-dragon-den.service
systemctl show scamshield-monitor.service --property=StatusText --value
journalctl -u scamshield-monitor.service --since today --no-pager
sudo -u scamshield sqlite3 /var/lib/scamshield/dragon-den/dragon-den.db \
  'SELECT status, COUNT(*) FROM deliveries GROUP BY status;'
```

Expected terminal outbox states are:

- `COMPLETE`: Telegram accepted the warning and native forward;
- `UNFORWARDABLE`: Telegram permanently refused the source forward and a
  tombstone was attempted;
- `RETRY`: a rate limit or transient Telegram/network failure is waiting;
- `DEAD`: twelve bounded attempts were exhausted and require inspection.

Status resembles
`raw[complete=…;routes=11/11;missing_routes=0;enqueued=…;completed=…]`.
It contains aggregate counts only. Logs record error classes and source
pseudonyms, never message bodies, bot tokens, public handles, exact IOCs, or
private analysis artifacts.

If the bot cannot post a warning temporarily, the authorized monitor session
posts the same warning and continues the raw forward. That fallback is what
makes the dedicated bot transport non-gating without weakening the disclaimer.
