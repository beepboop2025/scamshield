# Whispers from the Dragon Den

`dragon_den_bot.py` is a dedicated Telegram Bot API service that mirrors every
new post from an explicit public-channel allowlist into one or more destination
channels. Destination content is raw and automatically forwarded. It is not
reviewed, verified, corrected, endorsed, or used as evidence by Palimpsest.

This is deliberately a different publication lane from Palimpsest's website:

```text
public Telegram source channel
  -> dedicated Dragon Den bot receives channel_post
  -> private reference-only SQLite outbox
  -> mandatory warning to each destination
  -> native Telegram forward (raw text/media + original attribution)

same incoming post
  -> asynchronous ScamShield classification
  -> private Palimpsest Evidence Capsule when policy threshold is met
  -> human review / deterministic sanitizer
  -> sanitized Palimpsest Whispers tab
```

ScamShield analysis starts only after raw delivery has been queued. A detector,
rate provider, or Palimpsest bridge failure cannot suppress or modify a raw
forward.

## What “everything raw” means

The bot attempts every new or edited post of any kind that Telegram delivers
from every enabled source in the route registry. Native forwarding preserves
the original source attribution, text, caption, entities, media, poll, and
other Telegram-supported content. `forwardMessages` preserves media-album
grouping.

The promise is complete across the declared, accessible sources after
activation—not all Telegram and not an infinite historical scrape. Telegram
does not expose a universal firehose. In particular:

- the bot must be an administrator in each source and destination channel;
- a source must have a public `@username`; private chats, invite links, numeric
  source IDs, DMs, user submissions, and closed groups are rejected by schema;
- Telegram does not forward protected content or some service messages; the
  bot publishes an explicit tombstone and does not copy or download around the
  restriction;
- Bot API pending updates are finite, so a sufficiently long outage can create
  a gap; systemd restarts the service and the private outbox survives releases;
- edited posts receive a new `SOURCE EDIT` receipt; Telegram does not provide a
  general deleted-channel-post update, so source deletions cannot be mirrored
  reliably;
- a crash after Telegram accepts a forward but before SQLite records success
  can produce a duplicate. The stable receipt printed before each forward makes
  that narrow ambiguity visible and operator-deduplicable.

Every forward is preceded by a non-configurable warning that says the material
may be false, incomplete, manipulated, illegal, or malicious and should not be
treated as evidence. A disclaimer does not convert a private source into a
public one; that is why the source schema itself is public-only.

## Route registry

Copy `dragon-den-routes.example.json` to the production path and replace its
placeholders. A catch-all destination receives every source. Each source may
also fan out to any number of topic destinations:

```json
{
  "schema_version": "scamshield-dragon-den-routes/v1",
  "destinations": [
    {
      "id": "dragon-den",
      "chat_id": "@whispers_from_the_dragon_den",
      "label": "All raw signals"
    },
    {
      "id": "china-economy",
      "chat_id": "@palimpsest_china_economy",
      "label": "China economy raw context"
    }
  ],
  "catch_all_destination_ids": ["dragon-den"],
  "sources": [
    {
      "source": "@public_source_name",
      "label": "Public source name",
      "destination_ids": ["china-economy"],
      "enabled": true
    }
  ]
}
```

Unknown fields, duplicate routes, missing destinations, numeric/private
sources, invite links, and an empty enabled-source list fail startup. One
destination failure is retried independently and does not roll back successful
delivery to another destination.

## BotFather and channel setup

Create a new bot specifically for this service. Do not reuse
`SCAMSHIELD_TOKEN`: Telegram allows only one `getUpdates` poller for a bot
token.

For every source channel:

1. Give the channel a public `@username`.
2. Add the Dragon Den bot as an administrator so Telegram delivers
   `channel_post` and `edited_channel_post` updates.
3. Add that exact `@username` to the source registry.

For every destination channel:

1. Add the Dragon Den bot as an administrator.
2. Grant permission to post messages.
3. Add the public `@username` or numeric `-100…` destination ID to the registry.

The service validates administrator access to every configured source and
destination before declaring itself ready.

## Production activation

On the Hetzner host, edit the root-owned environment and routing files without
printing the token in logs or shell history:

```bash
sudoedit /etc/scamshield/scamshield.env
sudoedit /etc/scamshield/dragon-den-routes.json
sudo chown root:scamshield-runtime \
  /etc/scamshield/scamshield.env \
  /etc/scamshield/dragon-den-routes.json
sudo chmod 0640 \
  /etc/scamshield/scamshield.env \
  /etc/scamshield/dragon-den-routes.json
sudo systemctl enable --now scamshield-dragon-den.service
```

Required environment:

```text
DRAGON_DEN_BOT_TOKEN=<dedicated BotFather token>
DRAGON_DEN_ROUTES_FILE=/etc/scamshield/dragon-den-routes.json
DRAGON_DEN_DB=/var/lib/scamshield/dragon-den/dragon-den.db
DRAGON_DEN_PROTECT_CONTENT=1
```

`DRAGON_DEN_PROTECT_CONTENT=1` keeps the forwarded content visible but prevents
downstream forwarding and saving. Set it to `0` only if the destination is
intended to be a reshareable raw feed. This setting does not sanitize or alter
the forwarded post.

## Operations

```bash
systemctl status scamshield-dragon-den.service
journalctl -u scamshield-dragon-den.service --since today
sudo -u scamshield sqlite3 /var/lib/scamshield/dragon-den/dragon-den.db \
  'SELECT status, COUNT(*) FROM deliveries GROUP BY status;'
```

Expected terminal states are `COMPLETE` and `UNFORWARDABLE`. `RETRY` represents
a recoverable Telegram/rate-limit failure; `DEAD` means the bounded retry budget
was exhausted and requires operator inspection. Logs include stable receipt and
route IDs, never message bodies, Telegram bot tokens, or private analysis.

The database is purposefully isolated from `scamshield.db`. It stores source
and destination Telegram coordinates, message IDs, delivery states, and
destination message IDs, but no raw text, caption, media, exact IOC extraction,
or private Palimpsest artifact.
