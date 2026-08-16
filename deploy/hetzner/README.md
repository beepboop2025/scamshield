# ScamShield on Hetzner

This deployment keeps Telegram credentials and mutable intelligence state on
an always-on Hetzner host while GitHub delivers test-gated, atomic code
releases. A code deploy never replaces the Bot API token, Telethon session,
SQLite database, channel registry, pseudonym key, capsule inbox, or review
queue.

## Architecture

```text
GitHub master push
  -> ScamShield tests + pinned Palimpsest adapter tests
  -> forced-command SSH request
  -> build immutable release on Hetzner
  -> atomic current-symlink switch
  -> restart only services that were already running
  -> health/duplicate-poller gate, rollback on failure

Hetzner
  scamshield-bot.service      Bot API private submissions / authorized groups
  scamshield-dragon-den.service  raw public-channel fan-out under a dedicated bot
  scamshield-monitor.service  configured public or operator-authorized sources
  scamshield-feed.timer       privacy-minimized, human-review-only artifacts
  scamshield-source-expansion.timer  bounded verified-public-source promotion
  scamshield-social-export.timer  signed, metadata-link-only publisher posts
```

## Telegram boundary

This is broad configured coverage, not a Telegram firehose. Telegram does not
offer one. The Bot API receives only chats where the bot participates and the
Telethon account receives only sources it can legitimately access. Private
groups require administrator/operator authorization. Never set the Telethon
event handler to all visible chats, scrape private conversations, or describe
configured-channel coverage as “all Telegram.”

The Telethon login is one-time under normal operation. Its session is stored at
`/var/lib/scamshield/telegram/scamshield_monitor.session` and survives every
GitHub deployment. Telegram can still require reauthorization after a security
reset, account revocation, or session invalidation; no host can bypass that.

The monitor stores idempotent message receipts and an independent history
cursor for each HMAC-pseudonymized source. On restart it first consumes
Telethon's saved update state, then reconciles a bounded history gap every five
minutes. Live messages never advance the history cursor. The source file is
also re-read on that cadence, so adding an explicitly authorized source does
not require a new Telegram login or a code release.

WATCH-or-higher posts can nominate public usernames. The monitor resolves a
bounded batch only to verify entity type and public username; it does not join
or read candidates at that stage. Once a handle has been seen in at least two
distinct configured sources, an offline policy job running every 30 minutes can
append it to the registry. Each run is capped at five additions and the managed
registry stops at 100 configured sources. The monitor then applies its normal
public-channel collection path.

Live updates are handed to a bounded worker queue so Telegram's dispatcher does
not wait on classification. Queue saturation defers work to the durable history
cursor rather than dropping it or allowing unbounded memory growth. Recovery
walks independent sources concurrently, while messages within one source remain
ordered. Source refresh and public-candidate verification run independently of
recovery, so one slow maintenance path does not stall the others.

Review the queue or promote one manually with:

```bash
sudo -u scamshield /opt/scamshield/current/.venv/bin/python \
  /opt/scamshield/current/manage_sources.py \
  --db /var/lib/scamshield/scamshield.db candidates --min-hits 2
sudo /opt/scamshield/current/.venv/bin/python \
  /opt/scamshield/current/manage_sources.py \
  --db /var/lib/scamshield/scamshield.db \
  --channels /etc/scamshield/channels.txt approve @reviewed_public_source
```

Use `reject @name` for a false lead and `add-public @name` for a public source
the operator independently reviewed. Authorized private sources are never
promoted from discovery: join them legitimately in an official client and add
their numeric ID to the root-owned registry.

Run `reject` as the `scamshield` user because it updates SQLite; run `approve`
or `add-public` as root because those commands update the root-owned source
registry. `approve` opens SQLite read-only and is marked approved after the
monitor resolves it.

The privacy-minimized monitoring summary is also copied into
`/var/lib/scamshield/handoffs/narcoscope/` as a group-readable private handoff.
NarcoScope receives no Telegram session, credentials, raw messages, exact IOCs,
source identifiers, or access to ScamShield's private review directory.

## First-time server bootstrap

Use an existing Ubuntu 24.04 Hetzner server or create a small dedicated node.
Before enabling the ScamShield bot, identify and retire any old process polling
the same Bot API token; Telegram permits only one `getUpdates` poller.

Generate a dedicated deployment key (not a personal SSH key):

```bash
ssh-keygen -t ed25519 -N "" -f scamshield_hetzner_deploy
```

Copy the repository to the host or clone it there, then run:

```bash
sudo bash deploy/hetzner/install.sh \
  https://github.com/beepboop2025/scamshield.git \
  /path/to/scamshield_hetzner_deploy.pub
```

The installer creates an unprivileged `scamshield` user, immutable release
directories, root-owned configuration, persistent state, systemd units, and a
forced-command SSH entry. It does not start services on a fresh host or restart
an existing bot during bootstrap. The monitor remains disabled until the
one-time authorization helper succeeds.

On the existing Liquidity Lab fleet box, the installer also recognizes the
legacy `/etc/scamshield.env`, `/opt/scamshield/channels.txt`, active unit, and
shared database. It migrates the configuration without printing secrets,
creates a consistent SQLite backup under
`/var/lib/scamshield/migration-backups/`, and preserves Riptide's database
access through the existing `scamshield` group. The separate
`scamshield-runtime` group protects Telegram credentials and source config from
other fleet services. `/etc/scamshield` remains `root:scamshield-runtime` mode
0750 and the reviewed social registry remains `root:scamshield-runtime` mode
0640. Narrow POSIX ACL entries give `scamshield-social-export` traverse-only
access to that directory and read-only access to that one registry. The
exporter is not a `scamshield-runtime` member, cannot list the directory, and
cannot read the shared environment, channel allowlist, session, or route file.
Replacing either ACL-managed path outside deployment makes social preflight
fail closed until `update.sh` restores the reviewed access contract.

## Server secrets and activation

Edit `/etc/scamshield/scamshield.env`, then keep it protected:

```bash
sudo chown root:scamshield-runtime /etc/scamshield/scamshield.env
sudo chmod 0640 /etc/scamshield/scamshield.env
sudo chown root:scamshield-runtime /etc/scamshield/channels.txt
sudo chmod 0640 /etc/scamshield/channels.txt
```

The channel file may contain public handles/links and explicitly authorized
private identifiers only. Start the Bot API service after the old poller is
retired:

```bash
sudo systemctl enable --now scamshield-bot.service scamshield-feed.timer
```

Authorize the dedicated monitor once, directly on the server:

```bash
sudo /opt/scamshield/current/deploy/hetzner/authorize-monitor.sh
```

Enter Telegram’s code and any 2FA password in that SSH terminal. Never put
either value in GitHub. If `SCAMSHIELD_PHONE` is blank, the helper also asks
for the dedicated account's E.164 phone number and does not persist it. The
helper protects the resulting session and starts the monitor.

## GitHub automatic deployment

Add these repository secrets:

- `SCAMSHIELD_HETZNER_HOST`
- `SCAMSHIELD_HETZNER_SSH_KEY` (the dedicated private key)
- `SCAMSHIELD_HETZNER_KNOWN_HOSTS` (the independently verified host-key line)

For example, set file-backed secrets without placing their values in shell
history:

```bash
gh secret set SCAMSHIELD_HETZNER_SSH_KEY \
  -R beepboop2025/scamshield < scamshield_hetzner_deploy
gh secret set SCAMSHIELD_HETZNER_KNOWN_HOSTS \
  -R beepboop2025/scamshield < verified_known_hosts
```

Set `SCAMSHIELD_HETZNER_HOST` through GitHub’s web UI or `gh secret set`, then
enable automatic production delivery only after one successful manual dispatch:

```bash
gh variable set HETZNER_DEPLOY_ENABLED \
  -R beepboop2025/scamshield --body true
```

Thereafter every push to `master` runs both test suites and requests a
restricted, atomic server deployment. Pull requests run tests but cannot reach
production secrets.

## Operations

```bash
systemctl status scamshield-bot scamshield-monitor scamshield-feed.timer \
  scamshield-source-expansion.timer
journalctl -u scamshield-bot -u scamshield-monitor --since today
sudo -u scamshield test -s /var/lib/scamshield/review/scamshield-review.jsonl
sudo -u scamshield test -s /var/lib/scamshield/review/scamshield-monitoring-summary.json
```

In the owner bot chat, `/liquidity` displays the current UTC-day coverage and
reviewed monetary pulse. Reply to a newly scanned suspicious message with
`/review_amount` and no arguments to receive the exact review syntax.
Configured-channel alerts include an opaque `Review ID` and may be reviewed by
replying to the alert the same way. The SQLite schema migrates additively on
service start; existing assessments and IOC history remain intact, while exact
daily coverage begins at deployment.

The private owner command `/monitor` shows the collector heartbeat, resolved
and unresolved source totals, live queue depth, deferred recovery count, and
the last history/candidate pass. It contains no Telegram source identifiers or
message content.

The review queue is not an automatic accusation feed. It excludes exact IOC
values and message fragments and remains marked for human review.

## Palimpsest social-observation lane

The social lane reuses the monitor's legitimate Telethon access, but it is a
separate opt-in sink with its own SQLite database. It does not alter the
ScamShield analysis receipt, history cursor, or Dragon Den outbox. Any spool
failure is caught before the analysis queue, so ScamShield continues operating.

Collection uses two allowlists. A publisher must be a reviewed
`telegram_channel` in `/etc/scamshield/palimpsest-social-sources.json` with a
local `telegram_handle`, and that same handle must already be present in
`/etc/scamshield/channels.txt`. Installation and upgrades seed the example only
when the local file is absent; they never replace its operator-reviewed
contents. The seeded eight-source file mirrors the public Palimpsest registry;
its reviewed `cgtn-telegram` row alone adds the collection-only
`"telegram_handle": "@CGTNOfficial_BJ"`. Add another binding only when
Palimpsest also adds that publisher as a public `telegram_channel` source:

```bash
sudoedit /etc/scamshield/palimpsest-social-sources.json
```

Every row mirrors the exact public Palimpsest registry fields. A Telegram row
may add one local-only field such as `"telegram_handle": "@publisher"`.
Instagram rows are mirrored without that field and receive `not-attempted`
coverage from ScamShield. The local handle is removed before computing
`source_registry_sha256`, so the digest must equal the complete public registry,
including any Instagram rows. Never add a hidden monitor source or numeric peer
ID to this file.

The first resolved encounter privately pins each publisher to its numeric
Telegram peer ID. Numeric peer IDs, standalone native identity fields, complete
text, media, sessions, and credentials do not enter the artifacts. The public
canonical `t.me` permalink necessarily contains the public post number. The
private directory is `scamshield:scamshield-social` mode 2750 so SQLite/WAL files
inherit the dedicated group; its SQLite database, WAL, and SHM members are mode
0640. Public records contain a stable opaque
observation ID, append-only version IDs, bounded title/excerpt, canonical
permalink, approved publisher article links, content digest, content type,
append-only supersession edge, and explicit non-corroboration relation.

Generate a dedicated HMAC key in the root-only systemd credential file. It is
not present in the common environment inherited by the bot and monitor:

```bash
openssl rand -hex 32 | sudo tee /etc/scamshield/social-export-hmac.key >/dev/null
sudo chown root:root /etc/scamshield/social-export-hmac.key
sudo chmod 0600 /etc/scamshield/social-export-hmac.key
sudoedit /etc/scamshield/scamshield.env  # set the opt-in flag to 1
```

Set `SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED=1`. Preflight then fails closed
unless the local registry's public projection exactly matches the pinned
Palimpsest registry, the private path and modes are correct, and the signing
credential is usable. Fresh installs start the timer; the default disabled flag
makes each invocation a successful no-op until the lane is explicitly enabled.
If an earlier experimental deployment left
`/var/lib/scamshield/social-observations.db`, preflight refuses to initialize a
second history. Stop the monitor and export timer, use SQLite's online backup
API to copy that database into the fixed private path below, retain the old file
as a rollback copy, restore the stated ownership/mode, and only then re-enable
the lane. Do not move a live WAL database with ordinary file-copy commands.
Each successful materialization creates one immutable generation and atomically
switches `/var/lib/scamshield/social-export/current`. Terminal observation
payloads are rejected before their aggregate exceeds 12 MiB, preserving
headroom inside the 16 MiB latest-artifact cap; the ledger is capped at 64 MiB,
and only four generations are retained.
The public root and `generations` parent are owned
`scamshield-social-export:caddy`, mode 2750; immutable bundle directories are
mode 0750 and artifact files are mode 0640. The hostile-input monitor is not in
the Caddy group and its systemd mount makes this subtree read-only. During the
one-time ownership transition, an older monitor-owned tree is moved intact to a
root-only `social-export.legacy.<timestamp>.<pid>` rollback path rather than
recursively re-owned. `/var/lib/scamshield` is `root:scamshield` mode 3771: the
sticky root-owned parent still permits the shared SQLite group to create
sidecars, but the hostile-input service UID cannot replace the separately owned
public child. Caddy receives traverse-only access to that child, and each
hostile-input unit also makes the export subtree read-only or inaccessible. The
directory contains:

- `social-observations-latest.json` — current sanitized observations and
  per-source coverage;
- `social-observations-versions.jsonl` — append-only sanitized revisions; and
- `social-observations.hmac.json` — SHA-256 and HMAC-SHA256 receipts for both
  exact byte streams.

The same atomic generation also contains the fixed importer aliases
`latest.json`, `versions.jsonl`, and `hmac.json`. Expose only those three short
names at `/palimpsest/social-observations/`; the descriptive filenames remain
the authenticated artifact keys inside the sidecar.

The authoritative route lives in Seiche's `ops/Caddyfile`, so its normal Caddy
installer preserves it on redeploy. The ScamShield
`palimpsest-social-observations.caddy` file is a matching reference fragment for
standalone validation, not a second production source of truth.
`palimpsest.info` is GitHub Pages and cannot route to this node. Inside the
`api.seiche.info` site, use exact GET/HEAD matchers before an explicit subtree
404, strip `/palimpsest/social-observations`, and serve from
`/var/lib/scamshield/social-export/current`. The allowlist exposes only:

- `https://api.seiche.info/palimpsest/social-observations/latest.json`
- `https://api.seiche.info/palimpsest/social-observations/versions.jsonl`
- `https://api.seiche.info/palimpsest/social-observations/hmac.json`

Set the Palimpsest GitHub variable `SOCIAL_OBSERVATIONS_SNAPSHOT_URL` to the
first URL; the importer derives the other two sibling URLs. Share the HMAC value
separately as the `SOCIAL_OBSERVATIONS_HMAC_KEY` repository secret.

If all active sources are currently failing, registry validation fails, the
database is unavailable, or signing fails, the exporter does not switch the
`current` symlink. The previous generation remains the last known good. Expose
only that `current` directory through a fixed read-only HTTPS location; never
serve the spool database, environment file, source registry, or generations
parent. An exporter failure is deliberately not an application-release
rollback condition: the monitor and bot remain on the validated release, the
failed oneshot remains visible to systemd, the deployment reports failure
without reverting the healthy release, and the last good bundle stays served.
This is bounded reviewed-publisher coverage, not “all Telegram,” and
every record remains `attributed-source-report-not-corroboration`.

Each completed reconciliation also refetches the newest 50 channel messages.
That bounded overlap recovers queued/offline edits and safe deletions behind the
monotonic new-message cursor. Older edits or deletions can remain undetected; a
larger or unbounded historical sweep is intentionally excluded from this
metadata-minimizing lane.

The v1 history is one append-only authenticated prefix, so it is never silently
truncated or rotated. The spool computes the exact projected JSONL size and
rejects the next revision before the 64 MiB boundary. It likewise refuses a
terminal revision before the bounded 12 MiB payload budget can exhaust the
16 MiB latest artifact. Either limit revokes freshness and preserves the last
good generation. Resuming after that point requires a jointly versioned
segmented/compaction contract in Palimpsest rather than an adapter-only
retention shortcut.

CGTN is a mixed world-news channel. Its adapter therefore accepts only posts
matching a small declared China term list in the message or canonical approved
article path; sports/world items such as Ronaldo or Paraguay updates are counted
as `outside-scope` rejections. This deterministic boundary deliberately favors
precision and can miss China-relevant posts that use none of the declared
English or Chinese terms. Publisher identity alone never establishes relevance.

The preferred Dragon Den mode is an ungated raw-publication lane inside the
Telethon monitor. It accepts only public `@username` sources explicitly listed
in both `/etc/scamshield/channels.txt` and the root-owned
`/etc/scamshield/dragon-den-routes.json`. The monitoring account reads the
third-party sources; the dedicated bot needs post-only administrator rights in
the destination channels, not in the sources. Only Telegram coordinates and
delivery state live in `/var/lib/scamshield/dragon-den/`.

Set `DRAGON_DEN_RELAY_ENABLED=1` only after routes, token, destination grants,
and Telegram content protection are ready. Keep
`scamshield-dragon-den.service` disabled; that unit is an alternative Bot API
poller for the uncommon case where the bot administers every source. Follow
[`docs/DRAGON_DEN.md`](../../docs/DRAGON_DEN.md) for activation and verification.

The adjacent monitoring summary is a gated, aggregate-only private handoff for
Palimpsest review and a future NarcoScope analyst import. It contains no source
identifiers, message text, assessment IDs, or exact IOCs and is never marked
publication-eligible. See `docs/TELEGRAM_MONITORING_EXPORT.md`.
