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
  scamshield-monitor.service  configured public or operator-authorized sources
  scamshield-feed.timer       privacy-minimized, human-review-only artifacts
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

Flagged posts can nominate public usernames for review, but the collector never
resolves or joins those nominations automatically. Review and promote one with:

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
`scamshield-runtime` group protects Telegram credentials and source config
from other fleet services.

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
systemctl status scamshield-bot scamshield-monitor scamshield-feed.timer
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

The review queue is not an automatic accusation feed. It excludes exact IOC
values and message fragments and remains marked for human review.

The adjacent monitoring summary is a gated, aggregate-only private handoff for
Palimpsest review and a future NarcoScope analyst import. It contains no source
identifiers, message text, assessment IDs, or exact IOCs and is never marked
publication-eligible. See `docs/TELEGRAM_MONITORING_EXPORT.md`.
