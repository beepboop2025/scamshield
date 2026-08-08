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
  scamshield-feed.timer       privacy-minimized, human-review-only JSONL queue
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
forced-command SSH entry. It deliberately leaves the services stopped.

## Server secrets and activation

Edit `/etc/scamshield/scamshield.env`, then keep it protected:

```bash
sudo chown root:scamshield /etc/scamshield/scamshield.env
sudo chmod 0640 /etc/scamshield/scamshield.env
sudo chown root:scamshield /etc/scamshield/channels.txt
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
either value in GitHub. The helper protects the resulting session and starts
the monitor.

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
```

The review queue is not an automatic accusation feed. It excludes exact IOC
values and message fragments and remains marked for human review.
