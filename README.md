# ScamShield

ScamShield by Palimpsest is a Telegram risk-intelligence system for suspicious payments,
scams, and illicit-market activity. It combines a hardened money-flow detector,
conjunctive threat-family rules, a live USDT/INR reference oracle, and
evidence-bounded provenance hypotheses published by Palimpsest.

It currently recognizes tested patterns for:

- USDT/INR laundering premiums, money-mule recruitment, account rental, and
  crypto-to-local-rail cash-out;
- task, advance-fee, guaranteed-return, impersonation/phishing, and
  stolen-access scams;
- possible narcotics, illegal-wildlife, illicit-weapons, forged-document, and
  counterfeit-currency offers;
- illegal gambling promotions and scam-compound forced-labour recruitment
  risks;
- China-linked underground banking / *feiqian*, Golden Triangle scam-casino
  infrastructure, cartel-linked laundering typologies, and wildlife proceeds
  as carefully limited provenance hypotheses.

## What coverage means

ScamShield does **not** see all of Telegram. A bot sees submitted private
messages and, when correctly configured, messages in groups where it is
present. The Telethon monitor sees only public or operator-authorized sources
listed in `channels.txt`. An empty list watches nothing.

Coverage is measured through `/coverage`: observed messages, flagged messages,
collection errors, surface type, and an optional HMAC-pseudonymized source.
This is the basis for expanding toward broad Telegram coverage without claiming
visibility the platform has not granted.

## Reviewed liquidity pulse

The owner-only `/liquidity` command renders a UTC-day pulse from measured daily
coverage and explicitly reviewed monetary observations. It never extracts an
amount from message text or treats a suspicious message as realized proceeds.
Sparse coverage is shown as `INSUFFICIENT_DATA`, not zero activity.

To add one reviewed observation, reply either to the original suspicious
message after ScamShield has scanned it or to a configured-channel alert that
contains an opaque `Review ID`:

```text
/review_amount <measure> <currency> <amount> <rail> <verification> <confidence> [usd=<amount>] [fx=<https-url-or-urn>]
```

For example, an owner recording a victim-reported USD loss could use:

```text
/review_amount victim_reported_loss USD 125 bank_transfer victim_report low
```

Supported Telegram review classes are `amount_mentioned`, `payment_requested`,
`victim_reported_loss`, and `verified_transfer`. The latter two have stricter
verification rules enforced by the measurement contract. Non-USD values may be
counted without normalization; a sum remains withheld unless the review also
supplies `usd=` and an `fx=` provenance URL or URN.

Use `/liquidity` for the current UTC day or `/liquidity YYYY-MM-DD` for an
earlier day. Only messages observed after this daily ledger was deployed appear
in it; historical all-time coverage is deliberately not backfilled into
invented daily figures.

## Two Telegram modes

1. **Shield mode** is always on. A user forwards a suspicious message in a
   private bot chat and receives a composite verdict, evidence limits, possible
   typology, and reporting steps.
2. **Guardian mode** is off by default. When enabled, the bot scores messages
   in administrator-authorized groups and applies `POLICY` from `bot.py`.
   Enabling it requires both BotFather settings—group joins enabled and Group
   Privacy disabled—plus `SCAMSHIELD_GUARDIAN=1`.

The separate `monitor.py` process uses a dedicated Telethon account for
configured public/authorized channels. Never use a personal Telegram account
for hostile-source monitoring.

The public bot menu also exposes `/how`, `/typologies`, `/privacy`, `/explore`,
and `/help`. Startup synchronizes the bot name, descriptions, and command menu
with the shipped behavior. Set `EVIDENCE_CHANNEL_URL` after the shared
NarcoScope–Palimpsest–ScamShield news channel exists to add its follow button;
`PALIMPSEST_URL` and `NARCOSCOPE_URL` can override the related-product links.
The bot also links to the crawlable
[public safety guide](https://palimpsest.info/guides/telegram-scam-message-checker/),
which explains interpretation and reporting outside Telegram. Override that
link with `SCAMSHIELD_GUIDE_URL` only when deploying an equivalent guide.

Private verdicts include one-tap agreement, disagreement, and uncertainty
feedback tailored to the verdict. The store records only the opaque assessment
ID, original tier, and selected response; it does not attach a Telegram identity,
submitted text, or exact IOC. Clean-result disagreement remains eligible because
it is the signal needed to find false negatives without retaining every clean
assessment.

Photos, screenshots, voice notes, PDFs, and other non-text uploads now receive
an explicit text-only limitation instead of silence. ScamShield counts only
the aggregate input type so the operator can prioritize OCR, QR extraction, or
voice support from measured demand. The owner-only `/funnel` command shows
these counts, `/start` campaign totals, and assessment-feedback totals without
user identities or message contents.

## API and MCP

Local integrations can use the same detector through a loopback REST API or a
stdio MCP server:

```bash
python3 api/scamshield_api.py
python3 mcp/scamshield_mcp.py
```

These developer surfaces are deliberately non-persisting: they do not write
to the IOC/review stores, never invoke the Palimpsest bridge, and omit both the
submitted text and exact IOC values from responses. See
[`docs/API-MCP.md`](docs/API-MCP.md), [`openapi.json`](openapi.json), and
[`llms.txt`](llms.txt).

Reviewed product and evidence releases are listed in [`news/feed.json`](news/feed.json).
This is the only ScamShield source eligible for the shared Evidence Signal
channel; the private human-review queue is never a broadcast input.

## ScamShield ↔ Palimpsest data flow

Palimpsest owns the canonical inert typology pack. ScamShield consumes the pack
and sends suspicious structured assessments back through a local one-shot
bridge. Raw Telegram text is hashed and is not included by default.

Palimpsest verifies an Evidence Capsule and stores it under its ignored runtime
outbox. Its outbound feed exposes aggregates and IOC counts, not exact handles,
phones, wallets, URLs, or matched fragments; message-only attribution is
withheld by default.

```bash
export SCAMSHIELD_PALIMPSEST_ROOT=/Users/mrinal/palimpsest-site
export SCAMSHIELD_PSEUDONYM_KEY='replace with a long installation-local secret'
export SCAMSHIELD_SHARE_MIN_TIER=WATCH
```

See [`docs/ARCHITECTURE_V3.md`](docs/ARCHITECTURE_V3.md) and Palimpsest's
`integrations/scamshield/README.md` for the contracts and trust boundaries.

## Rate intelligence

`MarketRateOracle` queries Coinbase and CoinGecko concurrently and caches the
result. It reports whether the quote is corroborated, divergent, single-source,
stale, or fallback. When live sources fail completely, the static fallback is
shown as context but numeric rate detection is disabled. This prevents a stale
number from becoming evidence.

## Run

```bash
python3 -m pip install -r requirements.txt
export SCAMSHIELD_TOKEN=...       # from @BotFather
export SCAMSHIELD_OWNER_ID=...    # numeric Telegram user ID
python3 bot.py
```

For the configured-channel monitor:

```bash
# TELETHON_API_ID and TELETHON_API_HASH must already be configured.
python3 login.py
python3 monitor.py
```

Useful optional settings:

| Variable | Default | Purpose |
|---|---:|---|
| `SCAMSHIELD_GUARDIAN` | `0` | Enable administrator-authorized group mode |
| `SCAMSHIELD_DB` | `scamshield.db` | Shared SQLite assessment/IOC/coverage store |
| `SCAMSHIELD_SESSION` | `scamshield_monitor` in the repository | Persistent Telethon session base path |
| `SCAMSHIELD_CHANNELS_FILE` | `channels.txt` in the repository | Public/authorized source registry |
| `SCAMSHIELD_DISCOVERY_VERIFY_ENABLED` | `1` | Resolve candidate handles without joining, for bounded public-source expansion |
| `SCAMSHIELD_DISCOVERY_VERIFY_BATCH` | `20` | Maximum candidate entities checked per maintenance pass |
| `SCAMSHIELD_RECONCILE_CONCURRENCY` | `4` | Maximum source history streams recovered concurrently |
| `SCAMSHIELD_SOURCE_REFRESH_SECONDS` | `60` | Registry refresh cadence, independent of history recovery |
| `SCAMSHIELD_CANDIDATE_VERIFY_SECONDS` | `300` | Public-candidate verification cadence |
| `SCAMSHIELD_LIVE_WORKERS` | `8` | Workers draining the bounded live-update queue |
| `SCAMSHIELD_LIVE_QUEUE_SIZE` | `1000` | Maximum live backlog before durable-history deferral |
| `SCAMSHIELD_STORE_RAW_SAMPLES` | `0` | Opt in to storing 300-character raw IOC samples |
| `SCAMSHIELD_PALIMPSEST_ROOT` | unset | Enable canonical pack + capsule bridge |
| `SCAMSHIELD_PALIMPSEST_OUTBOX` | `var/scamshield-inbox` | Relative Palimpsest runtime outbox |
| `SCAMSHIELD_SHARE_MIN_TIER` | `WATCH` | Minimum tier exported to Palimpsest |
| `SCAMSHIELD_PSEUDONYM_KEY` | unset | Stable local HMAC key for source coverage |
| `COINGECKO_DEMO_API_KEY` | unset | Optional CoinGecko demo key |
| `EVIDENCE_CHANNEL_URL` | unset | Shared evidence-news channel button shown in the bot |
| `PALIMPSEST_URL` | `https://palimpsest.info` | Palimpsest discovery link |
| `NARCOSCOPE_URL` | current Vercel site | NarcoScope discovery link |
| `SCAMSHIELD_GUIDE_URL` | Palimpsest public guide | Crawlable safety and interpretation guide shown in the bot |
| `SCAMSHIELD_API_HOST` | `127.0.0.1` | Local REST bind address |
| `SCAMSHIELD_API_PORT` | `8794` | Local REST port |

## Confidence and attribution

These labels are categorical—not probabilities:

- `TYPOLOGY_MATCH`: message behavior resembles a published typology.
- `CORROBORATED_LEAD`: at least two independent external source groups and
  evidence classes support the hypothesis.
- `DIRECT_LINK`: an authoritative, direct observation names the same IOC kind
  and exact IOC value that ScamShield extracted from this message. Unbound or
  unrelated case-record IOCs are rejected.

`feiqian` is a transfer mechanism, the Golden Triangle is an operating
ecosystem, and narcotics or wildlife trafficking are possible predicate
offences. They can coexist, but one never proves another. ScamShield must
abstain when case-specific evidence is absent.

## Test

All ScamShield tests are offline and standard-library-only:

```bash
python3 -m unittest discover tests -v
```

The Palimpsest adapter has an independent pytest suite in the Palimpsest
repository. Run both before deployment or changing the intelligence pack.

## Always-on Hetzner deployment

The production bundle in [`deploy/hetzner`](deploy/hetzner/README.md) keeps
secrets and mutable state outside immutable releases, runs the bot and
configured-channel monitor as hardened systemd services, produces a private
Palimpsest review queue, and can automatically deploy every green `master`
commit through a forced-command GitHub Actions key. The Telethon session is
authorized once and persists across code deployments. Discovery can expand the
registry up to 100 sources: the monitor first verifies that a nominated handle
is a public channel without joining it, and an offline hourly policy job
promotes at most five candidates seen in at least two distinct configured
sources. Private invitations and user/bot handles remain ineligible.
