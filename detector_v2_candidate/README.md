# detector v2 — validated candidate, NOT shipped

> **Round 2 (2026-08-02).** The two blocking defects below were fixed in
> `detector_v2.py`, and three independent red-teams then broke *that*. The
> single most important finding: **a group admin warning members off mule ads
> in Hinglish was CONFIRMED and would be DELETED**, as were the group's own
> pinned moderation rules — the detector cannot yet tell forbidding a mechanic
> from offering it, because the warning lexicon is English + CJK only. Also
> found: attribution suppressors were still summed into the score, so appending
> anti-scam boilerplate silenced 23 of 24 ads (worse than the kill-switch it
> replaced); a quadratic ReDoS in `_BLOCKQUOTE_RE` (69 ms at 4096 chars); and
> wrapping an ad in quote marks — 2 characters — dropped 19 of 19 out of the
> delete tier. Each red-team shipped a verified fix branch
> (`detector_v2_precision_patch.py`, `detector_v2_correctness_fixes.py`); a
> merged build is in `detector_v2_merged.py`. Read `MEASURED.md` for the
> numbers before trusting any of it.

A worked upgrade for `scamshield/detector.py`, with its labelled corpus, a
working prototype, and the red-team harnesses that broke it. **Nothing here is
wired into the live bot.** Read this before shipping any of it.

## Why the current detector needs replacing

It is template-literal. The rate regex demands the exact form `1 usdt = 128`,
and the recruitment phrases are exact strings like `inr work`. Measured against
24 realistic ads: **all of them score 0 (CLEAN)**, including

- `USDT to INR at 128, need bank accounts on rent, 3% commission daily` — the
  canonical ad, invisible because `at 128` is not `1 usdt = 128`.
- The highest-volume real mule ad in India (`ghar baithe kamao, sirf apna bank
  account use karna hai, 2% aapka`) — the whole family is unreachable, because
  every existing signal assumes a crypto-priced ad.
- Cyrillic/fullwidth homoglyph versions of the *exact template* the rules were
  written for.

It also has **false positives today**: four legitimate messages in the corpus
score 105/60/60/40 and would be deleted or flagged in guardian mode.

## What the candidate achieves (measured, not claimed)

| | current | candidate |
|---|---|---|
| 24 evasive positives caught | 0 | 24 |
| 32 hard negatives clean | 28 | 32 |
| legacy tests (7) | pass | pass |
| per-message cost | — | 0.6 ms typical, 17.6 ms worst at Telegram's 4096-char ceiling |

Design: semantic signals instead of literals (account-rental, cash-out courier,
freeze-compensation, source-of-funds-waiver), a rate layer that fires on many
written forms but only in an anomalous band, weights capped so no single signal
reaches the delete tier, and a **carrier/quoted split** so a victim quoting an
ad to warn others is not actioned. Keep that last mechanism verbatim in any
rewrite — it is the only thing protecting the warner, and it takes the worst
already-broken negative from 105/DELETED to 0.

## Why it is NOT shipped

Two independent red-teams broke it. `final.py` applies the fix package and
re-measures (0 corpus regressions); these survive it or were only partly fixed:

1. **RATE has no crypto anchor.** The band 103.5–198 is where a large share of
   Indian retail prices live. A vegetable-mandi price list and a bullion
   dealer's rate card still reach LIKELY_SCAM. Fix: RATE only counts as STRONG
   when a crypto/settlement token is present in the message.
2. **The suppressor layer is a kill-switch.** Appending one innocuous word
   (`GST`, `API`, `kaise`) to any ad dropped it out of the delete tier — a
   permanent, content-free bypass. Fix: split *attribution* suppressors (who is
   speaking) from *domain* suppressors (what topic this is); only attribution
   may gate the tier, and only when the carrier is weak.
3. **`MARKET_USDT_INR = 90.0` is hardcoded and stale-by-design**, and the whole
   rate layer is a band around it.

Also, and it bounds the whole exercise: **every corpus item is text.** Real ad
blasting increasingly ships the rate card as an image with a bare "DM" caption,
which scores 0 by construction on any text-only detector.

## Recommended order if you ship this

Fix 1 and 2 first, then re-run `run.py` (corpus) and `redteam2.py`/`redteam3.py`
(the out-of-corpus attacks). Until fix 2 lands, run guardian mode with
`CONFIRMED_PATTERN` mapped to `flag`, not `delete`.

**Currently moot:** group-join is DISABLED at BotFather, so the bot cannot be
added to any group and the delete tier cannot fire on anyone. Re-enabling group
mode is the decision that makes all of the above live.

## Files

- `corpus.py` — 24 positives + 32 negatives, each labelled with the evasion or
  the naive rule that would misfire
- `proto.py` — full working detector, same API shape as `scamshield/detector.py`
- `run.py` — corpus harness
- `final.py` — the fix package, prints a before/after table when run
- `attack*.py`, `redteam*.py` — the red-team harnesses; keep them, they are the
  regression suite for precision
- `expanded_patterns.json` — every regex expanded and compiled standalone
