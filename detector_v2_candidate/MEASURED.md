# detector v2 — what was measured, and what is still true

Shipped to `scamshield/detector.py` on 2026-08-02. The v1 module is preserved
here as `detector_v1_original.py`. Four independent red-team rounds produced
these numbers; every figure below was executed, not estimated.

## Why it was replaced

v1 was template-literal. Its rate regex demanded the exact form `1 usdt = 128`.
Measured against 24 realistic ads written the way real ads are written:

- **24 of 24 scored 0 (CLEAN)** — including `USDT to INR at 128, need bank
  accounts on rent, 3% commission daily`, and the highest-volume real Indian
  mule ad (`ghar baithe kamao, sirf apna bank account use karna hai, 2% aapka`),
  whose whole family was unreachable because every v1 signal assumed a
  crypto-priced ad.
- **4 legitimate messages scored 105/60/60/40** and would have been deleted or
  flagged.

## Where it landed

| | v1 | shipped v2 |
|---|---|---|
| 24 evasive positives caught | 0 | **24** |
| 32 hard negatives tier-clean | 28 | **32** |
| legacy suite (real drop-in) | 7/7 | **7/7** |
| 15 fresh ordinary messages | — | **0 flagged** |
| anti-scam boilerplate silences an ad | — | **0 of 24** (an interim build: 23 of 24) |
| quote-wrap / pipe / blockquote evasion | — | **0 of 17 lose the delete tier** |
| 20 invisible-character evasions | — | **20 of 20 still caught** |
| fuzz (18,611 calls, 2 seeds) | — | **0 exceptions** |
| typical message | 0.5 ms | **1.3 ms** |

Delete-tier false positives found and closed along the way, each of which would
have removed a real person's message with no appeal: a vegetable-mandi price
list, a bullion dealer's rate card, an NBFC gold-loan collection job ad, a
Chinese police anti-counterfeiting notice, a note-counting-machine dealer, a
Surat zari wholesaler, **a group admin warning members off mule ads in
Hinglish, and the group's own pinned moderation rules.**

Two structural bugs worth remembering: `_BLOCKQUOTE_RE` was quadratic (58.6 ms
on 4096 newlines, a 150x amplifier any group member could trigger; now 0.03 ms),
and attribution suppressors were being summed into the score rather than
consumed by the gates, which made a boilerplate append a universal silencer.

## What is still true

1. **The delete tier is evadable.** Cheapest measured: a fullwidth `＠` instead
   of `@` costs zero characters and drops 15 of 17 ads out of CONFIRMED; a
   2-char CJK caution word plus quote marks drops all 24 to WATCH. **This is
   currently moot — group-join is DISABLED at BotFather, so nothing can be
   deleted.** It becomes live the moment guardian mode is enabled.
2. **Precision holds for ordinary messages, not for adversarially-written
   ones.** 15 fresh everyday messages: 0 flagged. 15 written *after* reading
   which regexes mint a strong family: 9 flagged. Known residuals: a legal
   Fino/Airtel BC-CSP franchise ad flags (it is textually near-identical to a
   mule ad), HR payroll onboarding sits exactly on the threshold, and a few
   gambling words (`jodi`, `lottery`, `accuracy`) can combine innocently.
3. **`MARKET_USDT_INR = 90.0` is hardcoded** and the whole rate band hangs off
   it. Revisit when the real rate drifts.
4. **Every corpus item is text.** Real ad-blasting increasingly ships the rate
   card as an image with a bare "DM" caption, which scores 0 by construction on
   any text-only detector. This bounds the entire exercise.
5. `Signal` gained a `family` field at index 2, so positional construction
   `Signal(name, weight, detail)` now silently mis-assigns. Nothing constructs
   it outside the module today.
6. `monitor.py` records IOCs at score >= 15, so a warner's quoted scammer
   handles now get stored. Arguably wanted; it is a behaviour change.

## Before enabling guardian mode

Map `CONFIRMED_PATTERN` to `flag` rather than `delete` until item 1 is closed,
and re-run `redteam_merged.py`, `redteam_evasion_full.py`,
`redteam_fp_round4b.py` (each takes a module name as argv[1]).
