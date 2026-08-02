# ScamShield

Telegram bot + detection engine for USDT-INR money-mule recruitment ads,
counterfeit-currency ads, and gambling-insider spam.

**What it is not:** a Telegram-wide scanner. Bots only see chats they're in.
ScamShield protects at three points instead:

1. **Shield mode** — anyone forwards a suspicious message to the bot in
   private chat → instant verdict + scam-mechanics explanation + official
   reporting channels (1930 / cybercrime.gov.in).
2. **Guardian mode** — added as admin to a group, scores every message and
   acts per `POLICY` in `bot.py` (flag / delete / ban per tier).
3. **IOC pipeline** — every flagged message's handles, phones, channels and
   USDT wallets land in SQLite (`/digest` to dump). Wallets are the high-value
   indicator: Tether freezes addresses on law-enforcement request.

## Run

```bash
pip install -r requirements.txt
export SCAMSHIELD_TOKEN=...       # from @BotFather
export SCAMSHIELD_OWNER_ID=...    # your numeric Telegram id
python bot.py
```

## Test (offline, stdlib only — run before any deploy)

```bash
python3 -m unittest discover tests -v
```

## Detection signals (weights in `scamshield/detector.py`)

| Signal | Why it fires |
|---|---|
| above_market_rate | USDT/INR ≥5% over market — the laundering premium |
| tiered_fund_menu | hacker/game/stock/hybrid "fund" price sheet |
| upi_usdt_bridge | UPI/IMPS + USDT co-occurrence (mule-rail recruitment) |
| prepaid_demand | "work requires USDT prepaid" exit-scam setup |
| mule_recruitment_language | INR-work template stock phrases |
| contact_fanout | ≥3 redundant contacts (ban-resilience) |
| cn_ad_agency_marker | 代发-family paid ad-blasting markers |
| counterfeit_currency_ad | 假钞/验钞机 fake-note ads |
| gambling_insider_ad | 六合彩/PC28/内幕 betting-tips ads |

Ecosystem background and the observed corpus: see App-Dev-Ledger entry.
Never operate this through a personal account; monitoring of hostile
channels belongs on ANAKE's dedicated accounts.
