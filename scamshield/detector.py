"""ScamShield detector: classifies Telegram messages for USDT-INR
mule-recruitment / laundering-ad patterns.

Rule-based and fully offline — no API calls, so it can run inside a bot
handler at message speed. Signals are weighted and independent; the score
is the sum of fired signals, mapped to a verdict tier.

The signal set is derived from observed ad templates (2026-07, "Crypto
Library Discussion" corpus): above-market USDT/INR rates, tiered "fund"
menus (hacker/game/stock/hybrid), UPI/IMPS + USDT co-occurrence,
prepaid-deposit demands, contact fan-out, CN ad-agency markers, and the
adjacent counterfeit-note / gambling-insider ad families.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Rough legitimate USDT/INR rate. Ads in this ecosystem offer 110-130+.
# A 5%+ premium over this is already anomalous; 15%+ is near-conclusive.
# Update occasionally, or wire to a live feed; precision is not critical
# because the laundering premium (25-45%) dwarfs normal drift.
MARKET_USDT_INR = 90.0

_RATE_RE = re.compile(
    r"1\s*usdt\s*=\s*(\d{2,3})(?:\s*[-–~]\s*(\d{2,3}))?", re.IGNORECASE
)

_FUND_TIERS = ("hacker fund", "game fund", "stock fund", "hybrid fund",
               "mixed fund", "stocks fund", "game funds", "hacker funds")

_PREPAID_PHRASES = (
    "requires usdt prepaid", "prepayment of usdt", "requires prepayment",
    "after receiving the deposit", "usdt prepaid",
)

_RECRUITMENT_PHRASES = (
    "inr work", "large number of upi", "large amount of upi",
    "working partner", "don't ask for p2p", "do not request p2p",
    "unlimited purchase of usdt",
)

# Chinese-language markers common to the ad-blasting agencies and the
# adjacent ad families seen alongside the USDT ads.
_CN_AD_MARKERS = ("代发", "帮伐", "专业代", "精准代")          # paid ad-posting services
_CN_FAKE_NOTES = ("假钞", "验钞机", "精仿假钞")                 # counterfeit currency
_CN_GAMBLING = ("六合彩", "pc28", "内幕", "赛车.")              # betting "insider info"

_HANDLE_RE = re.compile(r"@[A-Za-z]\w{3,31}")
_PHONE_RE = re.compile(r"\+\d[\d\s()\-]{7,17}\d")
_TME_RE = re.compile(r"t\.me/[A-Za-z0-9_+]{4,}")
# EVM (0x...) and Tron (T...) addresses — USDT's two main rails.
_WALLET_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})\b")


@dataclass
class Signal:
    name: str
    weight: int
    detail: str


@dataclass
class Verdict:
    score: int
    tier: str                     # CLEAN | WATCH | LIKELY_SCAM | CONFIRMED_PATTERN
    signals: list[Signal]
    iocs: dict[str, list[str]] = field(default_factory=dict)

    def explain(self) -> str:
        if not self.signals:
            return "No known scam patterns detected."
        lines = [f"{s.name} (+{s.weight}): {s.detail}" for s in self.signals]
        return "\n".join(lines)


def _extract_rates(text_lower: str) -> list[float]:
    rates: list[float] = []
    for m in _RATE_RE.finditer(text_lower):
        rates.append(float(m.group(1)))
        if m.group(2):
            rates.append(float(m.group(2)))
    return rates


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Pull actionable indicators out of a message, deduplicated, order kept."""
    def uniq(seq):
        return list(dict.fromkeys(seq))
    return {
        "handles": uniq(_HANDLE_RE.findall(text)),
        "phones": uniq(_PHONE_RE.findall(text)),
        "channels": uniq(_TME_RE.findall(text)),
        "wallets": uniq(_WALLET_RE.findall(text)),
    }


def classify(text: str, market_rate: float = MARKET_USDT_INR) -> Verdict:
    lower = text.lower()
    signals: list[Signal] = []

    rates = _extract_rates(lower)
    hot = [r for r in rates if r >= market_rate * 1.05]
    if hot:
        premium = max(hot) / market_rate - 1
        weight = 40 if premium >= 0.15 else 25
        signals.append(Signal(
            "above_market_rate", weight,
            f"offers up to ₹{max(hot):.0f}/USDT, {premium:+.0%} vs market "
            f"(~₹{market_rate:.0f}) — a laundering premium, not a trade",
        ))

    tiers = {t for t in _FUND_TIERS if t in lower}
    if len(tiers) >= 2:
        signals.append(Signal(
            "tiered_fund_menu", 25,
            f"risk-tiered laundering menu ({', '.join(sorted(tiers))})",
        ))

    if ("upi" in lower or "imps" in lower) and "usdt" in lower:
        signals.append(Signal(
            "upi_usdt_bridge", 15,
            "recruits Indian instant-payment (UPI/IMPS) capacity for USDT conversion",
        ))

    if any(p in lower for p in _PREPAID_PHRASES):
        signals.append(Signal(
            "prepaid_demand", 10,
            "demands USDT deposit up front — classic mule exit-scam setup",
        ))

    if any(p in lower for p in _RECRUITMENT_PHRASES):
        signals.append(Signal(
            "mule_recruitment_language", 15,
            "stock phrases from INR-work mule recruitment templates",
        ))

    iocs = extract_iocs(text)
    fanout = sum(len(v) for v in iocs.values())
    if fanout >= 3:
        signals.append(Signal(
            "contact_fanout", 10,
            f"{fanout} contact points (redundant handles = ban-resilience)",
        ))

    if any(m in text for m in _CN_AD_MARKERS):
        signals.append(Signal(
            "cn_ad_agency_marker", 10,
            "posted via Chinese-language paid ad-blasting service",
        ))

    if any(m in text for m in _CN_FAKE_NOTES):
        signals.append(Signal(
            "counterfeit_currency_ad", 60,
            "advertises counterfeit banknotes (假钞/验钞机)",
        ))

    if any(m in lower for m in _CN_GAMBLING):
        signals.append(Signal(
            "gambling_insider_ad", 40,
            "illegal betting 'insider info' ad family",
        ))

    score = sum(s.weight for s in signals)
    if score >= 60:
        tier = "CONFIRMED_PATTERN"
    elif score >= 35:
        tier = "LIKELY_SCAM"
    elif score >= 15:
        tier = "WATCH"
    else:
        tier = "CLEAN"

    return Verdict(score=score, tier=tier, signals=signals,
                   iocs=iocs if score >= 15 else {})
