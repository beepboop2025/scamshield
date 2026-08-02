# -*- coding: utf-8 -*-
"""Red-team regression suite for detector_v2: the named counterexamples,
the append bypass, the unicode evasions, and worst-case latency."""
import sys, os, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proto
from detector_v2 import (classify, normalize, _ACCT, _INR_CTX, _ACCOUNT_RENT_RE,
                         _KIT_ITEM_RE, STRONG_FAMILIES)

W = 34


def row(name, t, want=None):
    a = proto.classify(t)
    b = classify(t)
    flag = ""
    if want:
        flag = "  OK" if b.tier in want else "  <<< MISS (want %s)" % "/".join(want)
    print(f"  {name:<{W}} v1cand={a.tier:18}({a.score:4})  v2={b.tier:18}({b.score:4}){flag}")
    return b


print("=" * 104)
print("1. NAMED RED-TEAM COUNTEREXAMPLES  (legit messages that must not be actioned)")
print("=" * 104)
row("vegetable mandi price list",
    "Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, "
    "dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi",
    ("CLEAN", "WATCH"))
row("bullion dealer rate card",
    "Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. "
    "Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders",
    ("CLEAN", "WATCH"))
row("NBFC gold-loan collection job",
    "Hiring field collection partners for our NBFC branch in Nagpur. Gold-loan recovery work. "
    "Cash collection handover at branch daily by 6pm. Bank account and PAN card required for "
    "onboarding. Fixed 22k plus incentive. Contact @mfl_hr_nagpur", ("CLEAN", "WATCH"))
row("CN police counterfeit notice",
    "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。", ("CLEAN", "WATCH"))
row("CN police notice + hotline",
    "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。举报电话 +86 10 8402 2988",
    ("CLEAN", "WATCH"))
row("CN police notice + channel IOC",
    "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。详情 t.me/police_notice_cn "
    "@cyber_police_in", ("CLEAN", "WATCH"))
row("CN shopkeeper 'can pass checker'",
    "各位小心，这批假钞可过验钞机，手感也很像，收现金的时候多留意一下。", ("CLEAN", "WATCH"))
row("CN shopkeeper + shop contact",
    "各位小心，这批假钞可过验钞机，手感也很像，收现金时多留意。有问题联系我 @shop_owner_delhi "
    "或 +91 98110 22334", ("CLEAN", "WATCH"))
row("CN news: seizure report",
    "本地新闻：警方查获一批假钞，嫌疑人通过快递发货，量大从优的广告在群里流传。转发请注明来源 "
    "@news_desk_cn t.me/newsdeskcn +86 21 8888 9999", ("CLEAN", "WATCH"))
row("warn-quoting victim (N01)",
    "⚠️ Warning for everyone in this group — I got this DM today, please don't fall for it:\n"
    "\"1USDT=128 INR, Hacker Fund, Game Fund, unlimited purchase of USDT, we need large amount "
    "of UPI, work requires prepayment of USDT\"\nThis is money mule recruitment. If you hand "
    "over your bank account you become the accused, not the victim. Report on 1930 or "
    "cybercrime.gov.in.", ("CLEAN", "WATCH"))
row("options-trading chat",
    "Bank Nifty 52000 CE premium 145 chal raha hai abhi, PE premium 132. Stock 120 ke aas paas "
    "support hai. Target 190 rakho, SL 110.", ("CLEAN", "WATCH"))
row("mobile-accessory wholesale",
    "Wholesale rate list: tempered glass 129, back cover 149, charger 199, cable 115. Rate fix "
    "hai. Reseller commission 5% daily on volume. @mobile_accessories_wholesale "
    "+91 90000 11111 t.me/mobacc", ("CLEAN", "WATCH"))
row("CA accounting + rental income",
    "Accounting and rental income entries for FY25-26 are pending. My CA says rent received has "
    "to be shown separately from business income.", ("CLEAN", "WATCH"))
row("khatam + flat rent pe",
    "Kaam khatam ho gaya bhai, ab woh flat rent pe dena hai. Koi tenant dekh lo, 15k tak "
    "chalega, brokerage 1 month.", ("CLEAN", "WATCH"))
row("property-mgmt accounting",
    "Accounting + rental agreement work for 3 flats in Whitefield. Tenant deposit credited to my "
    "current account, brokerage 2% commission paid monthly. DM @propmgmt_blr", ("CLEAN", "WATCH"))
row("HR payroll onboarding",
    "Welcome aboard! Send me your PAN card, Aadhaar and passbook photo for payroll setup. Bank "
    "account details required before the 25th. Ping @hr_acmecorp", ("CLEAN", "WATCH"))
row("landlord KYC request",
    "For the rent agreement please send me a copy of your PAN card and Aadhaar, plus the "
    "cancelled cheque for the deposit refund. Registration on Tuesday.", ("CLEAN", "WATCH"))
row("cab fare + 'hours'",
    "Booked the cab for 150, waited almost 2 hours at the airport. Surge is insane.",
    ("CLEAN", "WATCH"))
row("plumber quote + 'partners'",
    "Plumber quoted 180 for the tap and 120 for the flush. Our society partners with a vendor "
    "but they are slower. Bank account transfer only, no cash.", ("CLEAN", "WATCH"))

print()
print("=" * 104)
print("2. APPEND BYPASS: one innocuous token must NOT move the canonical ad off its tier")
print("=" * 104)
P08 = ("USDT to INR at 128, need bank accounts on rent, 3% commission daily. "
       "Trusted parties only. @usdt_inr_desk")
base_v1, base_v2 = proto.classify(P08), classify(P08)
print(f"  {'baseline P08':<{W}} v1cand={base_v1.tier:18}({base_v1.score:4})  "
      f"v2={base_v2.tier:18}({base_v2.score:4})")
held = 0
toks = ["GST bill available", "API access", "kaise? DM", "paper ready", "Nodal partner",
        "MID available", "BIN check", "aggregator tie-up", "VDA compliant",
        "Beware of duplicate channels.", "Report scams on 1930.",
        "Beware of duplicates. Kaise join karna hai puchho. GST bill milega. API access. Paper ready."]
for tok in toks:
    v = classify(P08 + " " + tok)
    ok = v.tier == base_v2.tier
    held += ok
    a = proto.classify(P08 + " " + tok)
    print(f"  {'+ ' + tok[:30]:<{W}} v1cand={a.tier:18}({a.score:4})  "
          f"v2={v.tier:18}({v.score:4})  {'HELD' if ok else '<<< MOVED'}")
print(f"  -> v2 held its tier on {held}/{len(toks)} appends")

print()
print("=" * 104)
print("3. UNICODE EVASION")
print("=" * 104)
SH = "­"
soft = P08.replace("accounts on rent", f"acco{SH}unts on re{SH}nt").replace("USDT", f"US{SH}DT")
row("P08 + soft hyphens (U+00AD)", soft, ("CONFIRMED_PATTERN",))
mvs = P08.replace("accounts", "acco᠎unts")
row("P08 + U+180E MONGOLIAN VOWSEP", mvs, ("CONFIRMED_PATTERN",))
cyr = (P08.replace("USDT", "USDТ").replace("accounts", "ассounts")
       .replace("rent", "rеnt").replace("commission", "соmmission"))
row("P08 + Cyrillic homoglyphs", cyr, ("CONFIRMED_PATTERN",))
row("P08 + softhyphen + Cyrillic",
    soft.replace("INR", "ІNR").replace("commission", "соmmission"), ("CONFIRMED_PATTERN",))
print(f"  normalize('acco\\u00ADunt') -> {normalize('acco' + SH + 'unt')!r}")
print(f"  'cancelled cheque' matches _KIT_ITEM_RE -> {bool(_KIT_ITEM_RE.search('cancelled cheque'))}")
print(f"  'canceled cheque'  matches _KIT_ITEM_RE -> {bool(_KIT_ITEM_RE.search('canceled cheque'))}")

print()
print("=" * 104)
print("4. ANCHORED-LEXICON PROBES (the substring bugs)")
print("=" * 104)
print("  _ACCT:", {p: (re.search(_ACCT, p, re.I).group(0) if re.search(_ACCT, p, re.I) else None)
                   for p in ["accounting", "accountant", "accountability", "khatam",
                             "bank account", "khata"]})
print("  _INR_CTX:", {p: (re.search(_INR_CTX, p, re.I).group(0) if re.search(_INR_CTX, p, re.I) else None)
                      for p in ["hours", "years", "stupid", "Palimpsest", "occupied",
                                "rs 500", "upi id"]})

print()
print("=" * 104)
print("5. WORST-CASE LATENCY at Telegram's 4096-char ceiling")
print("=" * 104)
CASES = [
    ("4096 rate-words, no digits", ("rate " + "x" * 19) * 170),
    ("4096 'bank account ' repeat", "bank account " * 315),
    ("4096 nested-quote bomb", '"' + "x" * 200 + '"' * 1900),
    ("4096 'withdraw ' + filler", ("withdraw " + "y" * 36) * 91),
    ("4096 digits", "128 " * 1024),
    ("4096 mixed CJK", "假钞 联系 快递 " * 300),
    ("4096 real ad, tiled", (P08 + " ") * 40),
]
worst = 0.0
for label, s in CASES:
    s = s[:4096]
    t0 = time.perf_counter()
    for _ in range(20):
        classify(s)
    dt = (time.perf_counter() - t0) / 20 * 1000
    worst = max(worst, dt)
    print(f"  {label:<{W}} {dt:8.2f} ms/msg  ({len(s)} chars)")
print(f"  -> worst observed: {worst:.2f} ms at 4096 chars")
