# -*- coding: utf-8 -*-
"""Third pass: confirm the two highest-consequence defects + proposed fixes."""
import sys, os, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proto import classify, STRONG_FAMILIES, _CN_OFFER, _WARN_RE

def rep(name, t):
    v = classify(t)
    strong = [s for s in v.signals if s.family in STRONG_FAMILIES]
    fams = sorted({s.family for s in strong})
    print(f"  {name:44} score={v.score:4} tier={v.tier:18} "
          f"strong_sigs={len(strong)} strong_fams={fams}")
    if getattr(v, 'notes', None): print(f"      NOTES {v.notes}")
    return v

print("=" * 100)
print("H. CAN A POLICE / SHOPKEEPER COUNTERFEIT WARNING REACH THE DELETE TIER?")
print("=" * 100)
# Real Chinese police & shopkeeper anti-counterfeit notices DO carry a hotline.
rep("H1 police notice, no phone",
    "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。")
rep("H2 police notice WITH hotline (realistic)",
    "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。"
    "举报电话 +86 10 8402 2988")
rep("H3 shopkeeper: 'these fakes CAN pass the checker'",
    "各位小心，这批假钞可过验钞机，手感也很像，收现金的时候多留意一下。")
rep("H4 same + shop contact",
    "各位小心，这批假钞可过验钞机，手感也很像，收现金时多留意。"
    "有问题联系我 @shop_owner_delhi 或 +91 98110 22334")

print("\n  Is 可过 really 'seller-only language'? (spec claims VERIFIED)")
for s in ["假钞可过验钞机可面交", "这批假钞可过验钞机，大家小心"]:
    print(f"    {s}  -> _CN_OFFER match: {_CN_OFFER.search(s).group(0)!r}")
print("  CJK warning markers present in _WARN_RE?")
for w in ["小心", "警方", "提醒大家", "派出所", "注意", "举报"]:
    print(f"    {w} -> {bool(_WARN_RE.search(w))}")

print()
print("=" * 100)
print("I. FIX TEST: gate clause (2) counting FAMILIES instead of SIGNALS")
print("=" * 100)
CASES = [
 ("A1 mandi rate list (legit)",
  "Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, "
  "dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi"),
 ("A10 bullion dealer (legit)",
  "Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. "
  "Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders"),
 ("L02 fake notes ad (legacy test, must stay CONFIRMED)",
  "假钞可过验钞机可面交可快递 +98 936 645 6019"),
 ("P01 canonical mule ad (must stay CONFIRMED)",
  "\U0001f525 USDT ➡️ INR \U0001f525\nRate 128/- fix hai bhai, market se 35 rs upar\n"
  "Bank account chahiye on rent\nCurrent account = 3% commission, saving = 2%\n"
  "Kit ready hona chahiye — ATM card + passbook + sim + net banking\n"
  "Freeze hua toh compensation hum denge\nDM @rk_settlement_01"),
]
print(f"  {'case':46} {'proto tier':20} {'tier if gate=FAMILIES':22}")
for name, t in CASES:
    v = classify(t)
    strong = [s for s in v.signals if s.family in STRONG_FAMILIES]
    fams = {s.family for s in strong}
    fixed = v.tier
    if v.tier == "CONFIRMED_PATTERN" and len(fams) < 2:
        fixed = "LIKELY_SCAM"
    flag = "  <-- CHANGES" if fixed != v.tier else ""
    print(f"  {name:46} {v.tier:20} {fixed:22}{flag}")

print()
print("=" * 100)
print("J. BACKTRACKING at realistic Telegram max length (4096 chars)")
print("=" * 100)
for label, s in [
    ("4096 rate-words, no digits", ("rate " + "x"*19) * 170),
    ("4096 'bank account ' repeat", "bank account " * 315),
    ("4096 nested-quote bomb", '"' + 'x'*200 + '"'*1900),
    ("4096 'withdraw ' + filler", ("withdraw " + "y"*36) * 91),
    ("4096 digits", "128 " * 1024),
]:
    s = s[:4096]
    t0 = time.perf_counter(); classify(s); dt = (time.perf_counter()-t0)*1000
    print(f"  {label:34} {dt:8.1f} ms  ({len(s)} chars)")
