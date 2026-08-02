# -*- coding: utf-8 -*-
import sys, os, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proto
from proto import classify, _score_text, STRONG_FAMILIES
from corpus import POSITIVES, NEGATIVES, LEGACY

print("### A. account_type_price_sheet on an options-trading message: what actually matched?")
t = "Bank Nifty 52000 CE premium 145 chal raha hai abhi, PE premium 132. Stock 120 ke aas paas support hai. Target 190 rakho, SL 110."
print("   _ACCT_TYPE_PRICE_RE matches:", [(m.group(0), m.group(1)) for m in proto._ACCT_TYPE_PRICE_RE.finditer(t)])
print("   extract_rates:", proto.extract_rates(t))
print("   -> middle group AND separator are both optional, so bare 'premium 145' / 'Stock 120' match.\n")

print("### B. Suppressor magnitudes are on the SAME scale as evidence and STACK")
MID = "Bank account chahiye on rent, 3% commission daily, instant payout. DM @rentdesk_in"
for label, extra in [("baseline",""),
                     ("+warn(1)"," Beware of duplicates."),
                     ("+warn+ask"," Beware of duplicates. Kaise join karna hai puchho."),
                     ("+warn+ask+gst"," Beware of duplicates. Kaise join karna hai puchho. GST bill milega."),
                     ("+warn+ask+gst+api"," Beware of duplicates. Kaise join karna hai puchho. GST bill milega. API access."),
                     ("+ all five"," Beware of duplicates. Kaise join karna hai puchho. GST bill milega. API access. Paper ready.")]:
    v = classify(MID+extra)
    sup = sum(s.weight for s in v.signals if s.family=="SUPPRESS")
    print(f"   {label:22} content={v.score-sup:4} suppressors={sup:5} score={v.score:4} tier={v.tier}")
print()

print("### C. CANDIDATE FIX 1 — gate on DISTINCT STRONG FAMILIES, not signal count")
orig = proto.classify.__code__
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"proto.py")).read()
patched = src.replace("if len(strong_full) < 2:", "if len({s.family for s in strong_full}) < 2:") \
             .replace("elif car_score < 60 or len(strong_car) < 2:", "elif car_score < 60 or len({s.family for s in strong_car}) < 2:")
assert patched != src
ns = {}
exec(compile(patched, "proto_fixed.py", "exec"), ns)
cls2 = ns["classify"]

def sweep(fn, label):
    fp_del, fp_flag, pos_lost = [], [], []
    for n,t in NEGATIVES:
        v=fn(t)
        if v.tier=="CONFIRMED_PATTERN": fp_del.append(n)
        elif v.tier=="LIKELY_SCAM": fp_flag.append(n)
    for n,t in POSITIVES:
        v=fn(t)
        if v.score < 35: pos_lost.append(n)
    legacy=[]
    for n,t,w in LEGACY:
        v=fn(t)
        if w=="POS" and n=="L02_fake_notes" and v.tier!="CONFIRMED_PATTERN": legacy.append((n,v.tier))
        if w=="POS" and n=="L01_inr_work_ad" and v.tier!="CONFIRMED_PATTERN": legacy.append((n,v.tier))
    print(f"   {label}: corpus negFP_delete={fp_del} negFP_flag={fp_flag} pos_below_flag={pos_lost} legacy_breaks={legacy}")

sweep(classify, "as-proposed ")
sweep(cls2,     "family-gated")

NEWFP = [
 ("A1 mandi","Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi"),
 ("A10 bullion","Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders"),
 ("A7+ioc police","警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。详情 t.me/police_notice_cn @cyber_police_in +86 10 1234 5678"),
]
print("\n   effect on the NEW false positives:")
for n,t in NEWFP:
    print(f"     {n:16} as-proposed={classify(t).tier:18} family-gated={cls2(t).tier}")
print("   effect on the counterfeit POSITIVES (the cost of the fix):")
for n,t in POSITIVES:
    if "counterfeit" in n or "gambl" in n or n.startswith(("P15","P16","P17","P18","P20","P23","P24")):
        print(f"     {n:22} as-proposed={classify(t).tier:18} family-gated={cls2(t).tier}")
print(f"     L02_fake_notes(legacy)  as-proposed={classify(LEGACY[1][1]).tier:18} family-gated={cls2(LEGACY[1][1]).tier}")

print("\n### D. Worst-case latency at Telegram's real 4096-char limit")
for label, s in [("4096 rate-words", ("rate "+"x"*15)*256),
                 ("4096 acct+verb",  ("bank account word word "*170)[:4096]),
                 ("4096 quotes",     ('"'+"z"*40+'"')*97),
                 ("4096 mixed CJK",  ("假钞 联系 快递 "*300)[:4096])]:
    t0=time.perf_counter()
    for _ in range(20): classify(s)
    print(f"   {label:20} {(time.perf_counter()-t0)/20*1000:7.2f} ms/msg")
