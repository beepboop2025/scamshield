import os
# -*- coding: utf-8 -*-
"""Run corpus + legacy fixtures + red-team counterexamples + my 12 new negatives
against ANY detector module.  usage: python3 measure.py detector_v2 | detector_v2fix"""
import sys, os, importlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
D = importlib.import_module(sys.argv[1] if len(sys.argv) > 1 else "detector_v2")
from corpus import POSITIVES, NEGATIVES, LEGACY
from redteam_precision_cases import CASES

FLAG, DEL = 35, 60
BAD = ("LIKELY_SCAM", "CONFIRMED_PATTERN")

fails = []
npos = 0
for n, t in POSITIVES:
    v = D.classify(t)
    if v.score >= FLAG: npos += 1
    else: fails.append(("POS-MISS", n, v.tier, v.score))
nneg = 0
for n, t in NEGATIVES:
    v = D.classify(t)
    if v.score < FLAG and v.tier not in BAD: nneg += 1
    else: fails.append(("NEG-FLAG", n, v.tier, v.score))
nleg = 0
for n, t, w in LEGACY:
    v = D.classify(t)
    ok = (v.score >= FLAG) if w == "POS" else (v.score < FLAG and v.tier not in BAD)
    if ok: nleg += 1
    else: fails.append(("LEGACY", n, v.tier, v.score))

print("corpus positives %d/%d   negatives %d/%d   legacy %d/%d" %
      (npos, len(POSITIVES), nneg, len(NEGATIVES), nleg, len(LEGACY)))
for f in fails: print("   FAIL", f)

# red-team counterexamples that must stay CLEAN/WATCH
RT = [
 ("mandi price list", "Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi"),
 ("bullion rate card", "Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders"),
 ("NBFC collection job", "Hiring field collection partners for our NBFC branch in Nagpur. Gold-loan recovery work. Cash collection handover at branch daily by 6pm. Bank account and PAN card required for onboarding. Fixed 22k plus incentive. Contact @mfl_hr_nagpur"),
 ("CN police notice", "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。举报电话 +86 10 8402 2988"),
 ("CN shopkeeper warn", "各位小心，这批假钞可过验钞机，手感也很像，收现金时多留意。有问题联系我 @shop_owner_delhi 或 +91 98110 22334"),
 ("CN news seizure", "本地新闻：警方查获一批假钞，嫌疑人通过快递发货，量大从优的广告在群里流传。转发请注明来源 @news_desk_cn t.me/newsdeskcn +86 21 8888 9999"),
 ("options chat", "Bank Nifty 52000 CE premium 145, 51800 PE 178, spread cost 120. Expiry Thursday, brokerage 20 per order."),
 ("accessory wholesale", "Mobile back cover wholesale: silicone 145, tempered glass 120, magsafe 165 per piece. Minimum 50 pcs. @acc_wholesale_delhi"),
 ("CJK live ad + caution", "假钞可过验钞机可面交可快递，小心假货 +98 936 645 6019"),  # MUST stay flagged
]
print("\nred-team counterexamples (want CLEAN/WATCH; last one MUST be flagged):")
for n, t in RT:
    v = D.classify(t)
    print("   %-22s %-18s %3d" % (n, v.tier, v.score))

print("\nappend bypass on P08 (want CONFIRMED_PATTERN held):")
P08 = dict(POSITIVES)["P08_canonical"]
for extra in ["", " GST", " API", " kaise", " paper", " Nodal", " MID", " BIN",
              " aggregator", " VDA", " Beware of duplicate channels",
              " Report scams on 1930", " police", " group rules", " mat karo",
              " GST API kaise paper Nodal MID BIN aggregator VDA Beware of duplicate channels Report scams on 1930"]:
    v = D.classify(P08 + extra)
    print("   %-28s %-18s %3d" % (repr(extra)[:28], v.tier, v.score))

print("\nmy 12 new negatives:")
n_bad = 0
for name, why, text in CASES:
    v = D.classify(text)
    bad = v.tier in BAD
    n_bad += bad
    print("   %s %-34s %-18s %3d" % ("!!!" if bad else "   ", name, v.tier, v.score))
print("   -> %d/%d flagged" % (n_bad, len(CASES)))
