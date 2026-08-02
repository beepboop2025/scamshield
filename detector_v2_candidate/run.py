# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus import POSITIVES, NEGATIVES, LEGACY
from proto import classify

FLAG = 35   # POLICY: LIKELY_SCAM -> flag ; CONFIRMED -> delete
DEL  = 60

def line(tag, name, v, want):
    ok = (v.score >= FLAG) if want == "POS" else (v.score < FLAG)
    tier_ok = True
    if want == "NEG" and v.tier in ("LIKELY_SCAM", "CONFIRMED_PATTERN"):
        tier_ok = False
    mark = "PASS" if (ok and tier_ok) else "FAIL"
    print(f"{mark:4} {tag} {name:24} score={v.score:4} tier={v.tier:17} "
          f"carrier={getattr(v,'car_score',0):4} fams={sorted(v.families)}")
    if mark == "FAIL" or "-v" in sys.argv:
        for s in v.signals:
            print(f"        {s.weight:+4} {s.family:10} {s.name}: {s.detail[:90]}")
        if getattr(v, "notes", None):
            print(f"        NOTES {v.notes}")
    return mark == "PASS"

fails = 0
print("=== POSITIVES (want score >= 35) ===")
for n, t in POSITIVES:
    fails += not line("POS", n, classify(t), "POS")
print("\n=== NEGATIVES (want score < 35 AND tier not flagged) ===")
for n, t in NEGATIVES:
    fails += not line("NEG", n, classify(t), "NEG")
print("\n=== LEGACY FIXTURES ===")
for n, t, w in LEGACY:
    fails += not line(w, n, classify(t), w)
print(f"\nFAILURES: {fails}")
