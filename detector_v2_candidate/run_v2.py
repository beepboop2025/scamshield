# -*- coding: utf-8 -*-
"""Corpus harness for detector_v2 (same pass criteria as run.py)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus import POSITIVES, NEGATIVES, LEGACY
from detector_v2 import classify

FLAG = 35
DEL = 60


def line(tag, name, v, want):
    ok = (v.score >= FLAG) if want == "POS" else (v.score < FLAG)
    tier_ok = True
    if want == "NEG" and v.tier in ("LIKELY_SCAM", "CONFIRMED_PATTERN"):
        tier_ok = False
    mark = "PASS" if (ok and tier_ok) else "FAIL"
    print(f"{mark:4} {tag} {name:24} score={v.score:4} tier={v.tier:17} "
          f"carrier={v.car_score:4} fams={sorted(v.families)}")
    if mark == "FAIL" or "-v" in sys.argv:
        for s in v.signals:
            print(f"        {s.weight:+4} {s.family:10} {s.name}: {s.detail[:90]}")
        if v.notes:
            print(f"        NOTES {v.notes}")
    return mark == "PASS"


fails = 0
npos = nneg = 0
print("=== POSITIVES (want score >= 35) ===")
for n, t in POSITIVES:
    r = line("POS", n, classify(t), "POS")
    npos += r
    fails += not r
print("\n=== NEGATIVES (want score < 35 AND tier not flagged) ===")
for n, t in NEGATIVES:
    r = line("NEG", n, classify(t), "NEG")
    nneg += r
    fails += not r
print("\n=== LEGACY FIXTURES ===")
for n, t, w in LEGACY:
    fails += not line(w, n, classify(t), w)
print(f"\nPOSITIVES CAUGHT: {npos}/{len(POSITIVES)}   NEGATIVES CLEAN: {nneg}/{len(NEGATIVES)}")
print(f"FAILURES: {fails}")
