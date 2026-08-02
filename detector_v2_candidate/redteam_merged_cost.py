import os
# -*- coding: utf-8 -*-
"""Cost-of-the-fixes probes: what do the new prohibition/quote rules give away?"""
import sys, importlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
D = importlib.import_module(sys.argv[1] if len(sys.argv) > 1 else "detector_v2_merged")
from corpus import POSITIVES
C = D.classify
BAD = ("LIKELY_SCAM", "CONFIRMED_PATTERN")

print("A. PROHIBITION SPRINKLE: put a prohibition marker in EVERY sentence of the ad")
def sprinkle(t, tok):
    out = []
    for line in t.split("\n"):
        out.append(line + (" " + tok if line.strip() else ""))
    return "\n".join(out)
for tok in ["mat do", "kisi ko mat dena", "we delete these ads on sight",
            "lalach mat karo", "account freeze ho jayega"]:
    held = conf = lost = 0
    lostn = []
    for n, t in POSITIVES:
        b, a = C(t), C(sprinkle(t, tok))
        if b.tier in BAD and a.tier not in BAD:
            lost += 1
            lostn.append(n)
        if a.tier == b.tier:
            held += 1
    print("   %-32s tier held %2d/24  dropped out of flag tier: %d %s"
          % ("+'%s' per line" % tok, held, lost, lostn))

print("\nB. QUOTE-WRAP + a fake authorial voice (defeats the C3 attribution test?)")
P08 = dict(POSITIVES)["P08_canonical"]
for label, s in [
    ("bare quote-wrap", '"%s"' % P08),
    ("quote + 'beware of fakes'", 'Beware of fake desks copying us. "%s"' % P08),
    ("quote + 'is this legit?'", 'is this legit or scam? "%s"' % P08),
    ("quote + warn + civic", 'Warning, beware. Report on 1930. "%s"' % P08),
    ("pipe-prefix + 'beware'", "Beware of fakes.\n" + "\n".join("| " + l for l in P08.split("\n"))),
]:
    v = C(s)
    print("   %-30s %-18s score=%3d car=%3d" % (label, v.tier, v.score, v.car_score))

print("\nC. COUNTERFEIT report-framing bypass (append police vocabulary to a real ad)")
for n, t in POSITIVES:
    if n in ("P15_counterfeit_hi", "P16_counterfeit_tw", "P23_counterfeit_en"):
        for tag in ["", " police", " 警方", " beware of fake notes", " cyber cell"]:
            v = C(t + tag)
            print("   %-22s +%-22s %-18s %3d" % (n, repr(tag)[:20], v.tier, v.score))

print("\nD. TYPICAL-MESSAGE COST")
import time
msgs = [t for _, t in POSITIVES] + ["hello how are you", "Anyone read the new ERC-7730 spec?"]
t0 = time.perf_counter()
for _ in range(50):
    for m in msgs:
        C(m)
print("   %.3f ms/message (mean over %d msgs x50)"
      % ((time.perf_counter() - t0) / (50 * len(msgs)) * 1000, len(msgs)))

print("\nE. BLOCKQUOTE REGEX in isolation (C2 quadratic check)")
import re
old = re.compile(r"(?m)^\s*(?:>|\|)\s?.*$")
new = D._BLOCKQUOTE_RE
for label, s in [("4096 newlines", "\n" * 4096), ("4096 spaces then x", " " * 4095 + "x"),
                 ("2048 '|\\n'", "|\n" * 2048)]:
    for nm, rx in [("old", old), ("new", new)]:
        t0 = time.perf_counter()
        for _ in range(5):
            rx.findall(s)
        print("   %-18s %s %8.2f ms" % (label, nm, (time.perf_counter() - t0) / 5 * 1000))

print("\nF. PIPE-PREFIX still not a delete bypass, on all positives")
n_lost = 0
for n, t in POSITIVES:
    b = C(t)
    a = C("\n".join("| " + l for l in t.split("\n")))
    if b.tier in BAD and a.tier not in BAD:
        n_lost += 1
        print("   LOST", n, b.tier, "->", a.tier)
print("   -> %d/24 lost the flag tier under pipe-prefix" % n_lost)
