# -*- coding: utf-8 -*-
"""Second red-team pass: defect classes attack.py does not cover.
   Focus: unanchored lexicon substrings, _INR_CTX bug, spec-vs-proto divergence."""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proto import (classify, _ACCOUNT_RENT_RE, _ACCT, _INR_CTX, _R_AT_NUM,
                   _KIT_ITEM_RE, _HANDOVER_RE, _PREDICATE_RE, _CASH_PICKUP_RE,
                   _SUBAGENT_RE, normalize, extract_rates, STRONG_FAMILIES)

def show(name, t, expect="clean"):
    v = classify(t)
    bad = (expect == "clean" and v.tier in ("LIKELY_SCAM", "CONFIRMED_PATTERN"))
    print(f"{'*** DEFECT' if bad else 'ok       '} {name:38} score={v.score:4} tier={v.tier:18}")
    for s in v.signals:
        print(f"            {s.weight:+4} {s.family:9} {s.name}")
    if getattr(v, 'notes', None): print(f"            NOTES {v.notes}")
    print()
    return bad

print("=" * 100)
print("D. UNANCHORED LEXICON SUBSTRINGS  (the exact bug class the brief is about)")
print("=" * 100)

# _ACCT has NO \b anchors: r'accounts?' matches inside 'accounting',
# r'khata' matches inside 'khatam'.
print("  _ACCT unanchored probes:")
for probe in ["accounting", "accountant", "accountability", "khatam", "khaata"]:
    m = re.search(_ACCT, probe, re.I)
    print(f"    {probe:18} -> {m.group(0)!r}" if m else f"    {probe:18} -> None")
print()

D = [
("D1 CA accounting + rental income",
 "Accounting and rental income entries for FY25-26 are pending. My CA says rent "
 "received has to be shown separately from business income."),

("D2 property mgmt accounting",
 "Accounting + rental agreement work for 3 flats in Whitefield. Tenant deposit "
 "credited to my current account, brokerage 2% commission paid monthly. "
 "DM @propmgmt_blr"),

("D3 khatam + flat rent pe",
 "Kaam khatam ho gaya bhai, ab woh flat rent pe dena hai. Koi tenant dekh lo, "
 "15k tak chalega, brokerage 1 month."),

("D4 microfinance field collections job",
 "Hiring field collection partners for our NBFC branch in Nagpur. Gold-loan "
 "recovery work. Cash collection handover at branch daily by 6pm. Bank account "
 "and PAN card required for onboarding. Fixed 22k plus incentive. "
 "Contact @mfl_hr_nagpur"),

("D5 HR payroll onboarding",
 "Welcome aboard! Send me your PAN card, Aadhaar and passbook photo for payroll "
 "setup. Bank account details required before the 25th. Ping @hr_acmecorp"),

("D6 landlord KYC request",
 "For the rent agreement please send me a copy of your PAN card and Aadhaar, "
 "plus the cancelled cheque for the deposit refund. Registration on Tuesday."),
]
bad = sum(show(n, t) for n, t in D)

print("=" * 100)
print("E. _INR_CTX SUBSTRING BUG -> unlocks the loose _R_AT_NUM 'at/for NNN' form")
print("=" * 100)
print("  _INR_CTX probes (pattern has NO \\b on rs/upi/inr/otc/settle):")
for probe in ["hours", "years", "partners", "workers", "stupid", "occupied", "Palimpsest"]:
    m = re.search(_INR_CTX, probe, re.I)
    print(f"    {probe:14} -> {m.group(0)!r}" if m else f"    {probe:14} -> None")
print()
E = [
("E1 cab fare + 'hours'",
 "Booked the cab for 150, waited almost 2 hours at the airport. Surge is insane."),
("E2 plumber quote + 'partners'",
 "Plumber quoted 180 for the tap and 120 for the flush. Our society partners "
 "with a vendor but they are slower. Bank account transfer only, no cash."),
]
bad += sum(show(n, t) for n, t in E)

print("=" * 100)
print("F. SPEC-vs-PROTOTYPE DIVERGENCE (the 'VERIFIED' claims attach to proto, not the spec)")
print("=" * 100)

# F1: spec's tiered_price_menu is a BARE (\d{3}) counter; proto uses rate-form extraction.
spec_num = re.compile(r"(?<![\w.])(\d{3})(?![\w.]|\s*%)")
def spec_tiered(text, mkt=90.0):
    vals = {float(m.group(1)) for m in spec_num.finditer(text)}
    return sorted(v for v in vals if mkt*1.15 <= v <= mkt*2.20)

for label, s in [
    ("shoe size / price list", "Sizes available 110, 120, 130 in stock"),
    ("cricket scores",         "India 178 for 4, Australia 165 all out, chased 190"),
    ("PC part prices",         "RAM 145, SSD 189, PSU 115 — all in USD though"),
    ("proto on same string",   "Sizes available 110, 120, 130 in stock"),
]:
    if label.startswith("proto"):
        print(f"  proto extract_rates -> {extract_rates(s)}")
    else:
        print(f"  spec tiered_price_menu on {label:22} -> {spec_tiered(s)}  "
              f"(fires: {len(spec_tiered(s))>=3})")
print()

# F2: gate clause (2). Spec says 2 distinct STRONG *families*; proto counts *signals*.
print("  Gate clause (2): spec says 'families', proto counts 'signals'.")
FAKE = "假钞可过验钞机可面交可快递 +98 936 645 6019"     # legacy test L02
v = classify(FAKE)
strong = [s for s in v.signals if s.family in STRONG_FAMILIES]
fams = {s.family for s in strong}
print(f"    legacy FAKE_NOTES_AD: tier={v.tier} strong_signals={len(strong)} "
      f"strong_families={sorted(fams)}")
print(f"    -> implementing the spec literally (>=2 FAMILIES) demotes this to "
      f"LIKELY_SCAM and BREAKS tests/test_detector.py::test_fake_notes_ad_is_confirmed")
print()

print("=" * 100)
print("G. NORMALISER GAPS (spec's zero-width class)")
print("=" * 100)
ZW = re.compile(r"[​-‏‪-‮⁠﻿]")
for cp, nm in [("­","SOFT HYPHEN"), ("​","ZWSP"), (" ","THIN SPACE"),
               ("ㅤ","HANGUL FILLER"), ("᠎","MONGOLIAN VOWEL SEP")]:
    print(f"    U+{ord(cp):04X} {nm:22} stripped={bool(ZW.match(cp))}  "
          f"survives_normalize={cp in normalize('x'+cp+'y')}")
print()
print("    'account' with SOFT HYPHEN inside:",
      bool(_ACCOUNT_RENT_RE.search(normalize("bank acco­unt chahiye on rent"))))
print("    'cancelled' (British) vs regex r'canceled?\\s*cheque':",
      bool(re.search(r"\bcanceled?\s*cheque\b", "cancelled cheque", re.I)))

print(f"\nNEW PRECISION DEFECTS: {bad}")
