# -*- coding: utf-8 -*-
import sys, os, re, json, unicodedata
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proto import classify, _score_text, STRONG_FAMILIES, normalize

def brief(name, t):
    v = classify(t)
    fams=[s.family for s in v.signals if s.family in STRONG_FAMILIES]
    print(f"  {name:46} score={v.score:4} tier={v.tier:18} strong_signals={len(fams)} distinct_fams={len(set(fams))} {sorted(set(fams))}")
    if getattr(v,'notes',None): print(f"       {v.notes}")
    return v

print("### 1. Does the CONFIRMED gate count SIGNALS or FAMILIES?  (spec says families)")
brief("A1 mandi list (2x RATE signals only)",
 "Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, "
 "dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi")
brief("A10 bullion (2x RATE signals only)",
 "Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. "
 "Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders")

print("\n### 2. Counterfeit: police/news warning + a link => DELETE?")
brief("A7 police warning, no IOC",  "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。")
brief("A7 + a channel link",        "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。详情 t.me/police_notice_cn @cyber_police_in +86 10 1234 5678")
brief("news report on seizure",     "本地新闻：警方查获一批假钞，嫌疑人通过快递发货，量大从优的广告在群里流传。转发请注明来源 @news_desk_cn t.me/newsdeskcn +86 21 8888 9999")

print("\n### 3. Cheapest evasion of the DELETE tier: one commercial token")
P08 = "USDT to INR at 128, need bank accounts on rent, 3% commission daily. Trusted parties only. @usdt_inr_desk"
brief("P08 canonical baseline", P08)
for tok in ["GST bill available","API access","paper ready","kaise? DM","Nodal partner","MID available","aggregator tie-up","VDA compliant"]:
    brief(f"P08 + '{tok}'", P08 + " " + tok)

print("\n### 4. Soft hyphen (U+00AD) — not in the zero-width strip class")
brief("P08 baseline", P08)
brief("P08 w/ 1 soft hyphen in 'account'", P08.replace("accounts on rent","acco­unts on rent"))
brief("P08 w/ soft hyphens in acct+rent",  P08.replace("accounts on rent","acco­unts on re­nt").replace("USDT","US­DT"))
print("   normalize('acco\\u00ADunt') ->", repr(normalize("acco­unt")))

print("\n### 5. HARD CAP to WATCH (== ignored) on a mid-scoring live ad")
MID = "Bank account chahiye on rent, 3% commission daily, instant payout. DM @rentdesk_in"
brief("mid-scoring ad baseline", MID)
brief("+ 'Beware of duplicates. Kaise join karna hai puchho'",
      MID + " Beware of duplicate channels. Kaise join karna hai puchho.")

print("\n### 6. Spec-vs-implementation drift")
spec = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"expanded_patterns.json")))
import proto
print("   impl _RESEARCH_RE contains '\\\\bpaper\\\\b' :", "\\bpaper\\b" in proto._RESEARCH_RE.pattern)
print("   proposal research regex has 'paper'      : (see brief) -> NO")
print("   impl _SOURCE_VERB contains 'available'   :", "available" in proto._ACCOUNT_SOURCING_RE.pattern)
print("   impl _COMPLIANCE_RE contains '\\\\bvda\\\\b':", "\\bvda\\b" in proto._COMPLIANCE_RE.pattern)
print("   impl _PAYOPS_RE contains '\\\\bapi\\\\b'   :", "\\bapi\\b" in proto._PAYOPS_RE.pattern)
print("   impl _PAYOPS_RE contains '\\\\bbin\\\\b'   :", "\\bbin\\b" in proto._PAYOPS_RE.pattern)

print("\n### 7. Do the PROPOSAL's literal regexes compile, and the zero-width class?")
zw = "[​-‏‪-‮⁠﻿]"
print("   proposal zero-width class covers U+00AD (soft hyphen):", bool(re.search(zw, "­")))
print("   ... U+2062 invisible-times                          :", bool(re.search(zw, "⁢")))
print("   ... U+1160 hangul filler                            :", bool(re.search(zw, "ᅠ")))
print("   NFKC folds Devanagari digits?", unicodedata.normalize("NFKC","१२८"), "| int() accepts:", int("१२८"))
print("   python \\d matches Devanagari digit:", bool(re.match(r"\d","१")))

print("\n### 8. Devanagari / Arabic-Indic digit rate evasion")
brief("P08 with '128'->Devanagari '१२८'", P08.replace("128","१२८"))
brief("P08 with '128'->Arabic-Indic '١٢٨'", P08.replace("128","١٢٨"))

print("\n### 9. tiered_price_menu spec says it must NOT double-count with anomalous_inr_rate")
v = classify("Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. dealer commission 2%. @m +91 98290 12345 t.me/x")
print("   families set on Verdict:", v.families, " (len 1) but gate used len(strong_signals) =",
      len([s for s in v.signals if s.family in STRONG_FAMILIES]))
