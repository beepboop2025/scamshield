import os
# -*- coding: utf-8 -*-
"""Measure ANY detector module against every requested check.
usage: python3 measure_all.py <module_name>
"""
import sys, os, time, importlib

CAND = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CAND)
D = importlib.import_module(sys.argv[1] if len(sys.argv) > 1 else "detector_v2_merged")
from corpus import POSITIVES, NEGATIVES, LEGACY
from redteam_precision_cases import CASES

FLAG, DEL = 35, 60
BAD = ("LIKELY_SCAM", "CONFIRMED_PATTERN")
C = D.classify

print("=" * 92)
print("MODULE:", D.__name__)
print("=" * 92)

# ---- 1. corpus -----------------------------------------------------------
pos_score = pos_tier = 0
pos_miss = []
for n, t in POSITIVES:
    v = C(t)
    if v.score >= FLAG:
        pos_score += 1
    else:
        pos_miss.append(("score", n, v.tier, v.score))
    if v.tier in BAD:
        pos_tier += 1
    else:
        pos_miss.append(("tier", n, v.tier, v.score))
neg_both = neg_tier = 0
neg_miss = []
for n, t in NEGATIVES:
    v = C(t)
    if v.tier not in BAD:
        neg_tier += 1
    else:
        neg_miss.append(("tier", n, v.tier, v.score))
    if v.score < FLAG and v.tier not in BAD:
        neg_both += 1
    else:
        neg_miss.append(("score<35", n, v.tier, v.score))
print("1. CORPUS")
print("   positives  score>=35 : %d/%d   tier flagged: %d/%d" %
      (pos_score, len(POSITIVES), pos_tier, len(POSITIVES)))
print("   negatives  tier-clean: %d/%d   tier-clean AND score<35: %d/%d" %
      (neg_tier, len(NEGATIVES), neg_both, len(NEGATIVES)))
for m in pos_miss + neg_miss:
    print("      MISS", m)

# ---- 3. C1 boilerplate append -------------------------------------------
BOILER = ("\n\nBeware of scams. This group is monitored. Do not fall for fake desks, "
          "do not reply to unknown DMs, do not share your passbook or ATM card. "
          "Group rules: we delete these ads on sight, repeat offenders are banned. "
          "Money mule recruitment is a crime and you become the accused. "
          "Report on 1930 or cybercrime.gov.in, contact the cyber cell. "
          "Admin notice: kisi ko apna account kiraye pe mat do, lalach mat karo, "
          "yeh sab fraud hai, savdhan rahe. 提醒大家 请注意 谨防 诈骗 警惕 举报 小心")
# The maximal attack: one block that fires ALL FIVE attribution suppressors
# (quoted span -25, warning -30, civic -25, research -30, ask -20 = -130).
MAXBOILER = (
    '\n\nWarning: beware, this is a scam, do not fall for it, do not reply. '
    'Money mule recruitment, they advertise these people. '
    'Report on 1930 or cybercrime.gov.in, file a complaint with the cyber cell. '
    'I am a researcher writing a piece for a newsletter, preprint and dataset on OSF, '
    'comments welcome, willing to talk on background. '
    'Is this legit or scam? Should I? Has anyone seen this? Anyone know? '
    '"Someone forwarded me this exact message today and I would like to know '
    'whether it is genuine before I do anything at all about it"')

print("\n3. C1 BOILERPLATE-APPEND ATTACK (all 24 positives)")
for label, boil in [("admin-notice boilerplate", BOILER),
                    ("maximal 5-suppressor block", MAXBOILER)]:
    sil = kept = 0
    moved = []
    for n, t in POSITIVES:
        b = C(t)
        a = C(t + boil)
        if a.tier == "CLEAN":
            sil += 1
        if a.tier == b.tier:
            kept += 1
        else:
            moved.append((n, b.tier, b.score, a.tier, a.score))
    print("   [%s] silenced to CLEAN: %d/24   tier held: %d/24" % (label, sil, kept))
    for m in moved:
        print("      MOVED %-22s %s(%d) -> %s(%d)" % m)

# ---- 4. C3 quote-wrap / pipe-prefix -------------------------------------
conf = [(n, t) for n, t in POSITIVES if C(t).tier == "CONFIRMED_PATTERN"]
print("\n4. C3 QUOTE-WRAP + PIPE-PREFIX (on the %d CONFIRMED positives)" % len(conf))
for label, fn in [("quote-wrap", lambda t: '"' + t + '"'),
                  ("smart-quote-wrap", lambda t: '“' + t + '”'),
                  ("pipe-prefix", lambda t: "\n".join("| " + l for l in t.split("\n"))),
                  ("blockquote-prefix", lambda t: "\n".join("> " + l for l in t.split("\n")))]:
    held = sum(1 for n, t in conf if C(fn(t)).tier == "CONFIRMED_PATTERN")
    lost = [n for n, t in conf if C(fn(t)).tier != "CONFIRMED_PATTERN"]
    print("   %-18s held CONFIRMED %2d/%2d   lost: %s" % (label, held, len(conf), lost))

# ---- 5/6. precision cases -----------------------------------------------
print("\n5+6. redteam_precision_cases.py (12 ordinary messages)")
nbad = 0
for name, why, text in CASES:
    v = C(text)
    bad = v.tier in BAD
    nbad += bad
    print("   %s %-34s %-18s score=%3d" % ("!!!" if bad else "   ", name, v.tier, v.score))
print("   -> %d/%d flagged" % (nbad, len(CASES)))

# ---- 7. ReDoS ------------------------------------------------------------
print("\n7. ReDoS / latency at 4096 chars")
LAT = [("4096 newlines", "\n" * 4096),
       ("4096 digits", "1" * 4096),
       ("4096 '|' lines", "|\n" * 2048),
       ("4096 '>' lines", ">\n" * 2048),
       ("4096 spaces+pipe", (" " * 8 + "|x\n") * 400),
       ("4096 rate-words", (("rate " + "x" * 19) * 170)[:4096]),
       ("4096 'bank account '", ("bank account " * 315)[:4096]),
       ("4096 nested-quote bomb", ('"' + "x" * 200 + '"' * 1900)[:4096]),
       ("4096 mixed CJK", ("假钞 联系 快递 " * 300)[:4096]),
       ("4096 real ad tiled", (("USDT to INR at 128, need bank accounts on rent, "
                               "3% commission daily. @usdt_inr_desk ") * 40)[:4096]),
       ("4096 combining marks", ("á" * 2048)[:4096])]
worst = 0.0
for label, s in LAT:
    t0 = time.perf_counter()
    for _ in range(10):
        C(s)
    dt = (time.perf_counter() - t0) / 10 * 1000
    worst = max(worst, dt)
    print("   %-24s %8.2f ms  (%d chars)" % (label, dt, len(s)))
print("   -> worst %.2f ms" % worst)

# ---- 8. named red-team counterexamples ----------------------------------
RT = [
 ("mandi price list", "Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi", "clean"),
 ("bullion rate card", "Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders", "clean"),
 ("NBFC collection job", "Hiring field collection partners for our NBFC branch in Nagpur. Gold-loan recovery work. Cash collection handover at branch daily by 6pm. Bank account and PAN card required for onboarding. Fixed 22k plus incentive. Contact @mfl_hr_nagpur", "clean"),
 ("CN police notice", "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。举报电话 +86 10 8402 2988", "clean"),
 ("CN police + channel", "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。详情 t.me/police_notice_cn @cyber_police_in", "clean"),
 ("CN shopkeeper warn", "各位小心，这批假钞可过验钞机，手感也很像，收现金时多留意。有问题联系我 @shop_owner_delhi 或 +91 98110 22334", "clean"),
 ("CN news seizure", "本地新闻：警方查获一批假钞，嫌疑人通过快递发货，量大从优的广告在群里流传。转发请注明来源 @news_desk_cn t.me/newsdeskcn +86 21 8888 9999", "clean"),
 ("warn-quoting victim N01", dict(NEGATIVES)["N01_warn_quote_short"], "clean"),
 ("options chat", "Bank Nifty 52000 CE premium 145 chal raha hai abhi, PE premium 132. Stock 120 ke aas paas support hai. Target 190 rakho, SL 110.", "clean"),
 ("options chat 2", "Bank Nifty 52000 CE premium 145, 51800 PE 178, spread cost 120. Expiry Thursday, brokerage 20 per order.", "clean"),
 ("accessory wholesale", "Wholesale rate list: tempered glass 129, back cover 149, charger 199, cable 115. Rate fix hai. Reseller commission 5% daily on volume. @mobile_accessories_wholesale +91 90000 11111 t.me/mobacc", "clean"),
 ("CA accounting+rent", "Accounting and rental income entries for FY25-26 are pending. My CA says rent received has to be shown separately from business income.", "clean"),
 ("khatam + flat rent pe", "Kaam khatam ho gaya bhai, ab woh flat rent pe dena hai. Koi tenant dekh lo, 15k tak chalega, brokerage 1 month.", "clean"),
 ("property-mgmt acct", "Accounting + rental agreement work for 3 flats in Whitefield. Tenant deposit credited to my current account, brokerage 2% commission paid monthly. DM @propmgmt_blr", "clean"),
 ("HR payroll onboarding", "Welcome aboard! Send me your PAN card, Aadhaar and passbook photo for payroll setup. Bank account details required before the 25th. Ping @hr_acmecorp", "clean"),
 ("landlord KYC", "For the rent agreement please send me a copy of your PAN card and Aadhaar, plus the cancelled cheque for the deposit refund. Registration on Tuesday.", "clean"),
 ("cab fare + hours", "Booked the cab for 150, waited almost 2 hours at the airport. Surge is insane.", "clean"),
 ("plumber + partners", "Plumber quoted 180 for the tap and 120 for the flush. Our society partners with a vendor but they are slower. Bank account transfer only, no cash.", "clean"),
 ("tuition fee sheet", "Fee structure per month: Class 10 physics 150, chemistry 130, maths 175. Sibling discount available. Enquiry @coaching_center_pune", "clean"),
 ("bank AMB question", "Kya HDFC ne charges badha diye? AMB per account is 10,000 now for current accounts. Pehle 25000 tha Kotak me. Koi aur bank suggest karo jahan kam ho.", "clean"),
 ("CJK live ad + caution", "假钞可过验钞机可面交可快递，小心假货 +98 936 645 6019", "FLAG"),
]
print("\n8. NAMED RED-TEAM COUNTEREXAMPLES")
bad = 0
for n, t, want in RT:
    v = C(t)
    isbad = (want == "clean" and v.tier in BAD) or (want == "FLAG" and v.tier not in BAD)
    bad += isbad
    print("   %s %-24s %-18s score=%3d" % ("!!!" if isbad else "   ", n, v.tier, v.score))
print("   -> %d/%d wrong" % (bad, len(RT)))

# ---- 9. append-bypass ----------------------------------------------------
print("\n9. SINGLE-TOKEN APPEND BYPASS on P08 (baseline must hold)")
P08 = dict(POSITIVES)["P08_canonical"]
b = C(P08)
held = 0
toks = ["GST", "API", "kaise", "paper", "Nodal", "MID", "BIN", "aggregator", "VDA",
        "usd", "eur", "remittance", "wise", "police", "group rules", "mat karo",
        "Beware of duplicate channels", "Report scams on 1930",
        "we delete these ads on sight", "小心", "举报"]
for tok in toks:
    v = C(P08 + " " + tok)
    ok = v.tier == b.tier
    held += ok
    if not ok:
        print("      MOVED + %-28s %s(%d) -> %s(%d)" % (tok, b.tier, b.score, v.tier, v.score))
print("   baseline %s(%d); held %d/%d" % (b.tier, b.score, held, len(toks)))

# ---- 10. unicode evasion -------------------------------------------------
print("\n10. UNICODE EVASION PROBES (want CONFIRMED held)")
probes = {
  "U+00AD soft hyphen": P08.replace("accounts", "acco­unts").replace("rent", "re­nt"),
  "U+200B zero width": P08.replace("accounts", "acco​unts").replace("rent", "re​nt"),
  "U+200D ZWJ": P08.replace("accounts", "acco‍unts").replace("rent", "re‍nt"),
  "U+2066-69 bidi isolate": P08.replace("accounts", "acco⁦⁩unts").replace("rent", "re⁧⁩nt"),
  "U+202A-E bidi embed": P08.replace("accounts", "acco‪unts").replace("rent", "re‫nt"),
  "U+180E mongolian vs": P08.replace("accounts", "acco᠎unts"),
  "U+E0020 tag chars": P08.replace("accounts", "acco\U000e0041unts").replace("rent", "re\U000e0042nt"),
  "U+FE00 var selector": P08.replace("accounts", "acco︀unts").replace("rent", "re︁nt"),
  "U+E0100 var sel supp": P08.replace("accounts", "acco\U000e0100unts"),
  "U+0301 combining acc": P08.replace("accounts", "accóunts").replace("rent", "rént"),
  "U+0489 combining Me": P08.replace("accounts", "acco҉unts"),
  "U+20DD enclosing Me": P08.replace("accounts", "acco⃝unts"),
  "U+FE24 comb half": P08.replace("accounts", "acco︤unts"),
  "U+1AB0 comb ext": P08.replace("accounts", "acco᪰unts"),
  "U+1DC0 comb supp": P08.replace("accounts", "acco᷀unts"),
  "NFKD precomposed": P08.replace("accounts", "accóunts").replace("rent", "rént"),
  "fullwidth": P08.replace("accounts", "ａｃｃｏｕｎｔｓ"),
  "cyrillic homoglyph": P08.replace("USDT", "USDТ").replace("accounts", "ассounts").replace("rent", "rеnt").replace("commission", "сommission"),
  "small caps": P08.replace("USDT", "ᴜꜱᴅᴛ"),
  "U+2060 word joiner": P08.replace("accounts", "acco⁠unts").replace("rent", "re⁠nt"),
}
ok = 0
for label, s in probes.items():
    v = C(s)
    good = v.tier == "CONFIRMED_PATTERN"
    ok += good
    print("   %s %-24s %-18s score=%3d" % ("   " if good else "!!!", label, v.tier, v.score))
print("   -> %d/%d probes still CONFIRMED" % (ok, len(probes)))

# ---- 11. C5 fx kill-switch ----------------------------------------------
print("\n11. C5 FX EVASION (append a currency token to a live ad)")
for tok in ["usd", "USD", "eur", "gbp", "remittance", "wise", "forex", "nri"]:
    v = C(P08 + " " + tok)
    print("   + %-12s %-18s score=%3d" % (tok, v.tier, v.score))

# ---- 12. Devanagari sanity ----------------------------------------------
print("\n12. NORMALIZE sanity")
n = D.normalize
for probe in ["आएगा", "क्ष", "जिंदगी",
              "accóunt", "acco­unt", "仮鈔", "नमस्ते"]:
    print("   %-14r -> %r" % (probe, n(probe)))
CASH = "paisa आएगा phir withdraw karke"
print("   cashout-with-devanagari fires:", bool(D._CASHOUT_RE.search(n(CASH + " nikal ke de dena"))))
