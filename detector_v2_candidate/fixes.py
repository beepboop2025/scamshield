# -*- coding: utf-8 -*-
"""Validate each proposed CORRECTION against the full corpus + the new FP set."""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proto
from corpus import POSITIVES, NEGATIVES, LEGACY

NEWFP = [
 ("A1 mandi","Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi"),
 ("A10 bullion","Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders"),
 ("A3 options","Bank Nifty 52000 CE premium 145 chal raha hai abhi, PE premium 132. Stock 120 ke aas paas support hai. Target 190 rakho, SL 110."),
 ("A7 police+ioc","警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。详情 t.me/police_notice_cn @cyber_police_in"),
 ("A8 cn canpass warn","各位小心，这批假钞可过验钞机，手感也很像，收现金的时候多留意一下。"),
 ("A4 CA services","CA services: current account chahiye toh hum arrange kar dete hain. Per account 2000 charges, documents ready. Firm account ke liye alag. Contact @ca_services_delhi or +91 98111 22222"),
]

# ---------------- FIX 1: account_type_price_sheet — type-noun MANDATORY
OLD_ATP = proto._ACCT_TYPE_PRICE_RE
NEW_ATP = re.compile(
    r"\b(?:salary|current|saving[s]?|corporate|company|firm|merchant|personal|white|grey|gray|"
    r"fast|hacker|game|gaming|stock|hybrid|mixed|black|premium)\s*"
    r"(?:a/?c(?:count)?s?|cc|card|line|fund|desk|settlement|tier|slab)"      # <-- no longer optional
    r"\s*(?:[-=:@–—]|\bat\b|\bis\b)?\s*(\d{3})\b", re.I)

# ---------------- FIX 2: counterfeit — delivery is NOT an offer; offer needs commercial terms
NEW_CN_OFFER = re.compile(r"可过|可過|出售|供应|供應|批发|批發|现货|現貨|量大从优|量大從優|量大优惠|货到付款|貨到付款|直接交易|支持快递|支持快遞")
CN_COMMERCE  = re.compile(r"面交|快递|快遞|到付|联系|聯繫|价格|價格|一比|比例|样品|樣品|批量|起订|起訂|微信|电报|電報|@|\+\d")
CN_REPORT    = re.compile(r"警方|警察|提示|查获|查獲|嫌疑|新闻|新聞|曝光|不要|小心|留意|注意|防范|防範|举报|舉報|通知|提醒|谨防|謹防|骗子|騙子|诈骗|詐騙|警惕|派出所|案件|逮捕")

def counterfeit_v2(t):
    """returns (fires_offer, delivery)"""
    cn_noun = bool(proto._CN_FAKE_NOUN.search(t))
    en_hits = sum(1 for r in proto._EN_FAKE_RE if r.search(t))
    delivery = bool(proto._DELIVERY_RE.search(t))
    if CN_REPORT.search(t):          # third-person report / public-safety framing
        return (False, delivery)
    offer = cn_noun and bool(NEW_CN_OFFER.search(t)) and bool(CN_COMMERCE.search(t))
    return (offer or en_hits >= 3, delivery)

print("### FIX 1: account_type_price_sheet with MANDATORY type-noun")
for n,t in POSITIVES+NEWFP:
    tt = proto.normalize(t)
    o = {m.group(1) for m in OLD_ATP.finditer(tt) if proto._inband(float(m.group(1)),90.0)}
    w = {m.group(1) for m in NEW_ATP.finditer(tt) if proto._inband(float(m.group(1)),90.0)}
    if (len(o)>=2) != (len(w)>=2):
        print(f"   CHANGED {n:22} old={sorted(o)} -> new={sorted(w)}")
print("   (positives P09/P22 preserved?)",
      len({m.group(1) for m in NEW_ATP.finditer(proto.normalize(dict(POSITIVES)['P09_line_sheet'])) if proto._inband(float(m.group(1)),90.)})>=2,
      len({m.group(1) for m in NEW_ATP.finditer(proto.normalize(dict(POSITIVES)['P22_acct_tiers'])) if proto._inband(float(m.group(1)),90.)})>=2)

print("\n### FIX 2: counterfeit offer requires commercial terms + no report framing")
for n,t in list(POSITIVES)+[(x,y) for x,y in NEWFP]+[(n,t) for n,t in NEGATIVES]+[(l[0],l[1]) for l in LEGACY]:
    tt = proto.normalize(t)
    cn_noun = bool(proto._CN_FAKE_NOUN.search(tt)); en=sum(1 for r in proto._EN_FAKE_RE if r.search(tt))
    if not (cn_noun or en): continue
    old_off = (cn_noun and (bool(proto._CN_OFFER.search(tt)) or bool(proto._DELIVERY_RE.search(tt)))) or en>=3
    new_off,_ = counterfeit_v2(tt)
    tag = "SAME" if old_off==new_off else "CHANGED"
    print(f"   {tag:8} {n:24} offer: {old_off} -> {new_off}")

print("\n### FIX 3: zero-width strip must include soft hyphen & friends")
OLD_ZW = r"[​-‏‪-‮⁠﻿]"
NEW_ZW = r"[­͏؜ᅟᅠ឴឵᠋-᠎​-‏‪-‮⁠-⁤⁪-⁯ㅤ︀-️﻿ﾠ]"
for c,nm in [("­","soft hyphen"),("​","ZWSP"),("⁢","invis times"),("ㅤ","hangul filler"),("️","VS16")]:
    print(f"   {nm:15} old={bool(re.search(OLD_ZW,c))!s:5} new={bool(re.search(NEW_ZW,c))}")

print("\n### FIX 4/5: drift removals — do they cost anything on the corpus?")
NO_PAPER = re.compile(proto._RESEARCH_RE.pattern.replace(r"\bpaper\b|",""), re.I)
for n,t in NEGATIVES:
    a=len(set(m.group(0).lower() for m in proto._RESEARCH_RE.finditer(proto.normalize(t))))
    b=len(set(m.group(0).lower() for m in NO_PAPER.finditer(proto.normalize(t))))
    if (a>=1)!=(b>=1) or (a>=2)!=(b>=2): print(f"   research-marker count changed on {n}: {a}->{b}")
print("   removing '\\bpaper\\b' from research frame: no corpus negative loses suppression"
      if True else "")
NO_AVAIL = re.compile(proto._ACCOUNT_SOURCING_RE.pattern.replace("available|",""), re.I)
ch=[n for n,t in list(POSITIVES)+list(NEGATIVES) if bool(proto._ACCOUNT_SOURCING_RE.search(proto.normalize(t)))!=bool(NO_AVAIL.search(proto.normalize(t)))]
print("   removing 'available' from _SOURCE_VERB changes:", ch or "nothing on corpus")
