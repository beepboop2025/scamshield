# -*- coding: utf-8 -*-
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proto
from corpus import POSITIVES, NEGATIVES, LEGACY
src = open("proto.py").read()

# FIX A: gate on distinct STRONG FAMILIES, with a hardened single-family COUNTERFEIT carve-out
src = src.replace(
 "        if len(strong_full) < 2:",
 "        _ff={s.family for s in strong_full}\n"
 "        if len(_ff) < 2 and not (_ff=={'COUNTERFEIT'} and any(s.name=='counterfeit_note_offer' for s in strong_full)):")
src = src.replace(
 "        elif car_score < 60 or len(strong_car) < 2:",
 "        elif car_score < 60 or (len({s.family for s in strong_car}) < 2 and {s.family for s in strong_car}!={'COUNTERFEIT'}):")
# FIX B: delivery channel is corroboration, not a second strong signal
src = src.replace('"counterfeit_delivery_channel", 15, "COUNTERFEIT"','"counterfeit_delivery_channel", 15, "WEAK"')
# FIX C: counterfeit offer needs commercial terms, and dies under report framing
src = src.replace(
 '    if (cn_noun and (cn_offer or delivery)) or en_hits >= 3:',
 '    _cnrep = re.search(r"警方|警察|提示|查获|查獲|嫌疑|新闻|新聞|曝光|不要|小心|留意|注意|防范|防範|举报|舉報|通知|提醒|谨防|謹防|骗子|騙子|诈骗|詐騙|警惕|派出所|案件|逮捕", t)\n'
 '    _cncom = re.search(r"面交|快递|快遞|到付|联系|聯繫|价格|價格|一比|比例|样品|樣品|批量|起订|起訂|微信|@|\\+\\d", t)\n'
 '    cn_offer = bool(re.search(r"可过|可過|出售|供应|供應|批发|批發|现货|現貨|量大从优|量大從優|量大优惠|货到付款|貨到付款|直接交易|支持快递|支持快遞", t)) and bool(_cncom)\n'
 '    if (not _cnrep) and ((cn_noun and cn_offer) or en_hits >= 3):')
# FIX D: type-noun mandatory in account_type_price_sheet
src = src.replace('r"(?:a/?c(?:count)?s?|cc|card|line|fund|desk|settlement|tier|slab)?\\s*"',
                  'r"(?:a/?c(?:count)?s?|cc|card|line|fund|desk|settlement|tier|slab)\\s*"')
# FIX E: zero-width class incl. soft hyphen
src = src.replace('t = re.sub(r"[​-‏‪-‮⁠﻿]", "", t)',
                  't = re.sub("[\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180e\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u206a-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0]", "", t)')
# FIX F: drift removals
src = src.replace(r'\bpaper\b|','').replace('available|hiring','hiring')
ns={}; exec(compile(src,"fixed","exec"),ns); C=ns["classify"]

print("=== corpus regression under the full fix package ===")
bad=0
for n,t in POSITIVES:
    v=C(t)
    if v.score<35: print(f"  POS LOST {n} {v.score} {v.tier}"); bad+=1
for n,t in NEGATIVES:
    v=C(t)
    if v.tier in ("LIKELY_SCAM","CONFIRMED_PATTERN"): print(f"  NEG FLAGGED {n} {v.score} {v.tier}"); bad+=1
for n,t,w in LEGACY:
    v=C(t)
    ok = (v.tier=="CONFIRMED_PATTERN") if n in ("L01_inr_work_ad","L02_fake_notes") else \
         (v.tier in ("LIKELY_SCAM","CONFIRMED_PATTERN") if w=="POS" else v.tier in ("CLEAN","WATCH"))
    if not ok: print(f"  LEGACY BREAK {n} {v.score} {v.tier}"); bad+=1
print(f"  corpus regressions: {bad}")
print("\n=== the new false positives, before -> after ===")
for n,t in [
 ("A1 mandi","Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi"),
 ("A10 bullion","Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders"),
 ("A3 options","Bank Nifty 52000 CE premium 145 chal raha hai abhi, PE premium 132. Stock 120 ke aas paas support hai. Target 190 rakho, SL 110."),
 ("A7 police+ioc","警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。详情 t.me/police_notice_cn @cyber_police_in"),
 ("A8 cn canpass","各位小心，这批假钞可过验钞机，手感也很像，收现金的时候多留意一下。"),
 ("A2 mobile wholesale","Wholesale rate list: tempered glass 129, back cover 149, charger 199, cable 115. Rate fix hai. Reseller commission 5% daily on volume. @mobile_accessories_wholesale +91 90000 11111 t.me/mobacc"),
]:
    print(f"  {n:22} {proto.classify(t).tier:18} -> {C(t).tier}")
print("\n=== soft-hyphen evasion, before -> after ===")
P08="USDT to INR at 128, need bank accounts on rent, 3% commission daily. Trusted parties only. @usdt_inr_desk"
E=P08.replace("accounts on rent","acco­unts on re­nt").replace("USDT","US­DT")
print(f"  P08+softhyphen        {proto.classify(E).score}/{proto.classify(E).tier} -> {C(E).score}/{C(E).tier}")
