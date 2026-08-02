# -*- coding: utf-8 -*-
"""Adversarial red-team of the v0.2 proposal. NEW messages only."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proto import classify

def show(name, t, expect):
    v = classify(t)
    act = "FLAGGED" if v.tier in ("LIKELY_SCAM","CONFIRMED_PATTERN") else ("WATCH" if v.tier=="WATCH" else "clean")
    bad = (expect=="clean" and v.tier in ("LIKELY_SCAM","CONFIRMED_PATTERN")) or \
          (expect=="delete" and v.tier!="CONFIRMED_PATTERN")
    print(f"{'*** DEFECT' if bad else 'ok       '} {name:34} score={v.score:4} tier={v.tier:18} carrier={getattr(v,'car_score',0):4}")
    for s in v.signals:
        print(f"            {s.weight:+4} {s.family:9} {s.name}")
    if getattr(v,'notes',None): print(f"            NOTES {v.notes}")
    print()
    return bad

print("="*100)
print("A. PRECISION: invented-but-realistic LEGITIMATE messages (want: clean / not flagged)")
print("="*100)

FP = [
("A1 wholesale veg mandi rate list",
 "Aaj ka mandi rate: pyaaz 128 rs, aloo 112 rs, tamatar 145 rs per kg. Bulk supply only, "
 "dealer commission 2%. Order @sabzi_mandi_jaipur, call +91 98290 12345, t.me/sabzimandi"),

("A2 mobile accessory wholesaler",
 "Wholesale rate list: tempered glass 129, back cover 149, charger 199, cable 115. "
 "Rate fix hai, no bargaining. Reseller commission 5% daily on volume. "
 "@mobile_accessories_wholesale +91 90000 11111 t.me/mobacc"),

("A3 options trading group",
 "Bank Nifty 52000 CE premium 145 chal raha hai abhi, PE premium 132. "
 "Stock 120 ke aas paas support hai. Target 190 rakho, SL 110."),

("A4 CA offering company registration",
 "CA services: current account chahiye toh hum arrange kar dete hain. "
 "Per account 2000 charges, documents ready. Firm account ke liye alag. "
 "Contact @ca_services_delhi or +91 98111 22222"),

("A5 HDFC DSA merchant onboarding job",
 "Hiring DSA partners. We need current account holders and merchant account holders for "
 "our POS onboarding drive. Commission 2% per account opened, paid daily. "
 "Field work only. Apply @dsa_partner_desk"),

("A6 bank AMB fee question",
 "Kya HDFC ne charges badha diye? AMB per account is 10,000 now for current accounts. "
 "Pehle 25000 tha Kotak me. Koi aur bank suggest karo jahan kam ho."),

("A7 CN police counterfeit warning w/ courier",
 "警方提示：最近有人通过快递销售假钞，收到陌生包裹不要签收。"),

("A8 CN shopkeeper warning: notes CAN pass checker",
 "各位小心，这批假钞可过验钞机，手感也很像，收现金的时候多留意一下。"),

("A9 legit crypto OTC desk, no compliance words",
 "OTC desk. Buying and selling stablecoin at market. Rate today 118 for bulk above 10 lakh. "
 "Settlement instant. @otcdesk_blr +91 99999 88888 t.me/otcdeskblr"),

("A10 silver bullion dealer",
 "Chandi ka rate: 999 fine 128 rs per gram, 925 sterling 112 rs, scrap 105 rs. "
 "Rate fix, dealer commission 1.5%. @bullion_traders_jp +91 94140 00000 t.me/bulliontraders"),

("A11 tuition/coaching fee sheet",
 "Fee structure per month: Class 10 physics 150, chemistry 130, maths 175. "
 "Sibling discount available. Enquiry @coaching_center_pune"),
]
bad = sum(show(n,t,"clean") for n,t in FP)

print("="*100)
print("B. EVASION: cheapest rewrites of a KNOWN positive (want: still CONFIRMED)")
print("="*100)

P01 = ("\U0001f525 USDT ➡️ INR \U0001f525\nRate 128/- fix hai bhai, market se 35 rs upar\n"
       "Bank account chahiye on rent \U0001f4af\nCurrent account = 3% commission, saving = 2%\n"
       "Daily limit 5 lakh se 25 lakh tak\nKit ready hona chahiye — ATM card + passbook + sim + net banking\n"
       "Freeze hua toh compensation hum denge ✅\nDM \U0001f449 @rk_settlement_01")
P19 = ("USDT to INR at 128, need bank accounts on rent, 3% commission daily. Instant payout, "
       "we cover the freeze risk. Only Indian accounts, minimum 6 months old. DM @fastinrdesk")

EV = [
("B0 baseline P01 (unmodified)", P01),
("B1 P01 + 'GST bill milega'",              P01 + "\nGST bill milega ✅"),
("B2 P01 + 'API available'",                P01 + "\nAPI available for bulk partners"),
("B3 P01 + 'paper work ready rakho'",       P01 + "\nPaper work ready rakho"),
("B4 P01 + 'kaise karna hai puchho'",       P01 + "\nKaise karna hai woh puchho"),
("B5 P01 soft-hyphen in 'account'",         P01.replace("Bank account chahiye on rent","Bank acco­unt chahiye on re­nt")),
("B6 P01 rate 128 -> 102 (below band)",     P01.replace("128/-","102/-").replace("market se 35 rs upar","market se 12 rs upar")),
("B7 P19 + 'Beware of fake desks' + 'kaise'",
    P19 + " Beware of fake desks copying us, kaise verify karna hai puchh lo."),
("B8 P19 wrapped in quotes by scammer",     '"' + P19 + '"'),
("B9 P01 + 'GST' + 'API' (belt & braces)",  P01 + "\nGST invoice + API access available"),
]
bad2 = sum(show(n,t,"delete") for n,t in EV)

print("="*100)
print("C. PERFORMANCE / BACKTRACKING")
print("="*100)
for label, s in [
    ("10KB 'a'*n + account rent", "a"*10000 + " account on rent"),
    ("nested quote bomb", '"' + "x"*5000 + '"' * 200),
    ("acct-sourcing pathological", ("bank account " + "word "*3)*400 + "chahiye"),
    ("rate word + no digits", ("rate "+"x"*19)*2000),
    ("many quotes", '"'+ "y"*40 + '"' + ('"'+"z"*40+'"')*500),
]:
    t0=time.perf_counter(); classify(s); dt=(time.perf_counter()-t0)*1000
    print(f"  {label:34} {dt:9.1f} ms  ({len(s)} chars)")

print(f"\nPRECISION DEFECTS: {bad}/{len(FP)}   EVASION DEFECTS: {bad2}/{len(EV)}")
