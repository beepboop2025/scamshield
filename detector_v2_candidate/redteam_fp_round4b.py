import os
# -*- coding: utf-8 -*-
"""Round-4B false-positive hunt: same 'ordinary Indian Telegram message' bar as
round 4A, but written after reading which regexes actually mint a STRONG family.

usage: python3 redteam_fp_round4b.py [module_name]
"""
import sys, importlib

CAND = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CAND)
D = importlib.import_module(sys.argv[1] if len(sys.argv) > 1 else "detector_v2_merged")

BAD = ("LIKELY_SCAM", "CONFIRMED_PATTERN")

CASES = [

("G01_csp_aeps_explainer", "BC/CSP franchise explaining how an AePS withdrawal works",
 "Gramin CSP point start karein apne gaon me. Customer ke khate me DBT ka paisa aayega, wo "
 "aapke point pe aakar Aadhaar se withdraw kar lega, aur aapko har transaction pe commission "
 "milega. Daily limit 1 lakh tak ka cash aap handle kar sakte hain. Settlement T+1 me aapke "
 "current account me. Account holders ko passbook print aur mini statement bhi de sakte hain. "
 "Device aur training hum denge. 9838012345"),

("G02_deep_freezer_dealer", "appliance dealer selling a deep freezer with a compressor guarantee",
 "Deep freezer 300 litre, 5 saal compressor guarantee, 24500 me. Blue Star aur Voltas dono "
 "stock me hain. Ice cream parlour, dairy aur medical store ke liye best. GST bill ke saath, "
 "Jaipur city me delivery free. @coolworld_jaipur"),

("G03_surat_zari_wholesaler", "Surat textile wholesaler: zari / embroidery dupattas",
 "Surat se direct — pure silver thread zari work wale dupatte aur lehenga set. Hand work aur "
 "machine work dono available, machine me chalne wala fabric alag rakha hai. Bulk me 1:3 ke "
 "ratio me set banate hain, matlab teen dupatta ek lehenga ke saath. Sample courier kar denge, "
 "COD bhi chalega. Rate list DM me. 9727012345"),

("G04_ro_uv_purifier_dealer", "RO+UV water-purifier dealer quoting the reject ratio",
 "RO + UV + UF water purifier, 12 litre tank, copper model bhi hai. Reject water ka ratio 1:3 "
 "hai, matlab teen litre waste par ek litre clean. Machine me chalega borewell ka hard paani "
 "bhi, TDS 2000 tak. Free installation aur home delivery, COD available. Filter change 6 mahine "
 "me. 9845012345"),

("G05_virtual_office_ncr", "virtual-office provider for GST registration",
 "Virtual office on rent — GST registration + current account opening. Noida Sector 63 ka "
 "address, 1000 per month. Rent agreement, NOC aur electricity bill sab provide karenge. Hum "
 "current account opening support bhi provide karte hain, HDFC aur Kotak dono me tie-up hai. "
 "Physical desk chahiye to 4500 monthly. Call 9911012345 ya @voffice_ncr"),

("G06_payout_kyc_notice", "gig platform telling workers to use their own account for payouts",
 "Payout ke liye apna hi bank account use karein. Kisi dost ya rishtedaar ka khata mat dena, "
 "warna payment reject ho jayega aur dobara verification karana padega. Account holder ka naam "
 "PAN se exactly match hona chahiye. IFSC galat daala to paisa 3 din me wapas aayega."),

("G07_used_goods_buyer", "second-hand electronics buyer doing doorstep pickup",
 "Purane laptop, mobile, LED TV aur AC kharidte hain. Ghar se cash pickup, spot payment, no "
 "questions asked. Daily 20-30 piece ka limit hai to pehle photo bhejein. Screen tuti ho ya "
 "battery kharab ho to bhi le lenge, rate thoda kam milega. Andheri se Borivali tak aate hain. "
 "9820012345"),

("G08_sebi_dabba_news", "finance-group chatter about a SEBI crackdown on advisory groups",
 "SEBI ke latest order me likha hai ki Telegram pe chal rahe stock advisory groups, jo pehle "
 "free trial dete hain aur phir paid group me le jate hain, unke sure shot calls ka koi track "
 "record nahi hota. Gujarat me dabba trading ke case me bhi kai arrest hue hain pichle saal. In "
 "groups ka accuracy claim 90 percent tak jata hai lekin actual data kabhi publish nahi karte."),

("G09_matrimony_banter", "ordinary Hinglish banter about a couple and a college seat",
 "Bhai kya jodi banayi hai dono ne, ekdum perfect match. Uski to lottery lag gayi yaar, IIT "
 "Bombay me seat aa gayi aur shaadi bhi tay ho gayi ek hi mahine me. Waise mere andaaze ki "
 "accuracy bhi kam nahi hai, maine pichle saal hi bol diya tha ki inka kuch chakkar hai."),

("G10_kerala_lottery_agent", "authorised Kerala state-lottery agent, a legal business",
 "Kerala state lottery authorised agent, Ernakulam. Karunya, Win-Win, Sthree Sakthi aur Akshaya "
 "sab ticket milega. Result ki accuracy ke liye hamesha official site check karein, WhatsApp pe "
 "forward hone wale result galat hote hain. Jodi ya number scheme jaisa kuch nahi hota, ye sab "
 "afwah hai. Ticket 40 rupaye ka, minimum 5 lene padenge. @lottery_agent_kochi"),

("G11_ed_hawala_news", "news chat about an ED hawala seizure",
 "ED ne Surat me 400 crore ka hawala racket pakda hai, 12 log detain hue hain. Angadia firms ke "
 "through Mumbai se paisa ja raha tha. Aaj ke Divya Bhaskar me full page news hai, aur ek "
 "angadia association ne bayan bhi diya hai ki sab log aise nahi hote."),

("G12_pa_merchant_bizdev", "licensed payment aggregator's business-development post",
 "We are a licensed payment aggregator and we need payin merchants in the travel and education "
 "vertical. Onboarding is full KYC, current account required in the firm name, settlement T+1, "
 "and our commission is 1.8% per transaction. Instant payout available on request for a small "
 "extra fee. Daily volume capacity 50 lakh per merchant. RBI PA licence number on our site. "
 "DM @pa_bizdev_in"),

("G13_p2p_premium_complaint", "retail user complaining about the INR premium on P2P",
 "Aaj Binance P2P pe INR premium pagal ho gaya hai. Buy side rate 105 dikha raha hai, sell side "
 "rate 112, aur ek banda to ₹118 quote kar raha hai, jabki global spot 90 ke aas paas hai. "
 "Escrow ke bahar koi deal mat karna, aur bank transfer wale sellers se door raho."),

("G14_cash_payment_269st", "small business owner asking a tax question about cash payouts",
 "Bhai ek doubt hai. Vendor ke account me paisa aayega settlement ke time, phir wo apne bank se "
 "withdraw karke labour ko cash de deta hai. Iske liye koi extra compliance hai kya? Humara CA "
 "bol raha hai 2 lakh se upar cash payment pe 269ST lagega aur penalty barabar ki hai. Daily "
 "limit 50000 rakhein to safe hai?"),

("G15_community_kitchen", "free community kitchen post",
 "Andheri East me jisko bhi khane ki zarurat ho, station ke peeche hamari free community "
 "kitchen hai. 12 se 3 ke beech aa jaiye, tiffin le jaiye, no questions asked. Raat ke shelter "
 "ki list bhi hai humare paas. Koi donation zaruri nahi hai, lekin madad karni ho to "
 "@sewa_andheri pe message kar dein."),
]

print("=" * 96)
print("ROUND-4B FRESH FALSE-POSITIVE HUNT   module:", D.__name__)
print("=" * 96)

bad, watch = [], []
for name, why, text in CASES:
    v = D.classify(text)
    mark = "  <<< FALSE POSITIVE" if v.tier in BAD else ""
    print("\n%-30s %-18s score=%-4d car_score=%s%s" %
          (name, v.tier, v.score, getattr(v, "car_score", "n/a"), mark))
    print("   (%s)" % why)
    for s in v.signals:
        print("      %+5d  %-12s %-40s | %s" % (s.weight, s.family, s.name, s.detail[:100]))
    print("      families(strong)=%s  iocs=%s" %
          (sorted(v.families), {k: x for k, x in v.iocs.items() if x}))
    for n in v.notes:
        print("      note: %s" % n)
    if v.tier in BAD:
        bad.append((name, v))
    elif v.tier == "WATCH":
        watch.append((name, v))

print("\n" + "=" * 96)
print("SUMMARY: %d/%d reached LIKELY_SCAM or CONFIRMED_PATTERN" % (len(bad), len(CASES)))
for n, v in bad:
    print("   FP    %-28s %-18s score=%d families=%s" % (n, v.tier, v.score, sorted(v.families)))
print("   ---- WATCH (visible to a human, not actioned) ----")
for n, v in watch:
    print("   WATCH %-28s score=%d families=%s" % (n, v.score, sorted(v.families)))
