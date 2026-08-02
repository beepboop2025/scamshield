# -*- coding: utf-8 -*-
"""Round-4 false-positive hunt against a merged detector build.

15 FRESH ordinary Indian Telegram messages, none reused from corpus.py
(N01-N32) or redteam_precision_cases.py (M01-M12).

usage: python3 redteam_fp_round4.py [module_name]
"""
import sys, importlib

CAND = "/Users/user/dev/scamshield/detector_v2_candidate"
sys.path.insert(0, CAND)
D = importlib.import_module(sys.argv[1] if len(sys.argv) > 1 else "detector_v2_merged")

BAD = ("LIKELY_SCAM", "CONFIRMED_PATTERN")

CASES = [

# ---- 1. Hinglish anti-mule warning, ordinary member (not admin) ----------
("F01_hinglish_antimule_warning", "member warning the group off mule recruitment, Hinglish",
 "Bhaiyo dhyan se suno. Mere padosi ke bete ne apna current account ek company ko de diya "
 "tha, unhone bola tha pachees hazar mahina milega aur kuch nahi karna, bas account chalne "
 "dena hai. Do mahine baad account seize ho gaya aur ab wo ladka police station ke chakkar "
 "kaat raha hai. Kisi anjaan aadmi ko apna khata, ATM card, cheque book ya SIM mat do, chahe "
 "kitna bhi paisa offer kare. Yeh sab fraud ka paisa hota hai aur FIR aap pe hoti hai, unke "
 "upar nahi. Agar galti se de diya hai to turant bank ko likh ke do."),

# ---- 2. group moderation notice ------------------------------------------
("F02_mod_notice_hardware_group", "mods of a hardware/logistics group listing what gets deleted",
 "Notice from the mods. Is group me sirf hardware, logistics aur import-export ki baat hogi. "
 "Neeche wali post turant delete hogi aur banda permanently ban hoga:\n"
 "1. Bank account rent ya sell karne wali koi bhi post\n"
 "2. USDT ka rate quote karna ya crypto ka buy/sell offer\n"
 "3. Ghar baithe daily commission wale part time job ad\n"
 "4. Fake note, fake ID ya fake GST bill ka koi offer\n"
 "Pichle hafte hamne 6 members remove kiye. Agar aapko aisa DM aata hai to screenshot "
 "mods ko bhejein, group me forward mat karein."),

# ---- 3. BC / CSP franchise (a legal RBI banking-correspondent channel) ----
("F03_bc_csp_franchise", "Fino/AePS business-correspondent point franchise ad",
 "Fino Payments Bank ka CSP point franchise available hai Sitapur aur aaspaas ke blocks me. "
 "Services: Aadhaar enabled payment system, cash deposit aur withdrawal, DBT credit check, "
 "mini statement, money transfer aur new account opening. Commission structure: AePS "
 "withdrawal pe 0.50%, cash deposit pe fixed slab, aur monthly settlement seedha aapke "
 "current account me T+1 pe. Requirement: shop, laptop, printer, Morpho device aur 25000 "
 "security deposit jo refundable hai. Training hum denge. Interested log call karein "
 "9838012345 ya @csp_help_up pe message karein."),

# ---- 4. note-counting-machine seller -------------------------------------
("F04_note_machine_wholesaler", "wholesale dealer of legal note-counting / fake-note-detecting machines",
 "Note counting machine wholesale — Godrej, Maxsell aur Strob ke saare models stock me hain. "
 "Mix note value counter with fake note detection (UV + MG + IR sensor), 2 saal warranty, "
 "GST bill milega. Rate list: MX50 basic 8500, MX70 value counter 12900, bank grade heavy "
 "duty 24500. Spare UV tube 145 aur sensor cleaning kit 190 alag se. Bulk order pe extra "
 "discount aur all India courier free. Demo video bhej sakta hoon. Sharma Traders, Chandni "
 "Chowk, Delhi. @sharma_machines / 9811023456"),

# ---- 5. legal state-lottery chat -----------------------------------------
("F05_state_lottery_chat", "ordinary chat about the legal Kerala / Nagaland state lotteries",
 "Karunya Plus KN-540 ka result aa gaya, first prize 80 lakh Kozhikode series ko gaya. Main "
 "har hafte do ticket leta hoon, 40 rupaye ka ek. Dear Nagaland ka evening draw 8 baje hota "
 "hai aur Sambad ka result uske baad site pe aata hai. Kerala lottery hamesha authorised "
 "agent se hi lena chahiye, online reseller pe bharosa mat karo. Is baar kuch nahi laga, "
 "agli baar dekhte hain."),

# ---- 6. accounts-executive job ad ----------------------------------------
("F06_accounts_exec_job", "ordinary accounts-department hiring post",
 "Hiring: Accounts Executive for a textile export firm in Tirupur. Work: Tally Prime entries, "
 "GST returns (GSTR-1 and 3B), e-way bills, monthly bank reconciliation of our four current "
 "accounts, and processing vendor payouts through RTGS and NEFT. Salary 22000 to 28000 per "
 "month depending on experience, PF and ESI applicable, Saturday half day. B.Com freshers can "
 "apply, 2 years experience preferred. Send CV on WhatsApp 9443012345 or walk in Saturday "
 "10am at the Avinashi Road office. No consultancy charges, we hire directly."),

# ---- 7. wholesale rate list ----------------------------------------------
("F07_dryfruit_rate_list", "Delhi dry-fruit and spice wholesale rate sheet",
 "Aaj ka wholesale rate, per kg, ex-Delhi, GST extra:\n"
 "Cashew W240 — 745\n"
 "Almond California — 690\n"
 "Kishmish Indian — 195\n"
 "Kaju tukda — 520\n"
 "Black pepper — 128\n"
 "Jeera — 118\n"
 "Elaichi small — 2850\n"
 "Rate 6 baje tak valid hai. Minimum order 10 kg. Payment advance NEFT ya delivery pe cash, "
 "transport alag. Party rate ke liye DM karein."),

# ---- 8. payment-ops thread -----------------------------------------------
("F08_payout_failure_thread", "merchant payment-ops thread about a payout outage",
 "Anyone else on Cashfree seeing payout failures since last night's NPCI maintenance window? "
 "Our IMPS payouts sit in PENDING for about 40 minutes and then reverse. Payin is completely "
 "fine. We push roughly 12000 transactions a day and settlement is T+1 into the nodal account. "
 "Ticket CF-441822 raised at 11pm, no response yet. Separately our per-transaction payout cap "
 "was dropped from 2L to 1L without any notice — did anyone get a circular about that, or is "
 "it only our MID?"),

# ---- 9. cash-in-transit vendor -------------------------------------------
("F09_cit_vendor", "licensed cash-in-transit / doorstep-banking vendor pitch",
 "Cash-in-transit and doorstep banking vendor for the Pune region. We do daily cash pickup "
 "from retail outlets, sorting and counting at our processing centre, and same-day deposit "
 "into your bank account before the clearing cutoff. Insured up to 25 lakh per trip, armed "
 "guard, GPS tracked vans, and we already handle ATM cassette replenishment for two banks. "
 "Pricing is roughly 0.06% of value with a minimum per pickup, monthly invoice with GST. We "
 "follow the RBI outsourcing guidelines and can share our last audit report. "
 "Contact @cashlogix_pune"),

# ---- 10. frozen-account victim -------------------------------------------
("F10_olx_freeze_victim", "victim whose account was lien-marked after an OLX sale",
 "Guys mera SBI savings account do din se debit freeze hai. Maine OLX pe apna purana laptop "
 "becha tha aur buyer ne UPI se 18000 bheje the. Ab bank bol raha hai ki Rajasthan cyber cell "
 "se lien mark hua hai kyunki kisi complaint me mera account trail me aa gaya. Branch manager "
 "keh raha hai NOC lao. Mujhe kya pata tha paisa kahan se aaya, maine to sirf laptop becha "
 "tha. Koi bataye ki 1930 pe call karna chahiye ya seedha cyber cell jaana chahiye, aur koi "
 "acha lawyer suggest karo Jaipur me."),

# ---- 11. gold-loan franchise ---------------------------------------------
("F11_gold_loan_branch", "authorised gold-loan branch advertising rates",
 "Gold loan at 0.79% per month, up to 75% LTV, same day disbursal directly into your bank "
 "account. No processing fee till the end of this month. Bring original jewellery, Aadhaar and "
 "PAN, nothing else needed. We also buy gold at today's rate: 22K at 6140 per gram and 24K at "
 "6680 per gram, payment by RTGS the same day, no cash above the limit. Authorised franchise, "
 "Shivaji Nagar branch, open 9 to 7. WhatsApp 9886012345 for an appointment."),

# ---- 12. Chinese-language legitimate freight forwarder --------------------
("F12_cn_freight_forwarder", "CN freight forwarder to India, explicitly refusing hawala",
 "我们做印度专线物流，孟买、德里、金奈都能送。海运大概 25 天，空运 5 到 7 天。清关我们自己有牌照，"
 "GST 那边也能正常开票。收款支持人民币或者卢比，走正规银行电汇，不做地下钱庄那一套，也不接受现金交割。"
 "有需要的老板可以私聊，把报关资料准备好就行。"),

# ---- 13. registered chit fund --------------------------------------------
("F13_registered_chit_fund", "a Chit Funds Act registered chit, explaining its own mechanics",
 "Registered chit fund group starting next month: 20 members, 5 lakh chit value, 25 months. "
 "Monthly subscription is 20000. Auction on the 5th of every month, discount capped at 30% as "
 "per the Chit Funds Act, and foreman commission is 5% which is the legal maximum. The prized "
 "subscriber gets the payout into his bank account within two working days after "
 "documentation. Registrar of Chits registration number will be shared before you join. This "
 "is not a scheme and not an investment plan, it is a regulated chit — we have been running "
 "batches since 2016. @chit_foreman_blr"),

# ---- 14. kirana UPI settlement complaint ---------------------------------
("F14_kirana_upi_settlement", "shopkeeper chasing a missing UPI settlement",
 "Paytm soundbox wale bhaiya bol rahe the ki ab settlement T+1 ho gaya hai lekin mere paise do "
 "din se nahi aaye. Daily 40 se 50 hazar ka collection hota hai QR se. Kal ek customer ne 1150 "
 "ka payment kiya, uske phone pe success dikha lekin mere current account me credit nahi hua. "
 "Kisi ko pata hai complaint kahan karein? NPCI ke UPI helpline pe likha hai 30 din lag sakte "
 "hain, itna time to nahi hai bhai."),

# ---- 15. licensed PA/PG merchant-onboarding job --------------------------
("F15_pa_pg_onboarding_job", "compliance job at a licensed payment aggregator",
 "We are hiring a Merchant Onboarding Executive (payin / payout) for a licensed payment "
 "aggregator in Noida. Role: KYC verification of merchant current accounts, risk scoring of "
 "new merchants, chargeback handling, and coordinating with the settlement team on T+1 payouts "
 "and nodal reconciliation. You must know the RBI PA/PG guidelines and be comfortable saying "
 "no to a merchant. CTC 6 to 9 LPA depending on experience. This is a compliance role, not a "
 "sales role, and there is no commission component. Apply through the careers page or DM "
 "@hiring_noida_fin."),
]

FLAG, DEL = 35, 60

print("=" * 96)
print("ROUND-4 FRESH FALSE-POSITIVE HUNT   module:", D.__name__)
print("=" * 96)

bad = []
for name, why, text in CASES:
    v = D.classify(text)
    mark = "  <<< FALSE POSITIVE" if v.tier in BAD else ""
    print("\n%-32s %-18s score=%-4d car_score=%s%s" %
          (name, v.tier, v.score, getattr(v, "car_score", "n/a"), mark))
    print("   (%s)" % why)
    tot = 0
    for s in v.signals:
        tot += s.weight
        print("      %+5d  %-14s %-42s | %s" % (s.weight, s.family, s.name, s.detail[:96]))
    print("      ----- raw sum of ALL listed signals = %+d ; Verdict.score = %d" % (tot, v.score))
    if v.notes:
        for n in v.notes:
            print("      note: %s" % n)
    if v.tier in BAD:
        bad.append((name, v))

print("\n" + "=" * 96)
print("SUMMARY: %d/%d reached LIKELY_SCAM or CONFIRMED_PATTERN" % (len(bad), len(CASES)))
for n, v in bad:
    print("   FP  %-32s %-18s score=%d  families=%s" % (n, v.tier, v.score, sorted(v.families)))
print("also-ran (WATCH, score>=15):")
for name, why, text in CASES:
    v = D.classify(text)
    if v.tier == "WATCH":
        print("   WATCH %-30s score=%d" % (name, v.score))
