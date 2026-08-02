import os
# -*- coding: utf-8 -*-
"""Precision lens: 12 NEW ordinary Indian Telegram messages, none in corpus.py.
Every one is something a real person would post in a real group."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detector_v2 as D

CASES = [

("M01_rapido_payout_sheet", "gig-work payout card, 3 in-band numbers + the word payout/settlement",
"""🛵 Rapido captain payout update (Jaipur zone)
Peak hour incentive 145 per ride, airport pickup 160, night shift 120.
Weekly settlement every Monday, payout goes direct to your bank account.
Need 200 riders this month, no joining fee, petrol apka.
Fleet desk +91 98290 44112"""),

("M02_equity_intraday_chat", "ordinary stock chat: prices in band + T+1 settlement",
"""Aaj ka buy list bhai: IRFC at 145, IREDA at 178, Suzlon at 120.
Broker ne bola ab settlement T+1 hai, payout same day account me aa jata hai.
Koi aur le raha hai in teeno me?"""),

("M03_note_counting_machine_dealer", "shop selling a legal note-counting machine",
"""Maxsell / Godrej note counting machine with fake note detection.
Checks UV, magnetic ink and security thread. Works with the new 500 and 200 series notes.
Price 8,500 with 1 year warranty. Courier all India, COD available.
Shop in Karol Bagh, call +91 98110 22334"""),

("M04_frozen_account_victim", "victim describing his own frozen account and what the branch asked for",
"""Bhai mera HDFC account freeze ho gaya hai, branch wale bol rahe hain claim ke liye
passbook, PAN card aur cancelled cheque ki photo bhejo, net banking se 6 month ka
statement bhi nikal ke do. Cyber cell ka koi case Bengaluru se laga hai."""),

("M05_kurti_wholesale", "Jaipur wholesale rate list with a normal returns policy",
"""Ladies kurti wholesale, direct from Jaipur factory.
Rate list: cotton 145, rayon 165, printed georgette 120 per piece.
Minimum 20 pcs per design. 7 day return, no questions asked.
Courier all India, COD available. WhatsApp +91 94140 55221"""),

("M06_workspace_reseller", "Google Workspace / Zoho licence reseller, priced per seat",
"""Google Workspace Business Starter per account 1,500 rs per year, Zoho Mail per account 900 rs.
Need 10+ accounts minimum for the partner price. GST invoice given.
Payment by NEFT to our firm current account. Migration free.
Contact +91 99710 88445"""),

("M07_accounts_exec_hiring", "ordinary accounts-department job ad",
"""Hiring: Accounts Executive for our Andheri East office.
Tally Prime + GST filing, 2 years experience, salary 25k in hand.
We also want to hire two accounts interns for the audit season.
Field staff get 2% commission on collections, paid same day into their bank account.
Walk-in Monday to Wednesday. Contact +91 98200 11223"""),

("M08_hindi_admin_warning", "group admin warning members off mule recruitment, in Hinglish",
"""Group admin notice: koi bhi apna bank account kisi ko kiraye pe mat do.
Log 2-3% commission ka lalach dete hain, paisa aayega phir aap withdraw karke
unke aadmi ko de doge, aur baad me account freeze ho jayega.
Kisi bhi link pe click mat karna. - @jaipur_traders_admin"""),

("M09_bc_csp_franchise", "Fino/Airtel BC (business correspondent) point franchise, a legal RBI channel",
"""Fino Payments Bank CSP (BC point) franchise open.
Har block me agent chahiye. Aapke naam ka current account chahiye,
daily cash limit 2 lakh, commission 0.5% har transaction pe, settlement same day.
Aadhaar, PAN card, passbook aur cancelled cheque ki copy bhejo.
Contact @fino_csp_rajasthan"""),

("M10_kerala_lottery_cn", "Chinese speaker in India discussing the legal Kerala state lottery",
"""喀拉拉邦的彩票是政府发行的，昨天开奖了，我同事中了两千卢比。
这边跟国内不一样，下注是合法的，商店里就能买。"""),

("M11_freelancer_rates", "freelancer comparing his own hourly rates, INR settlement",
"""Upwork se paisa aa gaya finally. Pehle rate 150 per hour tha, ab client 175 de raha hai,
urgent kaam ka rate 190 hai. Payoneer se INR settlement 2 din leta hai.
Kisi ne is saal ka TDS kaise dikhaya?"""),

("M12_group_rules_pinned", "the moderation policy of the very group ScamShield would run in",
"""Group rules (pinned): we delete on sight — bank account on rent offers,
USDT to INR at 128 type rate ads, colour prediction and satta links, fake note
sellers, and any DM asking for your passbook or ATM card.
Repeat offenders are banned. Mods: @modteam"""),
]

WORST = ("LIKELY_SCAM", "CONFIRMED_PATTERN")

def show(name, why, text):
    v = D.classify(text)
    bad = v.tier in WORST
    mark = "!!! " if bad else "    "
    print(f"{mark}{name:34s} {v.tier:18s} score={v.score:3d}  car={v.car_score:3d}  fams={sorted(v.families)}")
    if bad or "-v" in sys.argv:
        print(f"      ({why})")
        for s in v.signals:
            print(f"        {s.weight:+4d} [{s.family:10s}] {s.name}: {s.detail[:110]}")
        for n in v.notes:
            print(f"        note: {n}")
        print()
    return bad

if __name__ == "__main__":
    n = 0
    for name, why, text in CASES:
        n += show(name, why, text)
    print(f"\n{n}/{len(CASES)} reach LIKELY_SCAM or above")
