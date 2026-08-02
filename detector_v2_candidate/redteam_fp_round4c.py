import os
# -*- coding: utf-8 -*-
"""Round-4C: minimal-trigger ablation for the round-4B false positives."""
import sys, importlib
CAND = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CAND)
M = importlib.import_module("detector_v2_merged")
P = importlib.import_module("detector_v2_precision_patch")
B = importlib.import_module("detector_v2")


def show(tag, text, mods=(("merged", M),)):
    for nm, mod in mods:
        v = mod.classify(text)
        print("  [%-9s] %-18s score=%-3d  %s" %
              (nm, v.tier, v.score,
               ", ".join("%s%+d" % (s.name, s.weight) for s in v.signals) or "-"))
    print("     %s" % tag)
    print()


print("=" * 92)
print("A. G03 — which 3 tokens mint counterfeit_note_offer(45) in a textile ad")
print("=" * 92)
BASE = ("Surat se direct dupatte aur lehenga set, bulk rate. Sample courier kar denge, "
        "COD bhi chalega. 9727012345")
for extra, tag in [
    ("", "control: no counterfeit token"),
    (" Pure silver thread zari work.", "1 token: silver thread"),
    (" Pure silver thread zari work. Machine me chalne wala fabric alag hai.",
     "2 tokens: + 'machine me chal'"),
    (" Pure silver thread zari work. Machine me chalne wala fabric alag hai. "
     "Set 1:3 ke ratio me banate hain.",
     "3 tokens: + '1:3'  <-- crosses en_hits>=3"),
    (" Pure silver thread zari work. Machine me chalne wala fabric alag hai. "
     "Set 1:3 ke ratio me banate hain. Aur haan, note counting machine bhi bech rahe hain.",
     "3 tokens + a NOTE-COUNTING-MACHINE mention -> C7 appliance guard rescues it"),
]:
    show(tag, BASE + extra)

print("=" * 92)
print("B. G03 tier escalation: LIKELY in base/precision, CONFIRMED in merged")
print("=" * 92)
G03 = ("Surat se direct — pure silver thread zari work wale dupatte aur lehenga set. Hand work aur "
       "machine work dono available, machine me chalne wala fabric alag rakha hai. Bulk me 1:3 ke "
       "ratio me set banate hain, matlab teen dupatta ek lehenga ke saath. Sample courier kar denge, "
       "COD bhi chalega. Rate list DM me. 9727012345")
show("full G03", G03, (("base", B), ("precision", P), ("merged", M)))
print("  merged _confirms({COUNTERFEIT}) =", M._confirms(
    [s for s in M.classify(G03).signals if s.family in M.STRONG_FAMILIES]))
print("  base    _confirms({COUNTERFEIT}) =", B._confirms(
    [s for s in B.classify(G03).signals if s.family in B.STRONG_FAMILIES]))
print("  -> the merged/correctness single-family COUNTERFEIT carve-out in _confirms()")
print("     is what turns this from a flag into a deletion.")
print("  drop the phone number (no IOC):")
show("no IOC -> CONFIRMED gate n_ioc<1 catches it", G03.replace(" 9727012345", ""),
     (("merged", M),))

print("=" * 92)
print("C. G05 — the 24-char window in _ACCOUNT_RENT_RE")
print("=" * 92)
for t, tag in [
    ("Virtual office on rent — GST registration + current account opening. 1000 per month.",
     "'on rent' ... 22 chars ... 'current account'  -> INSIDE the {0,24} window"),
    ("Virtual office on rent for company incorporation and current account opening. 1000/month.",
     "same ad, longer connector (36 chars) -> OUTSIDE the window, no signal"),
    ("Virtual office on rent — GST registration + current account opening. We also provide "
     "current account opening support with HDFC. 9911012345",
     "+ 'provide ... current account' -> account_sourcing_demand goes STRONG (rent_offer=True)"),
]:
    show(tag, t)

print("=" * 92)
print("D. G08/G09/G10 — GAMBLING needs 2 _IN_BET_RE hits + 1 _TIPS_FRAME_RE hit")
print("=" * 92)
for t, tag in [
    ("Uski to lottery lag gayi yaar.", "'lottery' alone = 1 hit, WEAK"),
    ("Kya jodi hai, aur uski to lottery lag gayi yaar.", "'jodi'+'lottery' = 2 hits, no tips frame"),
    ("Kya jodi hai, aur uski to lottery lag gayi. Mere andaaze ki accuracy kam nahi hai.",
     "+ the single word 'accuracy' -> gambling_tips_ad 40"),
    ("Kya jodi hai, aur uski to lottery lag gayi. Free trial wala scheme tha.",
     "'free trial' works as the tips frame just as well"),
]:
    show(tag, t)

print("=" * 92)
print("E. G07/G15 — 'no questions asked' outside a returns policy")
print("=" * 92)
for t, tag in [
    ("Tiffin le jaiye, no questions asked.", "charity phrasing -> source_of_funds_waiver 30"),
    ("7 din me return, no questions asked.", "_RETURNS_POLICY_RE exempts it -> 0"),
    ("Purane laptop kharidte hain, ghar se cash pickup, no questions asked. 9820012345",
     "+ cash pickup -> 40, LIKELY_SCAM"),
]:
    show(tag, t)

print("=" * 92)
print("F. G02 — _FREEZE_COMP_RE fires on a literal freezer")
print("=" * 92)
for t, tag in [
    ("Deep freezer 300 litre, 5 saal compressor guarantee, 24500 me.",
     "'freezer' .. 26 chars .. 'guarantee' -> freeze_compensation_offer 30"),
    ("Deep freezer 300 litre available. Compressor pe 5 saal ki guarantee milegi.",
     "same ad, 38 chars apart -> still inside {0,45}"),
    ("Frozen food supply karte hain, quality guarantee ke saath. Courier all India.",
     "'Frozen' + 'guarantee' -> also fires"),
]:
    show(tag, t)

print("=" * 92)
print("G. G01/G14 — _CASHOUT_RE branch 2 on ordinary 'money arrives, then withdraw'")
print("=" * 92)
for t, tag in [
    ("Customer ke khate me DBT ka paisa aayega, wo Aadhaar se withdraw kar lega.",
     "the AePS mechanic, described neutrally -> cashout_courier_mechanic 30"),
    ("Salary account me paisa aayega 1 tarikh ko, ATM se withdraw kar lena.",
     "a parent texting their child -> same 30"),
    ("Customer ke khate me paisa aayega, wo withdraw kar lega. Kisi aur ko mat dena.",
     "add a prohibition clause -> _only_in_prohibition rescues it"),
]:
    show(tag, t)

print("=" * 92)
print("H. G13 — three in-band numbers next to the word 'rate' + a crypto anchor")
print("=" * 92)
for t, tag in [
    ("Binance P2P pe buy side rate 105 dikha raha hai.", "1 rate + anchor -> above_market_rate 25"),
    ("Binance P2P pe buy rate 105, sell rate 112, aur ek banda ₹118 quote kar raha hai.",
     "3 in-band values -> + tiered_price_menu 20 = 45, LIKELY_SCAM"),
    ("Binance P2P pe buy rate 105, sell rate 112, ek banda ₹118. Global spot 90 hai.",
     "naming the real spot does not help: 90 is out of band, not a veto"),
]:
    show(tag, t)
