# -*- coding: utf-8 -*-
"""ScamShield v0.2 prototype: generalised, co-occurrence-gated signal set."""
from __future__ import annotations
import re, unicodedata
from dataclasses import dataclass, field

MARKET_USDT_INR = 90.0

# ---------------------------------------------------------------- normalise
# NFKC folds fullwidth (＝ -> =) but NOT Cyrillic homoglyphs or small caps.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "А":"A","В":"B","С":"C","Е":"E","Н":"H","І":"I","Ј":"J","К":"K","М":"M",
    "О":"O","Р":"P","Ѕ":"S","Т":"T","Х":"X","У":"Y","Г":"r","а":"a","в":"b",
    "с":"c","е":"e","о":"o","р":"p","ѕ":"s","т":"t","х":"x","у":"y","і":"i",
    "ј":"j","ԁ":"d","һ":"h","ӏ":"l","қ":"k","м":"m","н":"h","к":"k",
    # Greek -> Latin
    "Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N",
    "Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X","ο":"o","ρ":"p","α":"a","ν":"v",
    # Latin small-capital / phonetic (no NFKC decomposition)
    "ᴀ":"a","ʙ":"b","ᴄ":"c","ᴅ":"d","ᴇ":"e","ꜰ":"f","ɢ":"g","ʜ":"h","ɪ":"i",
    "ᴊ":"j","ᴋ":"k","ʟ":"l","ᴍ":"m","ɴ":"n","ᴏ":"o","ᴘ":"p","ǫ":"q","ʀ":"r",
    "ꜱ":"s","ᴛ":"t","ᴜ":"u","ᴠ":"v","ᴡ":"w","ʏ":"y","ᴢ":"z",
    # separators that ads use as decimal/thousands or bullets
    "－":"-","–":"-","—":"-","➖":"-","−":"-","‐":"-","‑":"-",
}
# Traditional -> Simplified for the CJK markers we key on (offline, no OpenCC).
_HANT2HANS = {"鈔":"钞","驗":"验","僞":"伪","偽":"伪","幣":"币","貨":"货","錢":"钱",
              "賣":"卖","買":"买","聯":"联","繫":"系","從":"从","優":"优","過":"过",
              "遞":"递","質":"质","賽":"赛","車":"车","彩":"彩","內":"内","幕":"幕",
              "點":"点","機":"机","銀":"银","盧":"卢","數":"数","發":"发","專":"专",
              "業":"业","準":"准","現":"现","額":"额","轉":"转","賬":"账","戶":"户"}

def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = "".join(_CONFUSABLES.get(c, c) for c in t)
    t = "".join(_HANT2HANS.get(c, c) for c in t)
    # collapse zero-width / bidi controls used to split tokens
    t = re.sub(r"[​-‏‪-‮⁠﻿]", "", t)
    return t

# ---------------------------------------------------------------- quoting
_QUOTE_RE = re.compile(r"[\"“”«»『「]([^\"“”«»』」]{20,1200})[\"“”«»』」]", re.S)
_BLOCKQUOTE_RE = re.compile(r"(?m)^\s*(?:>|\|)\s?.*$")

def split_quotes(text: str):
    """Return (carrier_text, quoted_text). Carrier = what the AUTHOR asserts."""
    quoted = []
    def _grab(m):
        quoted.append(m.group(1))
        return " ␣QUOTED␣ "
    carrier = _QUOTE_RE.sub(_grab, text)
    bq = _BLOCKQUOTE_RE.findall(carrier)
    if bq:
        quoted.extend(bq)
        carrier = _BLOCKQUOTE_RE.sub(" ␣QUOTED␣ ", carrier)
    return carrier, "\n".join(quoted)

# ---------------------------------------------------------------- rate layer
_INBAND_LO_MULT, _INBAND_HI_MULT = 1.15, 2.20   # 103.5 .. 198 at market 90

_NUM_RE = re.compile(r"(?<![\w.])(\d{3})(?![\w.]|\s*%)")

_FX_CTX = re.compile(
    r"\b(?:gbp|eur|aed|sar|kwd|qar|omr|bhd|sgd|cad|aud|chf|jpy|myr|thb|nzd|zar|usd)\b"
    r"|\b(?:pound|euro|dirham|riyal|rial|dinar|ringgit|yen)s?\b"
    r"|\b(?:wise|remitly|remittance|remit|western\s*union|xoom|instarem|forex|"
    r"mid-?market|nri)\b", re.I)

_QTY_RE = re.compile(r"(?<![\w.])(\d{2,6})\s*(?:usdt|usdts|tether|trx|qty|quantity|units?|pcs|nos)\b", re.I)

_RATE_WORD = (r"(?:rate|rates|bhav|bhaav|bhau|price|quote|quoting|payout|paying|"
              r"pay|buy(?:ing)?|sell(?:ing)?|de\s*raha|dega|milega|chal\s*raha|"
              r"per\s*unit|par\s*unit|fix|list)")
_ASSET = r"(?:usdt|tether|trc\s?-?20|erc\s?-?20|bep\s?-?20|usdt₮|\bust\b)"
_INR_CTX = (r"(?:inr|₹|rs\.?|rupee|rupya|rupaye|imps|neft|rtgs|upi|payin|pay-?in|"
            r"payout|settle|settlement|otc|p2p)")

# R1 asset<->number (price side only), R2 rate-word adjacency,
# R3 bare ratio 1:NNN, R4 currency-marked NNN/- or Rs NNN or NNN INR,
# R5 "at/@/for NNN" with INR-settlement context (checked at message level)
_R_ASSET_NUM = re.compile(rf"{_ASSET}[^\d\n]{{0,24}}?(\d{{3}})\b", re.I)
_R_NUM_ASSET = re.compile(rf"(\d{{3}})\s*(?:inr\s*)?(?:per|for|/|ka|each)\s*{_ASSET}", re.I)
_R_RATEWORD  = re.compile(rf"\b{_RATE_WORD}\b[^\d]{{0,20}}?(\d{{3}})\b"
                          rf"|(\d{{3}})\s*(?:/-)?[^\d\w]{{0,4}}\b{_RATE_WORD}\b", re.I)
_R_RATIO     = re.compile(r"(?<![\d.])1\s*[:=]\s*(\d{3})(?![\d.])")
_R_CURRENCY  = re.compile(r"₹\s*(\d{3})\b|\brs\.?\s*(\d{3})\b|(\d{3})\s*(?:/-|₹)"
                          r"|(\d{3})\s*(?:inr|rs\b|rupees?)", re.I)
_R_AT_NUM    = re.compile(r"(?:\bat|@|\bfor|\bupto|\babove|\bfix)\s*[:=]?\s*(\d{3})\b", re.I)

def _inband(n, mkt):
    return mkt * _INBAND_LO_MULT <= n <= mkt * _INBAND_HI_MULT

def _fx_adjacent(text, span):
    a, b = max(0, span[0] - 45), min(len(text), span[1] + 45)
    return bool(_FX_CTX.search(text[a:b]))

def _quantity_spans(text):
    return [m.span(1) for m in _QTY_RE.finditer(text)]

def extract_rates(text, mkt=MARKET_USDT_INR):
    """Return list of (value, span, form). Price-shaped, in-band, non-FX, non-qty."""
    qty = _quantity_spans(text)
    has_inr_ctx = bool(re.search(_INR_CTX, text, re.I)) or bool(re.search(_ASSET, text, re.I))
    out, seen = [], set()
    pats = [("asset_adj", _R_ASSET_NUM), ("num_per_asset", _R_NUM_ASSET),
            ("rate_word", _R_RATEWORD), ("ratio", _R_RATIO), ("currency", _R_CURRENCY)]
    if has_inr_ctx:
        pats.append(("at_num", _R_AT_NUM))
    for form, pat in pats:
        for m in pat.finditer(text):
            for gi in range(1, (m.re.groups or 0) + 1):
                if m.group(gi) is None:
                    continue
                sp = m.span(gi)
                n = float(m.group(gi))
                if not _inband(n, mkt):
                    continue
                if any(sp[0] >= q[0] and sp[1] <= q[1] for q in qty):
                    continue                      # it is a quantity, not a price
                if _fx_adjacent(text, sp):
                    continue                      # GBP/EUR remittance quote
                if sp in seen:
                    continue
                seen.add(sp)
                out.append((n, sp, form))
    return out

# ---------------------------------------------------------------- lexicons
_ABOVE_MKT_RE = re.compile(
    r"\b(?:market|bazar|bazaar|spot|bhav|bhaav)\b\s*(?:se|than|from|rate\s*se|ke)?\s*"
    r"\d{1,3}\s*(?:rs\.?|rupees?|₹|rupaye|rupya|%)?\s*"
    r"\b(?:upar|uper|upper|zyada|jyada|above|more|higher|extra|premium|plus)\b"
    r"|\b\d{1,3}\s*(?:rs\.?|rupees?|₹)?\s*\b(?:upar|uper|above|more|extra|premium)\b\s*"
    r"(?:se\s*)?\b(?:market|bazar|spot)\b"
    r"|\b(?:above|over)\s*market\s*rate\b", re.I)

_CASH_PICKUP_RE = re.compile(
    r"\bcash\s*(?:pick[\s-]?up|pickup|collection|handover|hand\s*over|delivery\s*boy)\b"
    r"|\bhawala\b|\bangadia\b|\bhundi\b|\bcash\s*(?:me|mein)\s*(?:dena|lena|denge)\b"
    r"|\bnever\s*touch\s*cash\b|\bcash\s*pickup\b", re.I)

_ACCT = (r"(?:bank\s*a/?c(?:count)?s?|current\s*a/?c(?:count)?s?|saving[s]?\s*a/?c(?:count)?s?|"
         r"salary\s*a/?c(?:count)?s?|corporate\s*a/?c(?:count)?s?|company\s*a/?c(?:count)?s?|"
         r"firm\s*a/?c(?:count)?s?|merchant\s*a/?c(?:count)?s?|personal\s*a/?c(?:count)?s?|"
         r"a/c|accounts?|khata|khaata)")
# NOTE: every alternative is \b-anchored on BOTH sides. "current" ends in "rent";
# an unanchored r"rent" fires on every "current account" in the corpus.
_RENT = (r"(?:\bon\s*rent\b|\bfor\s*rent\b|\brent\s*(?:pe|par|per|paid|payment|advance|amount)\b|"
         r"\brent(?:ed|al|als)?\b|\bkiray[ae]\b|\bkiraaye\b|\bhire[ds]?\b|\blease[ds]?\b|"
         r"\bbech\w*|\bsell\s*(?:your|apna|apni)\b)")
_ACCOUNT_RENT_RE = re.compile(rf"(?:{_ACCT}).{{0,24}}?{_RENT}|{_RENT}.{{0,24}}?(?:{_ACCT})",
                              re.I | re.S)

_SOURCE_VERB = (r"(?:chahiye|chaiye|chahiy\w*|wanted|required|requirement|need(?:ed|s)?|"
                r"looking\s*for|arrange|provide|supply|available|hiring|holders?|"
                r"bring\s*your\s*own|\bbyo\b|preferred|mangta|mangte)")
_ACCOUNT_SOURCING_RE = re.compile(
    rf"(?:{_ACCT})\W{{0,3}}(?:\w+\s+){{0,3}}?{_SOURCE_VERB}"
    rf"|{_SOURCE_VERB}\W{{0,3}}(?:\w+\s+){{0,3}}?(?:{_ACCT})"
    rf"|bring\s*your\s*own\s*bank", re.I)

_ACCOUNT_USE_RE = re.compile(
    r"(?:apna|apni|apne|aapka|aapke|aap\s*ka|your)\s*(?:\w+\s+){0,2}?"
    r"(?:bank\s*)?(?:a/?c(?:count)?|khata)\b.{0,25}?"
    r"(?:use\s*kar|istemaal|use\s*only|hamara|humara|our\s*business|de\s*dena|dena)",
    re.I | re.S)

_PER_ACCOUNT_PRICE_RE = re.compile(
    r"(?:\bper\b|\beach\b|\bhar\b|\bek\b|\b1\b|\bone\b)\s*(?:bank\s*)?a/?c(?:count)?\b"
    r"[^.\n]{0,40}?(?:₹|\brs\.?\s*|\binr\s*)?\d{1,3}(?:,\d{3})*\s*"
    r"(?:k\b|₹|\brs\b|rupees?|/-|,000|000\b|lakh|lac)", re.I)

_ACCT_TYPE_PRICE_RE = re.compile(
    r"\b(?:salary|current|saving[s]?|corporate|company|firm|merchant|personal|white|grey|gray|"
    r"fast|hacker|game|gaming|stock|hybrid|mixed|black|premium)\s*"
    r"(?:a/?c(?:count)?s?|cc|card|line|fund|desk|settlement|tier|slab)?\s*"
    r"(?:[-=:@–—]|\bat\b|\bis\b)?\s*(\d{3})\b", re.I)

_KIT_ITEM_RE = re.compile(
    r"\bpassbook\b|\bcheque\s*book\b|\bchequebook\b|\bcheck\s*book\b|\bnet\s*banking\b|"
    r"\binternet\s*banking\b|\batm\s*card\b|\bdebit\s*card\b|\bcredit\s*card\b|\bsim\b|"
    r"\bregistered\s*mobile\b|\baadhaar?\b|\bpan\s*card\b|\byubi\b|\bupi\s*id\b|"
    r"\botp\b|\bkyc\b|\bcanceled?\s*cheque\b|\btoken\s*device\b", re.I)
_HANDOVER_RE = re.compile(
    r"\bhand\s*over\b|\bhandover\b|\bde\s*dena\b|\bdena\s*hoga\b|\bdeni\s*hogi\b|"
    r"\bbhejo\b|\bbhej\s*do\b|\bbhejna\b|\bcourier\s*kar|\bwith\s*you\b|"
    r"\bsaath\s*(?:me|mein)\b|\bready\s*(?:hona|rakho|chahiye|hai)\b|\bphoto\s*bhej|"
    r"\bsend\s*(?:me|us|photo|copy)\b|\bupload\s*kar|\bfull\s*kit\b|\bkit\s*ready\b|"
    r"\bkit\s*(?:hai|chahiye|with)\b|\bbank\s*kit\b", re.I)

_CASHOUT_RE = re.compile(
    r"(?:withdraw\w*|nikal\w*|nikaal\w*|cash\s*out|cashout|paisa\s*nikal|amount\s*nikal)"
    r".{0,45}?(?:de\s*dena|de\s*do|dena\s*hoga|hand\s*over|handover|hamare|humare|"
    r"our\s*(?:man|guy|person|boy|agent)|aadmi|admi|deliver)"
    r"|(?:paisa|amount|funds?|money)\s*(?:aayega|aata|आएगा|comes?|credit\w*)"
    r".{0,60}?(?:withdraw|nikal|nikaal|cash\s*out)", re.I | re.S)

_FREEZE_COMP_RE = re.compile(
    r"\bfree[sz]\w*\b.{0,45}?(?:compensat\w*|cover\w*|guarantee\w*|bharenge|bhar\s*denge|"
    r"denge|de\s*denge|zimmedari|responsib\w*|refund|claim)"
    r"|(?:compensat\w*|cover|guarantee\w*|we\s*cover|hum\s*denge).{0,45}?\bfree[sz]\w*\b",
    re.I | re.S)

_SOF_WAIVER_RE = re.compile(
    r"(?:do\s*not|don'?t|never|no|nahi|nahin)\s*(?:\w+\s+){0,3}?"
    r"(?:ask|puchh?\w*|pooch\w*|require|need|check|verify)\s*(?:\w+\s+){0,3}?"
    r"source\s*of\s*(?:funds?|money)"
    r"|source\s*of\s*funds?\s*(?:not\s*required|nahi\s*|no\s*question)"
    r"|no\s*questions?\s*asked"
    r"|\bkoi\s*sawaal\s*nahi\b", re.I)

_PREDICATE_RE = re.compile(
    r"(?:overseas|offshore|foreign|international)\s*(?:\w+\s+){0,2}?"
    r"(?:gaming|gambling|betting|casino|colour|color)"
    r"|(?:gaming|betting|casino|gambling)\s*(?:volume|settlement|collection|payout|traffic|rails?)"
    r"|local\s*rails?|collection\s*partners?|settle\w*\s*(?:\w+\s+){0,3}?into\s*local", re.I)

_FRESH_ACCT_RE = re.compile(
    r"\bfresh\s*(?:bank\s*)?a/?c(?:count)?s?\b|\bnew\s*a/?c(?:count)?s?\s*only\b"
    r"|(?:purani|puraani|old|used|burnt|freeze[d]?)\s*(?:\w+\s+){0,2}?"
    r"(?:id|a/?c|account)\w*\s*(?:nahi|not|no\b)"
    r"|\bclean\s*history\b|\bclean\s*a/?c(?:count)?s?\b"
    r"|a/?c(?:count)?s?\s*(?:minimum|at\s*least)\s*\d+\s*(?:month|saal|year)", re.I)

_PAYIN_RECRUIT_RE = re.compile(
    r"\bpay[\s-]?in\b(?:[^.\n]{0,60}?)(?:chahiye|wanted|required|need|merchant|partner|"
    r"kaam\s*hai|capacity|recruit)"
    r"|(?:merchant|partner|agent)\s*chahiye[^.\n]{0,40}?\bpay[\s-]?(?:in|out)\b", re.I)

_COMMISSION_RE = re.compile(
    r"\d{1,2}(?:\.\d)?\s*%\s*(?:\w+\s+){0,3}?(?:commission|comm\b|cut|aapka|aapko|"
    r"yours?|per\s*(?:txn|transaction)|turnover|payin|pay-?in|payout|on\s*volume|daily)"
    r"|commission\s*(?:\w+\s+){0,2}?\d{1,2}(?:\.\d)?\s*%"
    r"|(?:har|per|every)\s*transaction\s*(?:pe|par|on)?\s*\d{1,2}(?:\.\d)?\s*%", re.I)

_FAST_SETTLE_RE = re.compile(
    r"settle\w*\s*(?:\w+\s+){0,3}?(?:\d{1,2}\s*(?:min|minute|ghant|hour)|instant|same\s*day|"
    r"turant|30\s*min|immediate)"
    r"|(?:\d{1,2}\s*(?:min|minute)|instant|turant)\s*(?:\w+\s+){0,2}?settle\w*"
    r"|instant\s*payout|payout\s*instant|\d{1,2}\s*min(?:ute)?s?\s*(?:ke\s*andar|me|mein|within)",
    re.I)

_THROUGHPUT_RE = re.compile(
    r"(?:daily|per\s*day|roz|monthly)\s*(?:\w+\s+){0,3}?(?:limit|capacity|volume|slab)"
    r"[^.\n]{0,30}?\d+\s*(?:lakh|lac|cr|crore|l\b|k\b)"
    r"|(?:limit|capacity|volume|slabs?)[^.\n]{0,20}?\d+\s*(?:lakh|lac|crore|l\b)"
    r"[^.\n]{0,30}?(?:daily|per\s*day|roz)"
    r"|volume\s*slabs?\s*[:\-]", re.I)

_HOMEJOB_RE = re.compile(
    r"\bpart[\s-]?time\s*job\b|\bghar\s*baithe\b|\bwork\s*from\s*home\b|\bwfh\s*job\b|"
    r"\bno\s*investment\b|\bdaily\s*(?:income|earning|payment)\b|"
    r"\b(?:kamaye|kamao|earn)\b[^.\n]{0,25}\bmonthly\b|"
    r"\bjob\s*100\s*%\b|\bno\s*(?:prior\s*)?experience\s*(?:needed|required)\b", re.I)

_SUBAGENT_RE = re.compile(
    r"\bagent\s*(?:chahiye|wanted|banne|banna|required|needed|onboard\w*)\b"
    r"|\b(?:city|area|region)\s*(?:wise|me|mein)\s*agent\b"
    r"|\bsub[\s-]?agent\b|\bcollection\s*partners?\b|\bregional\s*partners?\b", re.I)

_FUND_TIERS = ("hacker fund", "game fund", "stock fund", "hybrid fund", "mixed fund",
               "stocks fund", "game funds", "hacker funds", "mixed funds", "stock funds")

_PREPAID_RE = re.compile(
    r"(?:requires?|need|demand)\s*(?:\w+\s+){0,2}?prepay\w*|prepay\w*\s*of\s*usdt"
    r"|usdt\s*prepaid|after\s*receiving\s*the\s*deposit|advance\s*me\s*usdt", re.I)

_RECRUIT_PHRASE_RE = re.compile(
    r"\binr\s*work\b|\bunlimited\s*(?:purchase|quantity|qty)\b"
    r"|\blarge\s*(?:amount|number)\s*of\s*upi\b"
    r"|\b(?:do\s*not|don'?t)\s*(?:request|ask\s*for)\s*p2p\b"
    r"|\bno\s*p2p\b|\bp2p\s*drama\b|\bescrow\s*(?:not\s*required|nahi)\b"
    r"|\btime\s*waste\b|\bno\s*time\s*waste\b", re.I)

# ---- crypto rails / bridge (word-bounded: fixes 'stupid'/'Palimpsest' bugs)
_UPI_RE  = re.compile(r"(?<![a-z])upi(?![a-z])", re.I)
_IMPS_RE = re.compile(r"(?<![a-z])imps(?![a-z])", re.I)
_ASSET_RE = re.compile(_ASSET, re.I)

# ---- counterfeit
_CN_FAKE_NOUN = re.compile(r"假钞|假币|伪钞|仿钞|精仿|高仿|仿真(?:人民币|卢比|钞|币)")
_CN_MACHINE   = re.compile(r"验钞机|点钞机")          # legal appliance: 0 weight alone
_CN_OFFER     = re.compile(r"可过|可過|面交|快递|到付|货到付款|量大从优|量大优惠|"
                           r"联系|出售|供应|批发|现货|支持快递|直接交易")
_EN_FAKE_RE = [
    re.compile(r"\b(?:copy|replica|duplicate|fake|counterfeit|dupe)\s*(?:quality\s*)?"
               r"(?:note|notes|currency|cash|money|bills?)\b", re.I),
    re.compile(r"\b(?:security|silver)\s*thread\b", re.I),
    re.compile(r"\buv\b[^.\n]{0,20}(?:test|pass|light|check)|(?:pass\w*|check)[^.\n]{0,15}\buv\b", re.I),
    re.compile(r"\b(?:pen|marker|iodine)\s*(?:and|&|\+|,)?\s*uv\b|\bpen\s*test\b", re.I),
    re.compile(r"\b(?:500|200|2000|100)\s*(?:&|and|,|\+)\s*(?:500|200|2000|100)\s*series\b", re.I),
    re.compile(r"(?:ratio\s*)?\b1\s*:\s*[2-9]\b(?:\s*ratio)?", re.I),
    re.compile(r"\bmachine\s*(?:me|mein)?\s*(?:bhi\s*)?(?:chal|pass)\w*", re.I),
    re.compile(r"\b(?:note|notes)\s*(?:wale|wala|supply|supplier)\b", re.I),
]
_DELIVERY_RE = re.compile(
    r"\bcourier\b|\bcash\s*on\s*delivery\b|\bcod\b|\bhome\s*delivery\b|\bdoor\s*step\b|"
    r"\bpan[\s-]?india\s*(?:delivery|courier|shipping)?\b|\bpersonal\s*meet\b|面交|快递|到付", re.I)

# ---- gambling
_CN_BET_STRONG = re.compile(r"六合彩|时时彩|幸运飞艇|北京赛车|加拿大28|澳洲28|重庆时时|一分快三|"
                            r"彩票平台|博彩|赌场|开奖")
_PC28_RE = re.compile(r"(?<![A-Za-z0-9])p\s*[.\-_]?\s*c\s*[.\-_]?\s*2\s*[.\-_]?\s*8(?![0-9])", re.I)
_CN_INSIDE = re.compile(r"内幕")
_CN_RACE   = re.compile(re.escape("赛车"))          # MUST be escaped: legacy tuple was "赛车."
_IN_BET_RE = re.compile(
    r"\bsatta\b|\bmatka\b|\bteen\s*patti\b|\blambi\s*pari\b|\bcolou?r\s*prediction\b|"
    r"\bdream\s*-?11\b|\bfantasy\s*(?:tips|line)\b|\bsession\s*(?:fixing|pakka|report|milega)\b|"
    r"\bfix(?:ing)?\s*report\b|\bbookie\b|\bsure\s*shot\b|\bsureshot\b|\bjodi\b|\bdabba\b|"
    r"\blottery\b|\bsatta\s*bazar\b|\bipl\s*fixing\b", re.I)
_TIPS_FRAME_RE = re.compile(
    r"\binside\s*(?:info|report|news|line|tip|information)\b|\binsider\s*(?:info|tip)\b|"
    r"\bguaranteed\s*\d{2,3}\s*%|\bpakka\s*(?:hai|report|session|line)\b|"
    r"\b\d+\s*/\s*\d+\s*pass\b|\b\d+\s*me\s*se\s*\d+\s*pass\b|"
    r"\bpaid\s*group\b|\bvip\s*(?:group|signal|me)\b|\bfree\s*trial\b|"
    r"\b\d+\s*signal\b|\baccuracy\b", re.I)

_CN_TIPS_RE = re.compile(r"内幕|分享|预测|计划|稳赚|回血|上岸|精准|大神|导师|带你|包赢|必中|走势|"
                         r"实力|信誉|回水|返水|代理|下注")
_CN_AD_AGENCY = re.compile(r"代发|帮伐|专业代|精准代")

# ---- IOCs
_HANDLE_RE = re.compile(r"@[A-Za-z]\w{3,31}")
_PHONE_RE  = re.compile(r"\+\d[\d\s()\-]{7,17}\d")
_TME_RE    = re.compile(r"t\.me/[A-Za-z0-9_+]{4,}")
_WALLET_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})\b")

# ---------------------------------------------------------------- suppressors
_WARN_RE = re.compile(
    r"\b(?:this|it|yeh|ye|that)\s*(?:message\s*)?is\s*(?:a\s*)?(?:scam|fraud|fake|mule)\b"
    r"|\bdo\s*n[o']?t\s*(?:fall|reply|engage|respond|trust|send|share|deal|click)\b"
    r"|\bdon'?t\s*fall\s*for\b|\bdo\s*not\s*engage\b"
    r"|\bbeware\b|\bwarning\b|\bheads?\s*up\b|\bscam\s*(?:alert|handles?|warning)\b"
    r"|\bfraud\s*alert\b|\bmoney\s*mule\b|\bmule\s*(?:recruitment|account|network)"
    r"|\blaunder\w*\b|\byou\s*become\s*the\s*accused\b|\bgot\s*cheated\b|\bfake\s*listings?\b"
    r"|\bthey\s*(?:advertise|advertised|offer|claim|pay|are\s*)\b|\bthese\s*people\b"
    r"|\bthis\s*(?:exact\s*)?(?:message|dm|ad)\s*(?:was|is)\b|\bi\s*got\s*this\b"
    r"|\breported\s*in\s*this\s*group\b|\bposted\s*this\b|\badded\s*me\s*to\b"
    r"|提醒大家|请注意|注意防范|谨防|骗子|诈骗|警惕|派出所", re.I)

_CIVIC_RE = re.compile(
    r"(?<!\d)1930(?!\d)|cybercrime\.gov\.in|rbi\.org\.in|\brbi'?s?\s*circular\b|"
    r"\bfile\s*(?:a\s*)?(?:complaint|fir)\b|\bcyber\s*cell\b|\breport\s*(?:on|at|to)\b", re.I)

_RESEARCH_RE = re.compile(
    r"\bpreprint\b|\bpaper\b|\bdataset\b|\bresearch(?:er|ing|ers)?\b|\bosf\b|\barxiv\b|"
    r"\bwriting\s*a\s*(?:piece|story|article)\b|\bnewsletter\b|\bon\s*background\b|"
    r"\b(?:i\s*am|i'?m)\s*a\s*(?:reporter|journalist|researcher|student)\b|"
    r"\breporter\s*with\b|\bjournalist\b|\bfor\s*a\s*(?:piece|story)\b|"
    r"\bheadline\s*finding\b|\bcomments\s*welcome\b|\bwilling\s*to\s*talk\b|"
    r"\bname\s*withheld\b|\bthe\s*recruiters\b|\brecruitment\s*ads\b|\bnetworks\s*(?:and|in)\b|"
    r"\bdocumentary\b|纪录片", re.I)

_ASK_RE = re.compile(
    r"\bis\s*this\s*(?:legit|real|safe|genuine|a\s*scam|scam)\b|\blegit\s*or\s*scam\b|"
    r"\bshould\s*i\b|\bstupid\s*question\b|\banyone\s*know\b|\bkisi\s*ne\b|"
    r"\bsounds?\s*too\s*good\b|\bhas\s*anyone\b|\bcan\s*someone\b|\bany\s*idea\b|"
    r"\bkaise\b|\bkitne\s*din\b|\bwhere\s*can\s*i\b|哪里可以|坏了|有人知道", re.I)

_COMPLIANCE_RE = re.compile(
    r"\bfiu[\s-]?registered\b|\btds\b|\b194s\b|\b115bbh\b|\bitr[\s-]?\d\b|\bschedule\s*vda\b|"
    r"\bvda\b|\bgst\b|\bbinance\s*p2p\b|\bescrow\s*only\b|\bkyc\s*re-?verification\b|"
    r"\bcompletion\s*rate\b|\bon\s*the\s*platform\b|\bset-?off\b|\bcost\s*of\s*acquisition\b|"
    r"\bfy\d{2}\b|\bcoindcx\b|\bmudrex\b|\bwazirx\b|\bsupport\s*notice\b|\bhelpdesk\b", re.I)

_PAYOPS_RE = re.compile(
    r"\bt\s*\+\s*[012]\b|\bnodal\b|\bmids?\b|\bnpci\b|\bbin\b|\bticket\s*#?\d+\b|"
    r"\baggregator\b|\bstaging\b|\bintegrat\w*\b|\bapi\b|\brazorpay\b|\bphonepe\b|\bpaytm\s*(?:support|team)\b|"
    r"\breconciliation\b|\bsettlements?\s*team\b|\bplatform\s*fee\b|\bcollect\s*requests?\b|"
    r"\bupi\s*intent\b|\bcollision\b|\bfailing\b|\bstuck\s*since\b|\bcapped\b", re.I)

_RENTAL_HOUSING_RE = re.compile(
    r"\b\d\s*bhk\b|\bflat\b|\bapartment\b|\broom\s*on\s*rent\b|\bpg\b|\bsemi[\s-]?furnished\b|"
    r"\bdeposit\b[^.\n]{0,30}\bmonth\b|\bbrokerage\b|\btenant\b|\bowner\s*does\s*not\b|"
    r"\bcovered\s*parking\b|\bshifting\b|\ball\s*inclusive\b", re.I)

# ---------------------------------------------------------------- families
STRONG_FAMILIES = {"RATE", "ACCOUNT", "MECHANIC", "COUNTERFEIT", "GAMBLING"}

@dataclass
class Signal:
    name: str; weight: int; family: str; detail: str

@dataclass
class Verdict:
    score: int; tier: str; signals: list; iocs: dict = field(default_factory=dict)
    families: set = field(default_factory=set)
    def names(self): return {s.name for s in self.signals}


def _score_text(text: str, mkt: float, allow_rate: bool = True) -> list:
    """Content signals for one span of text (used for both full and carrier)."""
    t = normalize(text)
    low = t.lower()
    sig = []
    A = sig.append

    # ---- RATE family
    fx_msg = bool(_FX_CTX.search(t))
    rates = extract_rates(t, mkt) if (allow_rate and not fx_msg) else []
    if rates:
        vals = sorted({r[0] for r in rates})
        top = max(vals)
        prem = top / mkt - 1
        A(Signal("anomalous_inr_rate", 25 if prem < 0.30 else 30, "RATE",
                 f"quotes ₹{top:.0f}/unit vs ~₹{mkt:.0f} market ({prem:+.0%}); "
                 f"forms={sorted({r[2] for r in rates})}"))
        if len(vals) >= 3:
            A(Signal("tiered_price_menu", 20, "RATE",
                     f"risk-tiered price sheet: {vals}"))
    if _ABOVE_MKT_RE.search(t):
        A(Signal("above_market_admission", 25, "RATE",
                 "openly states the quote sits N rupees above market — a premium "
                 "paid for risk, which is the laundering fee itself"))
    tiers = {x for x in _FUND_TIERS if x in low}
    if len(tiers) >= 2:
        A(Signal("tiered_fund_menu", 20, "RATE", f"fund-tier menu {sorted(tiers)}"))
    if allow_rate and not fx_msg:
        ap = {m.group(1) for m in _ACCT_TYPE_PRICE_RE.finditer(t)
              if _inband(float(m.group(1)), mkt)}
        if len(ap) >= 2:
            A(Signal("account_type_price_sheet", 25, "RATE",
                     f"prices accounts by type/risk: {sorted(ap)}"))

    # ---- ACCOUNT family
    if _ACCOUNT_RENT_RE.search(t):
        A(Signal("account_rental_offer", 30, "ACCOUNT",
                 "bank account bound to a rent/hire/sale verb in the same clause"))
    if _ACCOUNT_SOURCING_RE.search(t):
        A(Signal("account_sourcing_demand", 20, "ACCOUNT",
                 "solicits third-party account holders (chahiye/wanted/holders/BYO bank)"))
    if _ACCOUNT_USE_RE.search(t):
        A(Signal("account_use_solicitation", 25, "ACCOUNT",
                 "'your account, our business' — asks recruit to lend account use"))
    if _PER_ACCOUNT_PRICE_RE.search(t):
        A(Signal("per_account_pricing", 25, "ACCOUNT",
                 "prices accounts per unit (per account = ₹N / N k advance)"))
    kit = {m.group(0).lower() for m in _KIT_ITEM_RE.finditer(t)}
    if len(kit) >= 2 and _HANDOVER_RE.search(t):
        A(Signal("banking_kit_handover", 25, "ACCOUNT",
                 f"credential kit + transfer verb: {sorted(kit)}"))
    elif len(kit) >= 3:
        A(Signal("credential_kit_enumeration", 10, "WEAK",
                 f"enumerates {len(kit)} banking credentials: {sorted(kit)}"))
    if _FRESH_ACCT_RE.search(t):
        A(Signal("fresh_clean_account_demand", 10, "ACCOUNT",
                 "requires unburnt / clean-history accounts"))

    # ---- MECHANIC family
    if _CASHOUT_RE.search(t):
        A(Signal("cashout_courier_mechanic", 30, "MECHANIC",
                 "instructs recruit to withdraw incoming funds and hand cash over"))
    if _FREEZE_COMP_RE.search(t):
        A(Signal("freeze_compensation_offer", 30, "MECHANIC",
                 "indemnifies account freezes — concedes funds are traceable proceeds"))
    if _SOF_WAIVER_RE.search(t):
        A(Signal("source_of_funds_waiver", 30, "MECHANIC",
                 "explicitly refuses to check source of funds"))
    if _PREDICATE_RE.search(t):
        A(Signal("illicit_predicate_settlement", 20, "MECHANIC",
                 "names the predicate offence (overseas gaming volume / local rails)"))
    if _PREPAID_RE.search(t):
        A(Signal("prepaid_demand", 10, "MECHANIC", "demands USDT deposit up front"))
    if _CASH_PICKUP_RE.search(t):
        A(Signal("cash_pickup_leg", 20, "MECHANIC",
                 "offers physical cash pickup / denies hawala / 'never touch cash'"))
    if _PAYIN_RECRUIT_RE.search(t):
        A(Signal("payin_payout_recruitment", 20, "MECHANIC",
                 "recruits payin/payout merchant capacity"))

    # ---- WEAK / corroborating only
    if _COMMISSION_RE.search(t):
        A(Signal("commission_share_terms", 10, "WEAK", "per-transaction commission split"))
    if _FAST_SETTLE_RE.search(t):
        A(Signal("fast_settlement_window", 5, "WEAK", "sub-hour / same-day settlement promise"))
    if _THROUGHPUT_RE.search(t):
        A(Signal("throughput_limit_requirement", 5, "WEAK", "daily lakh-scale limit requirement"))
    if _HOMEJOB_RE.search(t):
        A(Signal("earn_from_home_job_frame", 10, "WEAK", "part-time / ghar-baithe job framing"))
    if _SUBAGENT_RE.search(t):
        A(Signal("sub_agent_recruitment", 10, "WEAK", "recruits sub-agents / collection partners"))
    if _RECRUIT_PHRASE_RE.search(t):
        A(Signal("mule_template_phrase", 15, "WEAK", "INR-work template stock phrase"))
    if (_UPI_RE.search(t) or _IMPS_RE.search(t)) and _ASSET_RE.search(t):
        A(Signal("upi_usdt_bridge", 5, "WEAK", "UPI/IMPS + stablecoin co-occurrence"))
    _io = extract_iocs(text)
    _fan = sum(len(v) for v in _io.values())
    if _fan >= 3:
        A(Signal("contact_fanout", 5, "WEAK",
                 f"{_fan} contact points (redundant handles = ban-resilience)"))
    if _CN_AD_AGENCY.search(t):
        A(Signal("cn_ad_agency_marker", 10, "WEAK", "posted via CN paid ad-blasting service"))

    # ---- COUNTERFEIT family
    en_hits = sum(1 for r in _EN_FAKE_RE if r.search(t))
    cn_noun = bool(_CN_FAKE_NOUN.search(t))
    cn_offer = bool(_CN_OFFER.search(t))
    delivery = bool(_DELIVERY_RE.search(t))
    if (cn_noun and (cn_offer or delivery)) or en_hits >= 3:
        A(Signal("counterfeit_note_offer", 45, "COUNTERFEIT",
                 f"counterfeit-note OFFER (cn_noun={cn_noun}, cn_offer={cn_offer}, en={en_hits})"))
        if delivery:
            A(Signal("counterfeit_delivery_channel", 15, "COUNTERFEIT",
                     "courier / COD / 面交 fulfilment offered"))
    elif cn_noun or en_hits >= 1:
        A(Signal("counterfeit_note_mention", 10, "WEAK",
                 f"counterfeit vocabulary without an offer (cn={cn_noun}, en={en_hits})"))
    # NOTE: 验钞机/点钞机 alone contributes ZERO. It is a legal retail appliance.

    # ---- GAMBLING family
    cn_strong = bool(_CN_BET_STRONG.search(t)) or bool(_PC28_RE.search(t))
    in_hits = len({m.group(0).lower() for m in _IN_BET_RE.finditer(t)})
    tips = bool(_TIPS_FRAME_RE.search(t)) or bool(_CN_TIPS_RE.search(t))
    # 赛车 alone = motorsport; only a betting term when a strong marker co-occurs.
    race_bet = bool(_CN_RACE.search(t)) and cn_strong
    if (cn_strong or in_hits >= 2 or race_bet) and tips:
        A(Signal("gambling_tips_ad", 40, "GAMBLING",
                 f"illegal betting tips/insider ad (cn={cn_strong}, in={in_hits}, tips={tips})"))
    elif cn_strong or in_hits >= 1:
        A(Signal("gambling_term_mention", 10, "WEAK",
                 f"betting vocabulary without tips framing (cn={cn_strong}, in={in_hits})"))
    # NOTE: 内幕 alone contributes ZERO (= 'inside story'); 赛车 is re.escape()d.

    return sig


def extract_iocs(text: str) -> dict:
    u = lambda s: list(dict.fromkeys(s))
    return {"handles": u(_HANDLE_RE.findall(text)), "phones": u(_PHONE_RE.findall(text)),
            "channels": u(_TME_RE.findall(text)), "wallets": u(_WALLET_RE.findall(text))}


def _suppressors(carrier: str, quoted: str, full: str) -> list:
    """Suppressors are computed on the CARRIER text only — a scammer cannot
    earn them by pasting warning language inside the quoted block."""
    c = normalize(carrier); sig = []; A = sig.append
    warn = len(set(m.group(0).lower() for m in _WARN_RE.finditer(c)))
    civic = len(set(m.group(0).lower() for m in _CIVIC_RE.finditer(c)))
    res = len(set(m.group(0).lower() for m in _RESEARCH_RE.finditer(c)))
    ask = len(set(m.group(0).lower() for m in _ASK_RE.finditer(c)))
    if quoted.strip():
        A(Signal("quoted_ad_span", -25, "SUPPRESS",
                 f"{len(quoted)} chars attributed to a third party inside quotes"))
    if warn >= 2:
        A(Signal("victim_warning_frame", -30, "SUPPRESS", f"{warn} warning/advisory markers"))
    elif warn == 1:
        A(Signal("victim_warning_frame", -15, "SUPPRESS", "1 warning marker"))
    if civic >= 1:
        A(Signal("civic_reporting_reference", -25, "SUPPRESS",
                 "cites 1930 / cybercrime.gov.in / RBI — the reporting channel, not the ad"))
    if res >= 2:
        A(Signal("research_journalism_frame", -30, "SUPPRESS", f"{res} research/press markers"))
    elif res == 1:
        A(Signal("research_journalism_frame", -15, "SUPPRESS", "1 research/press marker"))
    if ask >= 1:
        A(Signal("interrogative_victim_query", -20, "SUPPRESS",
                 "asks whether it is a scam / help-seeking question"))
    if _COMPLIANCE_RE.search(c):
        A(Signal("regulated_compliance_context", -20, "SUPPRESS",
                 "FIU/TDS/on-platform-escrow/exchange-notice context"))
    if _PAYOPS_RE.search(c):
        A(Signal("payment_ops_context", -20, "SUPPRESS",
                 "payment-gateway engineering/ops context (T+N, nodal, MID, NPCI, ticket)"))
    if _FX_CTX.search(c):
        A(Signal("foreign_remittance_context", -25, "SUPPRESS",
                 "GBP/EUR/remittance context — INR quote is a forex rate, not a premium"))
    if _RENTAL_HOUSING_RE.search(c) and not _ACCOUNT_RENT_RE.search(c):
        A(Signal("housing_rental_context", -20, "SUPPRESS",
                 "flat/room rental listing; 'on rent' has no account object"))
    return sig


def classify(text: str, market_rate: float = MARKET_USDT_INR) -> Verdict:
    carrier, quoted = split_quotes(text)
    full_sig = _score_text(text, market_rate)
    car_sig = _score_text(carrier, market_rate)
    sup = _suppressors(carrier, quoted, text)

    signals = full_sig + sup
    score = max(0, sum(s.weight for s in signals))
    fams = {s.family for s in full_sig} & STRONG_FAMILIES
    car_score = max(0, sum(s.weight for s in car_sig) + sum(s.weight for s in sup))
    car_fams = {s.family for s in car_sig} & STRONG_FAMILIES

    if score >= 60: tier = "CONFIRMED_PATTERN"
    elif score >= 35: tier = "LIKELY_SCAM"
    elif score >= 15: tier = "WATCH"
    else: tier = "CLEAN"

    # --- CONFIRMED gate (deletion) -------------------------------------
    gate_notes = []
    strong_full = [s for s in full_sig if s.family in STRONG_FAMILIES]
    strong_car = [s for s in car_sig if s.family in STRONG_FAMILIES]
    n_ioc = sum(len(v) for v in extract_iocs(text).values())
    if tier == "CONFIRMED_PATTERN":
        if len(strong_full) < 2:
            tier = "LIKELY_SCAM"; gate_notes.append("gate: <2 strong signals")
        elif n_ioc < 1:
            tier = "LIKELY_SCAM"; gate_notes.append("gate: no contact IOC (no reachable advertiser)")
        elif any(s.family == "SUPPRESS" for s in sup):
            tier = "LIKELY_SCAM"; gate_notes.append("gate: suppressor present")
        elif car_score < 60 or len(strong_car) < 2:
            tier = "LIKELY_SCAM"
            gate_notes.append("gate: carrier text alone does not confirm (quoted content)")
    # --- hard cap for warn/report/ask framing --------------------------
    hard = {"victim_warning_frame", "civic_reporting_reference",
            "research_journalism_frame", "interrogative_victim_query"}
    fired = {s.name for s in sup}
    car_content = max(0, sum(s.weight for s in car_sig))
    # The cap is conditioned on the CARRIER content, not just marker count.
    # Without this, a scammer appends "beware of scams, call 1930" to their own
    # unquoted ad and buys a free pass. Verified bypass; do not relax.
    if tier in ("LIKELY_SCAM", "CONFIRMED_PATTERN") and (
            (len(fired & hard) >= 2 and car_content < 60)
            or (len(fired & hard) >= 1 and car_content < 35)):
        tier = "WATCH"
        gate_notes.append(f"cap: warn/report/ask framing (markers={sorted(fired & hard)}, "
                          f"carrier_content={car_content}) -> WATCH")

    v = Verdict(score=score, tier=tier, signals=signals,
                iocs=extract_iocs(text) if (score >= 10 or sup) else {}, families=fams)
    v.notes = gate_notes
    v.car_score = car_score
    return v
