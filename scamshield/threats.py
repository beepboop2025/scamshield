"""High-precision Telegram threat-family detection beyond money mules.

The mature detector in :mod:`scamshield.detector` remains responsible for
money-mule, laundering-rate, counterfeit-note, and gambling-ad signals.  This
module adds independent, conjunctive rules for illicit-market and common scam
families.  A subject word is never enough: a finding also needs observable
transaction, fulfilment, credential, or coercion behaviour.

The output describes a *message pattern*.  It never declares that a person,
channel, product, or payment is criminal, and it deliberately caps sensitive
human-trafficking and wildlife leads below an automatic-confirmation claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .detector import ATTRIBUTION_SUPPRESSORS, Verdict, extract_iocs, normalize

SCHEMA_VERSION = "scamshield-threat-assessment/v1"
RULESET_VERSION = "2026-08-08.1"
MAX_MATCHES_PER_CLASS = 8

TIER_RANK = {
    "CLEAN": 0,
    "WATCH": 1,
    "LIKELY_SCAM": 2,
    "CONFIRMED_PATTERN": 3,
}


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# Shared behavioural evidence. These expressions intentionally describe calls
# to action and transaction mechanics rather than generic topic vocabulary.
_OFFER = _rx(
    r"\b(?:for\s+sale|stock\s+(?:ready|available)|available\s+(?:now|today)|"
    r"buy\s+now|place\s+(?:an?\s+)?order|taking\s+orders?|supplier|vendor|"
    r"wholesale|bulk\s+order|price\s+list|rate\s+card|dm\s+(?:me|to\s+order)|"
    r"contact\s+(?:me|us|now)|message\s+(?:me|us)|inbox\s+(?:me|us))\b|"
    r"\b(?:maal|माल)\s+(?:available|ready|chahiye)\b|"
    r"出售|供应|供货|批发|现货|下单|价格表|联系(?:我|我们)?|私聊"
)
_PAYMENT = _rx(
    r"(?<![a-z])(?:usdt|usdc|btc|bitcoin|monero|xmr|crypto|upi|imps|cash|cod|"
    r"escrow)(?![a-z])|₹\s*\d|\b(?:rs\.?|inr|usd)\s*\d|\b\d+(?:\.\d+)?\s*%\b|"
    r"(?:付款|支付|比特币|泰达币|货到付款)"
)
_FULFILMENT = _rx(
    r"\b(?:door[\s-]?to[\s-]?door|home\s+delivery|same[\s-]?day\s+delivery|"
    r"courier|shipping|ship\s+(?:worldwide|anywhere)|drop\s+location|dead\s+drop|"
    r"cash\s+on\s+delivery|pan[\s-]?india|meet[\s-]?up|pickup\s+point|parcel)\b|"
    r"快递|发货|同城|面交|到付|送货上门"
)
_CONCEALMENT = _rx(
    r"\b(?:stealth\s+(?:pack|shipping)|discreet\s+(?:pack|shipping)|vacuum[\s-]?seal|"
    r"double[\s-]?pack|no\s+smell|customs[\s-]?proof|x[\s-]?ray[\s-]?proof|"
    r"hidden\s+compartment|no\s+label|burner\s+(?:account|phone)|no\s+questions)\b|"
    r"隐蔽包装|无味包装|躲避海关|匿名发货"
)
_UPFRONT_PAYMENT = _rx(
    r"\b(?:prepaid|advance\s+(?:fee|deposit|payment)|security\s+deposit|"
    r"registration\s+fee|processing\s+fee|release\s+fee|unlock\s+fee|"
    r"top[\s-]?up|recharge|add\s+funds?|pay\s+first|deposit\s+first|"
    r"complete\s+the\s+payment)\b|先付款|充值|垫付|保证金"
)
_RETURN_PROMISE = _rx(
    r"\b(?:guaranteed\s+(?:profit|return|income)|risk[\s-]?free\s+(?:profit|return)|"
    r"double\s+(?:your\s+)?money|triple\s+(?:your\s+)?money|fixed\s+returns?|"
    r"\d{2,4}\s*%\s+(?:return|profit|roi)|daily\s+(?:return|profit|income)|"
    r"sure[\s-]?shot\s+profit)\b|稳赚|保本高收益|保证收益"
)
_CREDENTIAL_ACTION = _rx(
    r"\b(?:share|send|enter|verify|confirm|tell\s+me)\b[^.!?\n]{0,35}\b(?:otp|pin|"
    r"cvv|password|seed\s+phrase|recovery\s+phrase|screen\s+share)\b|"
    r"\b(?:install|download)\b[^.!?\n]{0,30}\b(?:anydesk|teamviewer|quicksupport|"
    r"remote\s+app|apk)\b|验证码|密码|助记词|屏幕共享|远程控制"
)
_LINK_ACTION = _rx(
    r"\b(?:click|open|visit|login|sign\s+in|verify)\b[^\n]{0,50}"
    r"(?:https?://|www\.|[a-z0-9-]+\.(?:com|in|net|org|top|xyz|vip))"
)


@dataclass(frozen=True)
class ThreatRule:
    id: str
    family: str
    label: str
    subject: re.Pattern[str]
    contexts: tuple[tuple[str, re.Pattern[str]], ...]
    likely_requires: tuple[frozenset[str], ...]
    confirmed_requires: tuple[frozenset[str], ...] = ()
    tier_cap: str = "CONFIRMED_PATTERN"
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ThreatFinding:
    rule_id: str
    family: str
    label: str
    tier: str
    score: int
    evidence_classes: tuple[str, ...]
    matched_terms: Mapping[str, tuple[str, ...]]
    attribution_markers: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "family": self.family,
            "label": self.label,
            "tier": self.tier,
            "score": self.score,
            "evidence_classes": list(self.evidence_classes),
            "matched_terms": {
                key: list(values) for key, values in self.matched_terms.items()
            },
            "attribution_markers": list(self.attribution_markers),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ThreatAssessment:
    tier: str
    score: int
    findings: tuple[ThreatFinding, ...]
    ruleset_version: str = RULESET_VERSION

    @property
    def signal_names(self) -> tuple[str, ...]:
        return tuple(item.rule_id for item in self.findings)

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.family for item in self.findings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "ruleset_version": self.ruleset_version,
            "tier": self.tier,
            "score": self.score,
            "families": list(self.families),
            "findings": [item.to_dict() for item in self.findings],
            "limitations": [
                "Findings describe message patterns, not guilt or verified illegality.",
                "A human reviewer must inspect context before moderation, reporting, or publication.",
                "A message classifier cannot establish the source of specific funds.",
            ],
        }


_NARCOTICS = _rx(
    r"\b(?:meth(?:amphetamine)?|crystal\s+meth|fentanyl|heroin|cocaine|crack\s+cocaine|"
    r"mdma|ecstasy|ketamine|lsd|opium|hashish|charas|ganja|cannabis|marijuana|"
    r"yaba|ice\s+drug|nitazene|mephedrone|mcat|4[\s-]?mmc|alprazolam|tramadol)\b|"
    r"冰毒|海洛因|可卡因|芬太尼|摇头丸|氯胺酮|鸦片|大麻|麻古"
)
_WILDLIFE = _rx(
    r"\b(?:rhino\s+horn|pangolin\s+(?:scale|scales|meat)|elephant\s+ivory|raw\s+ivory|"
    r"tiger\s+(?:bone|skin|tooth|teeth|claw|wine)|leopard\s+skin|bear\s+bile|"
    r"shahtoosh|red\s+sanders?|rosewood\s+logs?|live\s+pangolin)\b|"
    r"犀牛角|穿山甲(?:鳞片|肉)|象牙|虎骨|虎皮|熊胆|红木走私"
)
_WILDLIFE_ILLEGAL = _rx(
    r"\b(?:no\s+cites|without\s+cites|no\s+permit|without\s+permit|wild[\s-]?caught|"
    r"poached|smuggled|protected\s+species|customs\s+clearance\s+not\s+needed)\b|"
    r"无证|野生捕获|走私|保护动物"
)
_WEAPONS = _rx(
    r"\b(?:glock|ak[\s-]?(?:47|56)|pistol|revolver|handgun|rifle|firearm|"
    r"country[\s-]?made\s+(?:gun|pistol)|katta|ammunition|live\s+rounds?|"
    r"detonator|explosive)\b|手枪|步枪|枪支|弹药|雷管"
)
_WEAPONS_ILLEGAL = _rx(
    r"\b(?:no\s+licen[cs]e|without\s+licen[cs]e|no\s+papers|without\s+papers|"
    r"unregistered|untraceable|serial\s+(?:removed|scratched)|ghost\s+gun|"
    r"country[\s-]?made|desi\s+katta)\b|无证枪|黑枪|无序列号"
)
_FORGED_DOCUMENT = _rx(
    r"\b(?:fake|forged|duplicate|counterfeit|editable)\s+(?:passport|visa|aadhaar|"
    r"aadhar|pan\s+card|driving\s+licen[cs]e|degree|marksheet|bank\s+statement|"
    r"salary\s+slip|police\s+clearance|id\s+card)|"
    r"(?:passport|visa|aadhaar|aadhar|pan\s+card|driving\s+licen[cs]e)\s+maker\b|"
    r"假护照|假签证|伪造证件|假身份证|代做流水"
)
_STOLEN_DATA = _rx(
    r"\b(?:cvv\s+dumps?|card\s+dumps?|fullz|fresh\s+cc|bank\s+logs?|"
    r"stealer\s+logs?|session\s+cookies?|otp\s+bot|phishing\s+kit|"
    r"sim[\s-]?swap\s+service|rdp\s+access|corporate\s+email\s+access|"
    r"verified\s+bank\s+login)\b|银行卡料|盗刷料|网银账号|钓鱼套件|验证码机器人"
)
_TASK_SCAM = _rx(
    r"\b(?:rating|review|like|subscribe|hotel\s+review|restaurant\s+review|"
    r"merchant|product|order)\s+(?:task|tasks|job|work)|"
    r"(?:task|任务)\s*(?:optimization|boosting|commission|返佣)|"
    r"order\s+boosting|刷单|点赞任务|好评任务"
)
_INVESTMENT_SCAM = _rx(
    r"\b(?:crypto|forex|stock|options?|binary|trading|investment|mining)\b"
    r"[^.!?\n]{0,65}\b(?:guaranteed|assured|fixed|risk[\s-]?free|double|triple|"
    r"daily\s+profit|sure[\s-]?shot)\b|"
    r"\b(?:guaranteed|assured|fixed|risk[\s-]?free)\b[^.!?\n]{0,65}"
    r"\b(?:returns?|profit|roi|income)\b|稳赚投资|保本投资|带单稳赚"
)
_IMPERSONATION = _rx(
    r"\b(?:digital\s+arrest|parcel\s+(?:contains|found\s+with)\s+(?:drugs|narcotics)|"
    r"fedex\s+(?:customs|parcel)|customs\s+(?:officer|case|seizure)|"
    r"police\s+video\s+call|cbi\s+(?:case|officer)|ed\s+(?:case|officer)|"
    r"electricity\s+(?:will\s+be\s+)?disconnected|kyc\s+(?:expired|suspended)|"
    r"bank\s+account\s+(?:blocked|suspended)|sim\s+(?:will\s+be\s+)?blocked)\b|"
    r"数字逮捕|冒充公安|冒充客服|快递涉毒|账户冻结"
)
_ADVANCE_FEE = _rx(
    r"\b(?:lottery|prize|inheritance|loan|job|visa|parcel|refund|recovery|"
    r"compensation)\b[^.!?\n]{0,70}\b(?:won|approved|selected|released|claim|"
    r"guaranteed|pending|recover)\b|"
    r"\b(?:recover\s+(?:lost|stolen)\s+(?:crypto|money)|fund\s+recovery\s+agent)\b|"
    r"中奖|退款客服|资金追回|贷款已批准"
)
_EXPLOITATIVE_RECRUITMENT = _rx(
    r"\b(?:casino|customer\s+service|online\s+marketing|typing|call\s+centre|"
    r"call\s+center)\s+job\b[^.!?\n]{0,80}\b(?:cambodia|myanmar|laos|"
    r"myawaddy|shwe\s+kokko|sihanoukville|golden\s+triangle)\b|"
    r"柬埔寨高薪|缅甸高薪|园区招聘|网投公司招聘"
)
_COERCION = _rx(
    r"\b(?:passport\s+(?:kept|held|retained|deposit|required)|cannot\s+leave|"
    r"not\s+allowed\s+to\s+leave|debt\s+(?:bond|repayment)|border\s+crossing|"
    r"travel\s+(?:and\s+)?visa\s+(?:arranged|provided)|ticket\s+(?:arranged|provided)|"
    r"no\s+experience\s+passport\s+required)\b|扣押护照|不能离开|偷渡|债务劳动|包机票签证"
)


RULES: tuple[ThreatRule, ...] = (
    ThreatRule(
        id="narcotics_trade_offer", family="NARCOTICS",
        label="Possible narcotics-market solicitation",
        subject=_NARCOTICS,
        contexts=(("offer", _OFFER), ("payment", _PAYMENT),
                  ("fulfilment", _FULFILMENT), ("concealment", _CONCEALMENT)),
        likely_requires=(frozenset({"offer", "contact"}),
                         frozenset({"offer", "fulfilment"}),
                         frozenset({"offer", "payment"})),
        confirmed_requires=(frozenset({"offer", "contact", "fulfilment", "payment"}),
                            frozenset({"offer", "contact", "concealment"})),
        limitations=("Drug vocabulary plus sale mechanics is a triage signal, not laboratory or legal proof.",),
    ),
    ThreatRule(
        id="wildlife_trade_offer", family="WILDLIFE",
        label="Possible illegal-wildlife-market solicitation",
        subject=_WILDLIFE,
        contexts=(("offer", _OFFER), ("payment", _PAYMENT),
                  ("fulfilment", _FULFILMENT), ("concealment", _CONCEALMENT),
                  ("illegality", _WILDLIFE_ILLEGAL)),
        likely_requires=(frozenset({"offer", "illegality"}),
                         frozenset({"offer", "contact", "fulfilment"}),
                         frozenset({"offer", "concealment"})),
        tier_cap="LIKELY_SCAM",
        limitations=("Legality can depend on species, jurisdiction, permits, provenance, and exemptions.",),
    ),
    ThreatRule(
        id="weapons_trade_offer", family="WEAPONS",
        label="Possible illicit-weapons-market solicitation",
        subject=_WEAPONS,
        contexts=(("offer", _OFFER), ("payment", _PAYMENT),
                  ("fulfilment", _FULFILMENT), ("illegality", _WEAPONS_ILLEGAL)),
        likely_requires=(frozenset({"offer", "illegality"}),
                         frozenset({"offer", "contact", "fulfilment", "payment"})),
        confirmed_requires=(frozenset({"offer", "contact", "fulfilment", "illegality"}),),
        limitations=("Weapons law and licensing vary by jurisdiction; human review is mandatory.",),
    ),
    ThreatRule(
        id="forged_document_offer", family="FORGERY",
        label="Possible forged-document service",
        subject=_FORGED_DOCUMENT,
        contexts=(("offer", _OFFER), ("payment", _PAYMENT),
                  ("fulfilment", _FULFILMENT)),
        likely_requires=(frozenset({"offer", "contact"}),
                         frozenset({"offer", "payment"})),
        confirmed_requires=(frozenset({"offer", "contact", "payment", "fulfilment"}),),
        limitations=("The detector cannot inspect the document or establish whether it is authentic.",),
    ),
    ThreatRule(
        id="stolen_data_offer", family="CYBERCRIME",
        label="Possible stolen-data or access-market solicitation",
        subject=_STOLEN_DATA,
        contexts=(("offer", _OFFER), ("payment", _PAYMENT),
                  ("fulfilment", _FULFILMENT)),
        likely_requires=(frozenset({"offer", "contact"}),
                         frozenset({"offer", "payment"})),
        confirmed_requires=(frozenset({"offer", "contact", "payment"}),),
        limitations=("Terminology can also occur in security research; attribution framing is therefore checked.",),
    ),
    ThreatRule(
        id="task_scam_pattern", family="FRAUD",
        label="Task/review scam pattern",
        subject=_TASK_SCAM,
        contexts=(("upfront_payment", _UPFRONT_PAYMENT),
                  ("return_promise", _RETURN_PROMISE), ("payment", _PAYMENT)),
        likely_requires=(frozenset({"upfront_payment", "return_promise"}),
                         frozenset({"upfront_payment", "contact"})),
        confirmed_requires=(frozenset({"upfront_payment", "return_promise", "contact", "payment"}),),
        limitations=("Legitimate gig platforms exist; never infer fraud from task vocabulary alone.",),
    ),
    ThreatRule(
        id="investment_scam_pattern", family="FRAUD",
        label="Guaranteed-return investment scam pattern",
        subject=_INVESTMENT_SCAM,
        contexts=(("return_promise", _RETURN_PROMISE),
                  ("upfront_payment", _UPFRONT_PAYMENT), ("payment", _PAYMENT)),
        likely_requires=(frozenset({"return_promise", "contact", "payment"}),
                         frozenset({"return_promise", "upfront_payment"})),
        confirmed_requires=(frozenset({"return_promise", "upfront_payment", "contact", "payment"}),),
        limitations=("This matches impossible or highly promotional claims; it is not investment advice.",),
    ),
    ThreatRule(
        id="impersonation_phishing_pattern", family="FRAUD",
        label="Authority/courier impersonation phishing pattern",
        subject=_IMPERSONATION,
        contexts=(("credential_action", _CREDENTIAL_ACTION),
                  ("link_action", _LINK_ACTION), ("upfront_payment", _UPFRONT_PAYMENT),
                  ("payment", _PAYMENT)),
        likely_requires=(frozenset({"credential_action"}), frozenset({"link_action"}),
                         frozenset({"upfront_payment", "payment"})),
        confirmed_requires=(frozenset({"credential_action", "link_action", "contact"}),),
        limitations=("Official notices can use similar language; verify through an independently obtained official channel.",),
    ),
    ThreatRule(
        id="advance_fee_scam_pattern", family="FRAUD",
        label="Advance-fee or recovery scam pattern",
        subject=_ADVANCE_FEE,
        contexts=(("upfront_payment", _UPFRONT_PAYMENT),
                  ("payment", _PAYMENT), ("link_action", _LINK_ACTION)),
        likely_requires=(frozenset({"upfront_payment", "contact"}),
                         frozenset({"upfront_payment", "link_action"})),
        confirmed_requires=(frozenset({"upfront_payment", "contact", "payment"}),),
        limitations=("A fee request must be verified independently; the message alone cannot prove fraudulent intent.",),
    ),
    ThreatRule(
        id="forced_labour_recruitment_risk", family="EXPLOITATION",
        label="Possible scam-compound forced-labour recruitment risk",
        subject=_EXPLOITATIVE_RECRUITMENT,
        contexts=(("coercion", _COERCION), ("offer", _OFFER),
                  ("payment", _PAYMENT), ("fulfilment", _FULFILMENT)),
        likely_requires=(frozenset({"coercion", "contact"}),
                         frozenset({"coercion", "offer"})),
        tier_cap="LIKELY_SCAM",
        limitations=("Treat as a safeguarding lead: do not contact or confront a suspected recruiter.",),
    ),
)


def _hits(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
    values: list[str] = []
    for match in pattern.finditer(text):
        value = " ".join(match.group(0).split())[:160]
        if value and value.casefold() not in {item.casefold() for item in values}:
            values.append(value)
        if len(values) >= MAX_MATCHES_PER_CLASS:
            break
    return tuple(values)


def _requirements_met(
    evidence: set[str], alternatives: Sequence[frozenset[str]],
) -> bool:
    return any(required <= evidence for required in alternatives)


def _tier_for(rule: ThreatRule, evidence: set[str]) -> str:
    if rule.confirmed_requires and _requirements_met(evidence, rule.confirmed_requires):
        tier = "CONFIRMED_PATTERN"
    elif _requirements_met(evidence, rule.likely_requires):
        tier = "LIKELY_SCAM"
    else:
        tier = "WATCH"
    if TIER_RANK[tier] > TIER_RANK[rule.tier_cap]:
        return rule.tier_cap
    return tier


def _score(tier: str, evidence_count: int) -> int:
    floor = {"WATCH": 15, "LIKELY_SCAM": 35, "CONFIRMED_PATTERN": 60}[tier]
    return min(85, floor + max(0, evidence_count - 2) * 5)


class ThreatEngine:
    """Evaluate one message against bounded, locally versioned threat rules."""

    def __init__(self, rules: Sequence[ThreatRule] = RULES):
        self.rules = tuple(rules)
        ids = [item.id for item in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate threat rule id")

    def assess(self, text: str, base_verdict: Verdict) -> ThreatAssessment:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        normalized = normalize(text)
        iocs = extract_iocs(text)
        has_contact = any(iocs.values())
        attribution = tuple(sorted(base_verdict.names() & ATTRIBUTION_SUPPRESSORS))
        findings: list[ThreatFinding] = []

        for rule in self.rules:
            subject_hits = _hits(rule.subject, normalized)
            if not subject_hits:
                continue
            matched: dict[str, tuple[str, ...]] = {"subject": subject_hits}
            evidence = {"subject"}
            for evidence_class, pattern in rule.contexts:
                values = _hits(pattern, normalized)
                if values:
                    evidence.add(evidence_class)
                    matched[evidence_class] = values
            if has_contact:
                evidence.add("contact")

            # Topic-only mentions are not findings. A caller must be able to
            # point to at least one observable behaviour beyond the noun.
            if len(evidence) < 2:
                continue
            tier = _tier_for(rule, evidence)

            # Warning, research, and victim-report frames are meaningful only
            # when the message does not still contain a complete transactional
            # call to action. This prevents an advertiser from buying a bypass
            # by appending the word "police" or "warning".
            transactional = {"offer", "contact"} <= evidence and bool(
                evidence & {"payment", "fulfilment", "concealment", "credential_action"}
            )
            if attribution and not transactional:
                tier = "WATCH"

            findings.append(ThreatFinding(
                rule_id=rule.id,
                family=rule.family,
                label=rule.label,
                tier=tier,
                score=_score(tier, len(evidence)),
                evidence_classes=tuple(sorted(evidence)),
                matched_terms=matched,
                attribution_markers=attribution,
                limitations=rule.limitations,
            ))

        findings.sort(key=lambda item: (-TIER_RANK[item.tier], -item.score, item.rule_id))
        if not findings:
            return ThreatAssessment(tier="CLEAN", score=0, findings=())
        top = findings[0]
        return ThreatAssessment(tier=top.tier, score=top.score, findings=tuple(findings))


__all__ = [
    "RULESET_VERSION", "SCHEMA_VERSION", "RULES", "ThreatAssessment",
    "ThreatEngine", "ThreatFinding", "ThreatRule",
]
