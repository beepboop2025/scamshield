"""Evidence-bounded provenance hypotheses for ScamShield.

This module deliberately answers a narrower question than the detector:

* ``detector.py`` asks whether a message matches a scam/mule advertisement.
* this module asks which *published financial-crime typologies* the available
  evidence resembles, and whether there is enough independent support to say
  anything stronger than resemblance.

The distinction matters.  ``feiqian`` is a value-transfer mechanism, the
Golden Triangle is an operating ecosystem, and drug or wildlife trafficking
are possible predicate offences.  They are separate dimensions and are not
mutually exclusive.  Message text alone never establishes the origin of a
specific payment.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .detector import Verdict, normalize

PACK_SCHEMA = "scamshield-intelligence-pack/v1"
ASSESSMENT_SCHEMA = "scamshield-provenance/v1"
MAX_PACK_BYTES = 1024 * 1024
MAX_TYPOLOGIES = 32
MAX_SOURCES = 128
MAX_INDICATORS = 256
MAX_TERMS_PER_INDICATOR = 128

DIMENSIONS = {
    "laundering_mechanism",
    "operating_ecosystem",
    "predicate_offence",
}
SPECIFICITY_RANK = {"low": 1, "medium": 2, "high": 3}
SUPPORT_RANK = {
    "TYPOLOGY_MATCH": 1,
    "CORROBORATED_LEAD": 2,
    "DIRECT_LINK": 3,
}
SOURCE_KINDS = {
    "authoritative",
    "blockchain_analytics",
    "financial_institution",
    "public_osint",
    "local_history",
    "user_supplied",
}
MATCH_TYPES = {"context", "behavior", "entity", "exact_ioc"}
RELIABILITY_LEVELS = {"reported", "derived", "direct"}
IOC_KINDS = {"handles", "phones", "channels", "wallets", "emails", "urls"}
_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IntelligencePackError(ValueError):
    """The intelligence pack is malformed or exceeds its trust boundary."""


def _reject_constant(value: str) -> None:
    raise IntelligencePackError(f"non-finite JSON number is not allowed: {value}")


def _text(value: Any, field: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntelligencePackError(f"{field} must be a non-empty string")
    if len(value) > maximum:
        raise IntelligencePackError(f"{field} exceeds {maximum} characters")
    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in value):
        raise IntelligencePackError(f"{field} contains a control character")
    return value


def _identifier(value: Any, field: str) -> str:
    value = _text(value, field, maximum=128)
    if not _ID_RE.fullmatch(value):
        raise IntelligencePackError(f"{field} is not a valid identifier")
    return value


def _list(value: Any, field: str, *, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise IntelligencePackError(f"{field} must be an array")
    if len(value) > maximum:
        raise IntelligencePackError(f"{field} exceeds {maximum} items")
    return value


def _exact_fields(value: Any, field: str, required: set[str],
                  optional: set[str] | None = None) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise IntelligencePackError(f"{field} must be an object")
    optional = optional or set()
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise IntelligencePackError(f"{field} missing fields: {sorted(missing)}")
    if unknown:
        raise IntelligencePackError(f"{field} has unknown fields: {sorted(unknown)}")
    return value


@dataclass(frozen=True)
class PackSource:
    id: str
    publisher: str
    title: str
    published_at: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "publisher": self.publisher,
            "title": self.title,
            "published_at": self.published_at,
            "url": self.url,
        }


@dataclass(frozen=True)
class IndicatorRule:
    id: str
    label: str
    evidence_class: str
    specificity: str
    any_terms: tuple[str, ...] = ()
    all_terms: tuple[str, ...] = ()
    any_signals: tuple[str, ...] = ()
    all_signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class Typology:
    id: str
    dimension: str
    label: str
    description: str
    minimum_indicators: int
    minimum_specificity: str
    source_refs: tuple[str, ...]
    limitations: tuple[str, ...]
    indicators: tuple[IndicatorRule, ...]


@dataclass(frozen=True)
class IntelligencePack:
    schema: str
    version: str
    generated_at: str
    publisher_name: str
    publisher_url: str
    digest_sha256: str
    sources: Mapping[str, PackSource]
    typologies: tuple[Typology, ...]
    principles: tuple[str, ...]

    def source_dicts(self, refs: Sequence[str]) -> list[dict[str, str]]:
        return [self.sources[ref].to_dict() for ref in refs]


def _string_tuple(value: Any, field: str, *, maximum: int,
                  identifiers: bool = False) -> tuple[str, ...]:
    values = _list(value, field, maximum=maximum)
    out: list[str] = []
    for index, item in enumerate(values):
        parsed = (_identifier(item, f"{field}[{index}]") if identifiers
                  else _text(item, f"{field}[{index}]", maximum=512))
        if parsed in out:
            raise IntelligencePackError(f"{field} contains duplicate {parsed!r}")
        out.append(parsed)
    return tuple(out)


def load_intelligence_pack(path: str | Path) -> IntelligencePack:
    """Load a bounded, inert Palimpsest intelligence pack.

    Indicator expressions are literal strings and detector-signal names.  The
    pack cannot provide regular expressions or executable code; literal terms
    are escaped before matching.  Unknown fields fail closed so a future pack
    cannot silently change the meaning of v1.
    """
    pack_path = Path(path)
    try:
        raw = pack_path.read_bytes()
    except OSError as exc:
        raise IntelligencePackError(f"cannot read intelligence pack: {exc}") from exc
    if len(raw) > MAX_PACK_BYTES:
        raise IntelligencePackError("intelligence pack exceeds the 1 MiB limit")
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelligencePackError(f"intelligence pack is not strict UTF-8 JSON: {exc}") from exc

    root = _exact_fields(
        data,
        "pack",
        {"schema", "version", "generated_at", "publisher", "method", "sources", "typologies"},
    )
    if root["schema"] != PACK_SCHEMA:
        raise IntelligencePackError(f"unsupported intelligence-pack schema {root['schema']!r}")
    version = _text(root["version"], "pack.version", maximum=64)
    generated_at = _text(root["generated_at"], "pack.generated_at", maximum=64)

    publisher = _exact_fields(root["publisher"], "pack.publisher", {"name", "project_url"})
    publisher_name = _text(publisher["name"], "pack.publisher.name", maximum=128)
    publisher_url = _text(publisher["project_url"], "pack.publisher.project_url", maximum=512)
    if not publisher_url.startswith("https://"):
        raise IntelligencePackError("pack.publisher.project_url must use https")

    method = _exact_fields(
        root["method"], "pack.method",
        {"summary", "support_levels", "principles"},
    )
    _text(method["summary"], "pack.method.summary")
    levels = _string_tuple(method["support_levels"], "pack.method.support_levels", maximum=8)
    if set(levels) != set(SUPPORT_RANK):
        raise IntelligencePackError("pack support levels do not match provenance v1")
    principles = _string_tuple(method["principles"], "pack.method.principles", maximum=32)

    source_items = _list(root["sources"], "pack.sources", maximum=MAX_SOURCES)
    sources: dict[str, PackSource] = {}
    for index, raw_source in enumerate(source_items):
        item = _exact_fields(
            raw_source, f"pack.sources[{index}]",
            {"id", "publisher", "title", "published_at", "url"},
        )
        source_id = _identifier(item["id"], f"pack.sources[{index}].id")
        if source_id in sources:
            raise IntelligencePackError(f"duplicate source id {source_id!r}")
        url = _text(item["url"], f"pack.sources[{index}].url", maximum=1024)
        if not url.startswith("https://"):
            raise IntelligencePackError(f"source {source_id!r} must use an https URL")
        sources[source_id] = PackSource(
            id=source_id,
            publisher=_text(item["publisher"], f"pack.sources[{index}].publisher", maximum=256),
            title=_text(item["title"], f"pack.sources[{index}].title"),
            published_at=_text(item["published_at"], f"pack.sources[{index}].published_at", maximum=64),
            url=url,
        )

    typology_items = _list(root["typologies"], "pack.typologies", maximum=MAX_TYPOLOGIES)
    typologies: list[Typology] = []
    seen_typologies: set[str] = set()
    total_indicators = 0
    for ti, raw_typology in enumerate(typology_items):
        item = _exact_fields(
            raw_typology, f"pack.typologies[{ti}]",
            {"id", "dimension", "label", "description", "minimum_indicators",
             "minimum_specificity", "source_refs", "limitations", "indicators"},
        )
        typology_id = _identifier(item["id"], f"pack.typologies[{ti}].id")
        if typology_id in seen_typologies:
            raise IntelligencePackError(f"duplicate typology id {typology_id!r}")
        seen_typologies.add(typology_id)
        dimension = _text(item["dimension"], f"pack.typologies[{ti}].dimension", maximum=64)
        if dimension not in DIMENSIONS:
            raise IntelligencePackError(f"unknown typology dimension {dimension!r}")
        minimum = item["minimum_indicators"]
        if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= 16:
            raise IntelligencePackError("minimum_indicators must be an integer in [1, 16]")
        specificity = _text(
            item["minimum_specificity"],
            f"pack.typologies[{ti}].minimum_specificity", maximum=16,
        )
        if specificity not in SPECIFICITY_RANK:
            raise IntelligencePackError(f"unknown specificity {specificity!r}")
        source_refs = _string_tuple(
            item["source_refs"], f"pack.typologies[{ti}].source_refs",
            maximum=32, identifiers=True,
        )
        if not source_refs or any(ref not in sources for ref in source_refs):
            raise IntelligencePackError(f"typology {typology_id!r} has an unknown/empty source reference")
        limitations = _string_tuple(
            item["limitations"], f"pack.typologies[{ti}].limitations", maximum=16,
        )
        if not limitations:
            raise IntelligencePackError(f"typology {typology_id!r} must state limitations")

        indicator_items = _list(
            item["indicators"], f"pack.typologies[{ti}].indicators", maximum=64,
        )
        total_indicators += len(indicator_items)
        if total_indicators > MAX_INDICATORS:
            raise IntelligencePackError("pack has too many indicators")
        indicators: list[IndicatorRule] = []
        seen_indicators: set[str] = set()
        for ii, raw_indicator in enumerate(indicator_items):
            field = f"pack.typologies[{ti}].indicators[{ii}]"
            rule = _exact_fields(
                raw_indicator, field,
                {"id", "label", "evidence_class", "specificity"},
                {"any_terms", "all_terms", "any_signals", "all_signals"},
            )
            indicator_id = _identifier(rule["id"], f"{field}.id")
            if indicator_id in seen_indicators:
                raise IntelligencePackError(
                    f"typology {typology_id!r} has duplicate indicator {indicator_id!r}"
                )
            seen_indicators.add(indicator_id)
            rule_specificity = _text(rule["specificity"], f"{field}.specificity", maximum=16)
            if rule_specificity not in SPECIFICITY_RANK:
                raise IntelligencePackError(f"{field}.specificity is unknown")
            kwargs: dict[str, tuple[str, ...]] = {}
            for name in ("any_terms", "all_terms", "any_signals", "all_signals"):
                kwargs[name] = _string_tuple(
                    rule.get(name, []), f"{field}.{name}",
                    maximum=MAX_TERMS_PER_INDICATOR,
                    identifiers=name.endswith("signals"),
                )
            if not any(kwargs.values()):
                raise IntelligencePackError(f"{field} has no matching clause")
            indicators.append(IndicatorRule(
                id=indicator_id,
                label=_text(rule["label"], f"{field}.label", maximum=512),
                evidence_class=_identifier(rule["evidence_class"], f"{field}.evidence_class"),
                specificity=rule_specificity,
                **kwargs,
            ))
        if minimum > len(indicators):
            raise IntelligencePackError(
                f"typology {typology_id!r} requires more indicators than it defines"
            )
        typologies.append(Typology(
            id=typology_id,
            dimension=dimension,
            label=_text(item["label"], f"pack.typologies[{ti}].label", maximum=512),
            description=_text(item["description"], f"pack.typologies[{ti}].description"),
            minimum_indicators=minimum,
            minimum_specificity=specificity,
            source_refs=source_refs,
            limitations=limitations,
            indicators=tuple(indicators),
        ))

    return IntelligencePack(
        schema=PACK_SCHEMA,
        version=version,
        generated_at=generated_at,
        publisher_name=publisher_name,
        publisher_url=publisher_url,
        digest_sha256=hashlib.sha256(raw).hexdigest(),
        sources=sources,
        typologies=tuple(typologies),
        principles=principles,
    )


@dataclass(frozen=True)
class ExternalObservation:
    """Case-specific evidence supplied by a future enrichment adapter.

    ``source_group`` names the independence unit. Ten observations from one
    vendor or one law-enforcement bulletin are still one backer.  The current
    Telegram path supplies no external observations; this API is the seam for
    sanctioned-entity lists, blockchain analytics, bank data, or reviewed
    public records later.
    """

    typology_id: str
    evidence_class: str
    source_id: str
    source_group: str
    source_kind: str
    match_type: str
    summary: str
    reliability: str = "reported"
    artifact_uri: str = ""
    observed_at: str = ""
    matched_ioc_kind: str = ""
    matched_ioc_value: str = ""

    def __post_init__(self) -> None:
        for value, name in (
            (self.typology_id, "typology_id"),
            (self.evidence_class, "evidence_class"),
            (self.source_id, "source_id"),
            (self.source_group, "source_group"),
        ):
            if not _ID_RE.fullmatch(value):
                raise ValueError(f"{name} is not a valid identifier")
        if self.source_kind not in SOURCE_KINDS:
            raise ValueError(f"unknown source_kind {self.source_kind!r}")
        if self.match_type not in MATCH_TYPES:
            raise ValueError(f"unknown match_type {self.match_type!r}")
        if self.reliability not in RELIABILITY_LEVELS:
            raise ValueError(f"unknown reliability {self.reliability!r}")
        if not self.summary.strip() or len(self.summary) > 1024:
            raise ValueError("summary must be a non-empty string of at most 1024 characters")
        if self.artifact_uri and not (
            self.artifact_uri.startswith("https://")
            or self.artifact_uri.startswith("urn:")
        ):
            raise ValueError("artifact_uri must use https or urn")
        if self.match_type == "exact_ioc":
            if self.matched_ioc_kind not in IOC_KINDS:
                raise ValueError("exact_ioc observations require a known matched_ioc_kind")
            if (not self.matched_ioc_value.strip()
                    or len(self.matched_ioc_value) > 2048):
                raise ValueError("exact_ioc observations require a bounded matched_ioc_value")
        elif self.matched_ioc_kind or self.matched_ioc_value:
            raise ValueError("matched IOC fields are only valid for exact_ioc observations")

    def to_dict(self) -> dict[str, str]:
        return {
            "typology_id": self.typology_id,
            "evidence_class": self.evidence_class,
            "source_id": self.source_id,
            "source_group": self.source_group,
            "source_kind": self.source_kind,
            "match_type": self.match_type,
            "summary": self.summary,
            "reliability": self.reliability,
            "artifact_uri": self.artifact_uri,
            "observed_at": self.observed_at,
            "matched_ioc_kind": self.matched_ioc_kind,
            "matched_ioc_value": self.matched_ioc_value,
        }


@dataclass(frozen=True)
class MatchedIndicator:
    id: str
    label: str
    evidence_class: str
    specificity: str
    term_hits: tuple[str, ...]
    signal_hits: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "evidence_class": self.evidence_class,
            "specificity": self.specificity,
            "term_hits": list(self.term_hits),
            "signal_hits": list(self.signal_hits),
        }


@dataclass(frozen=True)
class ProvenanceHypothesis:
    typology_id: str
    dimension: str
    label: str
    support_level: str
    matched_indicators: tuple[MatchedIndicator, ...]
    external_observations: tuple[ExternalObservation, ...]
    independent_backers: int
    evidence_classes: tuple[str, ...]
    typology_sources: tuple[PackSource, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "typology_id": self.typology_id,
            "dimension": self.dimension,
            "label": self.label,
            "support_level": self.support_level,
            "matched_indicators": [item.to_dict() for item in self.matched_indicators],
            "external_observations": [item.to_dict() for item in self.external_observations],
            "independent_backers": self.independent_backers,
            "evidence_classes": list(self.evidence_classes),
            "typology_sources": [source.to_dict() for source in self.typology_sources],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ProvenanceAssessment:
    assessment_id: str
    created_at: str
    message_sha256: str
    detector: Mapping[str, Any]
    threat_assessment: Mapping[str, Any]
    collection: Mapping[str, Any]
    market_rate: Mapping[str, Any]
    intelligence_pack: Mapping[str, str]
    hypotheses: tuple[ProvenanceHypothesis, ...]
    origin_answer: str
    abstentions: Mapping[str, str]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ASSESSMENT_SCHEMA,
            "assessment_id": self.assessment_id,
            "created_at": self.created_at,
            "message_sha256": self.message_sha256,
            "detector": dict(self.detector),
            "threat_assessment": dict(self.threat_assessment),
            "collection": dict(self.collection),
            "market_rate": dict(self.market_rate),
            "intelligence_pack": dict(self.intelligence_pack),
            "hypotheses": [hypothesis.to_dict() for hypothesis in self.hypotheses],
            "origin_answer": self.origin_answer,
            "abstentions": dict(self.abstentions),
            "limitations": list(self.limitations),
        }


def _contains_literal(haystack: str, literal: str) -> bool:
    literal = normalize(literal).casefold()
    if not literal:
        return False
    # Latin/digit phrases use token boundaries; CJK and punctuation-heavy
    # phrases use literal containment. The regex is generated only from an
    # escaped literal, never accepted from the intelligence pack.
    if literal[0].isascii() and literal[-1].isascii() and (
        literal[0].isalnum() and literal[-1].isalnum()
    ):
        return bool(re.search(r"(?<!\w)" + re.escape(literal) + r"(?!\w)", haystack))
    return literal in haystack


def _match_rule(rule: IndicatorRule, normalized_text: str,
                signal_names: set[str]) -> MatchedIndicator | None:
    any_term_hits = tuple(term for term in rule.any_terms
                          if _contains_literal(normalized_text, term))
    all_term_hits = tuple(term for term in rule.all_terms
                          if _contains_literal(normalized_text, term))
    any_signal_hits = tuple(name for name in rule.any_signals if name in signal_names)
    all_signal_hits = tuple(name for name in rule.all_signals if name in signal_names)

    if rule.any_terms and not any_term_hits:
        return None
    if rule.all_terms and len(all_term_hits) != len(rule.all_terms):
        return None
    if rule.any_signals and not any_signal_hits:
        return None
    if rule.all_signals and len(all_signal_hits) != len(rule.all_signals):
        return None
    return MatchedIndicator(
        id=rule.id,
        label=rule.label,
        evidence_class=rule.evidence_class,
        specificity=rule.specificity,
        term_hits=tuple(dict.fromkeys(any_term_hits + all_term_hits)),
        signal_hits=tuple(dict.fromkeys(any_signal_hits + all_signal_hits)),
    )


def _valid_message_match(typology: Typology,
                         matches: Sequence[MatchedIndicator]) -> bool:
    if len(matches) < typology.minimum_indicators:
        return False
    strongest = max((SPECIFICITY_RANK[item.specificity] for item in matches), default=0)
    return strongest >= SPECIFICITY_RANK[typology.minimum_specificity]


def _support_level(observations: Sequence[ExternalObservation]) -> str:
    if any(
        item.source_kind == "authoritative"
        and item.match_type == "exact_ioc"
        and item.reliability == "direct"
        for item in observations
    ):
        return "DIRECT_LINK"

    qualifying = {
        item.source_group
        for item in observations
        if item.source_kind in {
            "authoritative", "blockchain_analytics",
            "financial_institution", "public_osint",
        }
        and item.reliability in {"derived", "direct"}
    }
    classes = {item.evidence_class for item in observations if item.source_group in qualifying}
    if len(qualifying) >= 2 and len(classes) >= 2:
        return "CORROBORATED_LEAD"
    return "TYPOLOGY_MATCH"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProvenanceEngine:
    def __init__(self, pack: IntelligencePack, *, clock=_utc_now):
        self.pack = pack
        self._clock = clock
        self._typology_ids = {item.id for item in pack.typologies}

    @classmethod
    def from_path(cls, path: str | Path, *, clock=_utc_now) -> "ProvenanceEngine":
        return cls(load_intelligence_pack(path), clock=clock)

    def assess(
        self,
        text: str,
        verdict: Verdict,
        *,
        market_rate: Mapping[str, Any] | None = None,
        threat_assessment: Mapping[str, Any] | None = None,
        collection: Mapping[str, Any] | None = None,
        additional_signals: Iterable[str] = (),
        external_observations: Iterable[ExternalObservation] = (),
    ) -> ProvenanceAssessment:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        observations = tuple(external_observations)
        unknown = sorted({item.typology_id for item in observations} - self._typology_ids)
        if unknown:
            raise ValueError(f"external observations reference unknown typologies: {unknown}")
        for item in observations:
            if item.match_type != "exact_ioc":
                continue
            observed_values = verdict.iocs.get(item.matched_ioc_kind, [])
            if item.matched_ioc_value not in observed_values:
                raise ValueError(
                    "exact_ioc observation does not bind an IOC extracted from this message"
                )

        normalized = normalize(text).casefold()
        signal_names = {signal.name for signal in verdict.signals}
        for name in additional_signals:
            if not isinstance(name, str) or not _ID_RE.fullmatch(name):
                raise ValueError("additional signal names must be valid identifiers")
            signal_names.add(name)
        hypotheses: list[ProvenanceHypothesis] = []

        for typology in self.pack.typologies:
            matches = tuple(
                matched
                for rule in typology.indicators
                if (matched := _match_rule(rule, normalized, signal_names)) is not None
            )
            message_match = _valid_message_match(typology, matches)
            case_observations = tuple(
                item for item in observations if item.typology_id == typology.id
            )
            if not message_match and not case_observations:
                continue

            support = _support_level(case_observations)
            backers = {item.source_group for item in case_observations}
            if message_match:
                backers.add("submitted-message")
            evidence_classes = {item.evidence_class for item in matches}
            evidence_classes.update(item.evidence_class for item in case_observations)
            hypotheses.append(ProvenanceHypothesis(
                typology_id=typology.id,
                dimension=typology.dimension,
                label=typology.label,
                support_level=support,
                matched_indicators=matches if message_match else (),
                external_observations=case_observations,
                independent_backers=len(backers),
                evidence_classes=tuple(sorted(evidence_classes)),
                typology_sources=tuple(self.pack.sources[ref] for ref in typology.source_refs),
                limitations=typology.limitations,
            ))

        hypotheses.sort(
            key=lambda item: (
                -SUPPORT_RANK[item.support_level],
                -item.independent_backers,
                item.dimension,
                item.typology_id,
            )
        )
        hypothesis_tuple = tuple(hypotheses)
        origin_answer = self._answer(hypothesis_tuple)
        abstentions = self._abstentions(hypothesis_tuple)

        created = self._clock()
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        created_at = created.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        message_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
        rate = dict(market_rate or {})
        threat_context = dict(threat_assessment or {})
        collection_context = dict(collection or {})
        detector = {
            "tier": verdict.tier,
            "score": verdict.score,
            "carrier_score": verdict.car_score,
            "families": sorted(verdict.families),
            "signals": [
                {"name": item.name, "family": item.family, "weight": item.weight}
                for item in verdict.signals
            ],
            "iocs": {key: list(values) for key, values in verdict.iocs.items()},
        }
        pack_context = {
            "schema": self.pack.schema,
            "version": self.pack.version,
            "generated_at": self.pack.generated_at,
            "publisher": self.pack.publisher_name,
            "sha256": self.pack.digest_sha256,
        }
        base = {
            "schema_version": ASSESSMENT_SCHEMA,
            "created_at": created_at,
            "message_sha256": message_sha256,
            "detector": detector,
            "threat_assessment": threat_context,
            "collection": collection_context,
            "market_rate": rate,
            "intelligence_pack": pack_context,
            "hypotheses": [item.to_dict() for item in hypothesis_tuple],
            "origin_answer": origin_answer,
            "abstentions": abstentions,
        }
        assessment_id = hashlib.sha256(
            json.dumps(base, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hexdigest()[:24]
        return ProvenanceAssessment(
            assessment_id=assessment_id,
            created_at=created_at,
            message_sha256=message_sha256,
            detector=detector,
            threat_assessment=threat_context,
            collection=collection_context,
            market_rate=rate,
            intelligence_pack=pack_context,
            hypotheses=hypothesis_tuple,
            origin_answer=origin_answer,
            abstentions=abstentions,
            limitations=(
                "This is an analytical lead, not a finding of criminal origin or guilt.",
                "Typology sources describe known methods; they do not prove that this message or its IOCs participated in those cases.",
                "No numeric probability is shown because the current evidence set is not calibrated for source-of-funds probabilities.",
            ),
        )

    @staticmethod
    def _answer(hypotheses: Sequence[ProvenanceHypothesis]) -> str:
        if not hypotheses:
            return (
                "No source attribution can be made from the available evidence. "
                "No qualifying provenance typology was supported."
            )
        direct = [item for item in hypotheses if item.support_level == "DIRECT_LINK"]
        if direct:
            labels = ", ".join(item.label for item in direct[:2])
            return (
                f"An exact IOC has an authoritative public-record link to: {labels}. "
                "Human review of the cited record is still required."
            )
        corroborated = [
            item for item in hypotheses if item.support_level == "CORROBORATED_LEAD"
        ]
        if corroborated:
            labels = ", ".join(item.label for item in corroborated[:2])
            return (
                f"Independent evidence supports a corroborated lead for: {labels}. "
                "This is not yet a direct source-of-funds finding."
            )
        labels = ", ".join(item.label for item in hypotheses[:2])
        return (
            f"The message is consistent with these public typologies: {labels}. "
            "Message patterns alone do not establish where these specific funds originated."
        )

    @staticmethod
    def _abstentions(hypotheses: Sequence[ProvenanceHypothesis]) -> dict[str, str]:
        out: dict[str, str] = {}
        for dimension in sorted(DIMENSIONS):
            items = [item for item in hypotheses if item.dimension == dimension]
            if not items:
                out[dimension] = "no qualifying case-specific evidence"
            elif max(SUPPORT_RANK[item.support_level] for item in items) == 1:
                out[dimension] = "message-level typology match only; origin not established"
        return out


def validate_assessment_shape(value: Mapping[str, Any]) -> None:
    """Small shared guard used by the local Palimpsest bridge tests/clients."""
    if value.get("schema_version") != ASSESSMENT_SCHEMA:
        raise ValueError("unsupported assessment schema")
    if not isinstance(value.get("assessment_id"), str) or not re.fullmatch(
        r"[0-9a-f]{24}", value["assessment_id"]
    ):
        raise ValueError("invalid assessment_id")
    if not isinstance(value.get("message_sha256"), str) or not _SHA256_RE.fullmatch(
        value["message_sha256"]
    ):
        raise ValueError("invalid message_sha256")
    if not isinstance(value.get("hypotheses"), list) or len(value["hypotheses"]) > 32:
        raise ValueError("invalid hypotheses")
    threats = value.get("threat_assessment")
    if not isinstance(threats, dict):
        raise ValueError("threat_assessment must be an object")
    if threats and threats.get("schema_version") != "scamshield-threat-assessment/v1":
        raise ValueError("unsupported threat assessment schema")
    collection = value.get("collection")
    if not isinstance(collection, dict):
        raise ValueError("collection must be an object")
    if collection and collection.get("schema_version") != "scamshield-collection/v1":
        raise ValueError("unsupported collection schema")
    rate = value.get("market_rate", {})
    if not isinstance(rate, dict):
        raise ValueError("market_rate must be an object")
    numeric = rate.get("rate")
    if numeric is not None and (
        isinstance(numeric, bool)
        or not isinstance(numeric, (int, float))
        or not math.isfinite(float(numeric))
    ):
        raise ValueError("market rate is not finite")
