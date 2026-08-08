"""Coverage-aware monetary observations for an illicit-liquidity pulse.

The module deliberately does not extract money from message text and does not
estimate criminal revenue.  It accepts already reviewed observations, keeps
incompatible measurement classes separate, deduplicates repeated events, and
emits only privacy-gated daily aggregates suitable for Palimpsest review.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

from .liquidity_policy import may_publish_value

OBSERVATION_SCHEMA = "scamshield-monetary-observation/v1"
PULSE_SCHEMA = "palimpsest.illicit-liquidity.v1"
MAX_OBSERVATIONS_PER_WINDOW = 100_000

MEASURE_TYPES = {
    "amount_mentioned",
    "payment_requested",
    "victim_reported_loss",
    "verified_transfer",
    "estimated_proceeds",
    "suspicious_activity",
}
VERIFICATION_TYPES = {
    "unverified",
    "victim_report",
    "official_source",
    "official_attribution",
    "independent_label_agreement",
}
ATTRIBUTION_LEVELS = {"unverified", "low", "medium", "high", "direct"}
RAILS = {
    "bank_deposit", "bank_transfer", "card", "cash", "stablecoin",
    "crypto_other", "money_market", "unknown",
}

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CURRENCY = re.compile(r"^[A-Z0-9]{2,12}$")


def _token(value: str, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return value
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError(f"{field} is not a valid bounded identifier")
    return value


def _timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed


def _amount(value: str | None, field: str, *, required: bool) -> Decimal | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a decimal string")
    if len(value) > 128:
        raise ValueError(f"{field} exceeds 128 characters")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{field} must be a decimal string") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError(f"{field} must be finite and positive")
    return parsed


def _canonical_amount(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


@dataclass(frozen=True)
class MonetaryObservation:
    """One reviewed monetary event without raw message content."""

    observation_id: str
    event_key: str
    measure_type: str
    event_at: str
    source_pseudonym: str
    currency: str
    amount_low: str
    amount_high: str | None = None
    usd_low: str | None = None
    usd_high: str | None = None
    rail: str = "unknown"
    verification: str = "unverified"
    attribution_confidence: str = "unverified"
    evidence_refs: tuple[str, ...] = ()
    fx_rate_ref: str = ""

    def __post_init__(self) -> None:
        _token(self.observation_id, "observation_id")
        _token(self.event_key, "event_key")
        if self.measure_type not in MEASURE_TYPES:
            raise ValueError(f"unknown measure_type {self.measure_type!r}")
        _timestamp(self.event_at, "event_at")
        _token(self.source_pseudonym, "source_pseudonym", allow_empty=True)
        if not isinstance(self.currency, str) or not _CURRENCY.fullmatch(self.currency):
            raise ValueError("currency must be a 2-12 character uppercase code")
        low = _amount(self.amount_low, "amount_low", required=True)
        high = _amount(self.amount_high, "amount_high", required=False)
        usd_low = _amount(self.usd_low, "usd_low", required=False)
        usd_high = _amount(self.usd_high, "usd_high", required=False)

        if self.measure_type == "estimated_proceeds":
            if high is None or high < low:
                raise ValueError("estimated_proceeds requires amount_high >= amount_low")
            if (usd_low is None) != (usd_high is None):
                raise ValueError("estimated_proceeds USD bounds must be supplied together")
            if usd_low is not None and usd_high < usd_low:
                raise ValueError("usd_high must be >= usd_low")
        elif high is not None or usd_high is not None:
            raise ValueError("ranges are reserved for estimated_proceeds")

        if self.currency == "USD" and (
            (usd_low is not None and usd_low != low)
            or (usd_high is not None and usd_high != high)
        ):
            raise ValueError("USD observations must preserve native amount bounds")
        if self.currency != "USD" and usd_low is not None and not self.fx_rate_ref:
            raise ValueError("normalized non-USD values require fx_rate_ref")
        if self.fx_rate_ref and (
            not isinstance(self.fx_rate_ref, str)
            or len(self.fx_rate_ref) > 2048
            or not self.fx_rate_ref.startswith(("https://", "urn:"))
        ):
            raise ValueError("fx_rate_ref must be a bounded HTTPS URL or URN")
        if self.verification not in VERIFICATION_TYPES:
            raise ValueError(f"unknown verification {self.verification!r}")
        if self.attribution_confidence not in ATTRIBUTION_LEVELS:
            raise ValueError(
                f"unknown attribution_confidence {self.attribution_confidence!r}"
            )
        if self.rail not in RAILS:
            raise ValueError(f"unknown rail {self.rail!r}")
        if len(self.evidence_refs) > 16:
            raise ValueError("evidence_refs exceeds 16 items")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("evidence_refs contains duplicates")
        for index, reference in enumerate(self.evidence_refs):
            _token(reference, f"evidence_refs[{index}]")

        evidence_required = {
            "victim_reported_loss", "verified_transfer", "estimated_proceeds",
            "suspicious_activity",
        }
        if self.measure_type in evidence_required and not self.evidence_refs:
            raise ValueError(f"{self.measure_type} requires an evidence reference")
        if self.measure_type == "victim_reported_loss" and self.verification not in {
            "victim_report", "official_source",
        }:
            raise ValueError("victim_reported_loss requires report-source verification")
        if self.measure_type == "verified_transfer" and self.verification not in {
            "official_attribution", "independent_label_agreement",
        }:
            raise ValueError("verified_transfer requires independent attribution")
        if self.measure_type == "verified_transfer" and self.attribution_confidence not in {
            "high", "direct",
        }:
            raise ValueError("verified_transfer requires high or direct attribution confidence")

    @property
    def event_time(self) -> datetime:
        return _timestamp(self.event_at, "event_at")

    @property
    def usd_value(self) -> Decimal | None:
        if self.currency == "USD" and self.usd_low is None:
            return _amount(self.amount_low, "amount_low", required=True)
        return _amount(self.usd_low, "usd_low", required=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": OBSERVATION_SCHEMA,
            "observation_id": self.observation_id,
            "event_key": self.event_key,
            "measure_type": self.measure_type,
            "event_at": self.event_at,
            "source_pseudonym": self.source_pseudonym,
            "currency": self.currency,
            "amount_low": self.amount_low,
            "amount_high": self.amount_high,
            "usd_low": self.usd_low,
            "usd_high": self.usd_high,
            "rail": self.rail,
            "verification": self.verification,
            "attribution_confidence": self.attribution_confidence,
            "evidence_refs": list(self.evidence_refs),
            "fx_rate_ref": self.fx_rate_ref,
        }


@dataclass(frozen=True)
class CoverageWindow:
    start: str
    end: str
    surface: str
    messages_observed: int
    messages_flagged: int
    source_pseudonyms: tuple[str, ...]
    distinct_campaigns: int
    collection_errors: int = 0
    sampling_frame_known: bool = False

    def __post_init__(self) -> None:
        start = _timestamp(self.start, "start")
        end = _timestamp(self.end, "end")
        if start >= end:
            raise ValueError("coverage start must precede end")
        _token(self.surface, "surface")
        for field, value in (
            ("messages_observed", self.messages_observed),
            ("messages_flagged", self.messages_flagged),
            ("distinct_campaigns", self.distinct_campaigns),
            ("collection_errors", self.collection_errors),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        if self.messages_flagged > self.messages_observed:
            raise ValueError("messages_flagged cannot exceed messages_observed")
        if len(set(self.source_pseudonyms)) != len(self.source_pseudonyms):
            raise ValueError("source_pseudonyms contains duplicates")
        for index, source in enumerate(self.source_pseudonyms):
            _token(source, f"source_pseudonyms[{index}]")
        if not isinstance(self.sampling_frame_known, bool):
            raise ValueError("sampling_frame_known must be boolean")

    @property
    def start_time(self) -> datetime:
        return _timestamp(self.start, "start")

    @property
    def end_time(self) -> datetime:
        return _timestamp(self.end, "end")


@dataclass(frozen=True)
class PublicationPolicy:
    min_messages: int = 100
    min_sources: int = 5
    min_events_per_value: int = 20
    max_source_event_share: str = "0.40"
    max_source_value_share: str = "0.40"

    def __post_init__(self) -> None:
        for field, value in (
            ("min_messages", self.min_messages),
            ("min_sources", self.min_sources),
            ("min_events_per_value", self.min_events_per_value),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{field} must be a positive integer")
        for field, value in (
            ("max_source_event_share", self.max_source_event_share),
            ("max_source_value_share", self.max_source_value_share),
        ):
            parsed = _amount(value, field, required=True)
            if parsed > 1:
                raise ValueError(f"{field} must be in (0, 1]")


def _deduplicate(
    observations: Iterable[MonetaryObservation],
) -> tuple[list[MonetaryObservation], int]:
    by_observation: dict[str, MonetaryObservation] = {}
    for observation in observations:
        if len(by_observation) >= MAX_OBSERVATIONS_PER_WINDOW:
            raise ValueError("observation window exceeds the 100000-item limit")
        previous = by_observation.get(observation.observation_id)
        if previous is not None and previous != observation:
            raise ValueError(f"conflicting observation_id {observation.observation_id!r}")
        by_observation[observation.observation_id] = observation

    by_event: dict[tuple[str, str], MonetaryObservation] = {}
    for observation in sorted(by_observation.values(), key=lambda item: item.observation_id):
        key = (observation.measure_type, observation.event_key)
        previous = by_event.get(key)
        if previous is not None:
            comparable = (
                previous.currency, previous.amount_low, previous.amount_high,
                previous.usd_low, previous.usd_high, previous.rail,
            )
            candidate = (
                observation.currency, observation.amount_low, observation.amount_high,
                observation.usd_low, observation.usd_high, observation.rail,
            )
            if comparable != candidate:
                raise ValueError(f"conflicting duplicate event_key {observation.event_key!r}")
            continue
        by_event[key] = observation
    deduplicated = sorted(by_event.values(), key=lambda item: item.observation_id)
    return deduplicated, len(by_observation) - len(deduplicated)


def _bucket(
    measure_type: str,
    observations: list[MonetaryObservation],
    *,
    coverage_passes: bool,
    policy: PublicationPolicy,
) -> dict[str, Any]:
    if any(item.measure_type != measure_type for item in observations):
        raise ValueError("monetary bucket contains a different measure_type")
    sources = {item.source_pseudonym for item in observations if item.source_pseudonym}
    result: dict[str, Any] = {
        "event_count": len(observations),
        "source_count": len(sources),
        "usd_sum": None,
        "value_status": "COUNT_ONLY",
    }
    if not coverage_passes:
        result["value_status"] = "INSUFFICIENT_DATA"
        return result
    if not observations or not all(
        may_publish_value(item.measure_type, item.verification) for item in observations
    ):
        return result
    if len(observations) < policy.min_events_per_value:
        result["value_status"] = "WITHHELD_MIN_EVENTS"
        return result
    if any(not item.source_pseudonym for item in observations):
        result["value_status"] = "WITHHELD_INCOMPLETE_SOURCE"
        return result
    if len(sources) < policy.min_sources:
        result["value_status"] = "WITHHELD_SOURCE_DIVERSITY"
        return result
    values = [item.usd_value for item in observations]
    if any(value is None for value in values):
        result["value_status"] = "WITHHELD_INCOMPLETE_NORMALIZATION"
        return result
    normalized_values = [value for value in values if value is not None]

    event_counts = Counter(item.source_pseudonym for item in observations)
    event_share = Decimal(max(event_counts.values())) / Decimal(len(observations))
    totals: dict[str, Decimal] = defaultdict(Decimal)
    for item, value in zip(observations, normalized_values):
        totals[item.source_pseudonym] += value
    total = sum(totals.values(), Decimal(0))
    value_share = max(totals.values()) / total
    if event_share > Decimal(policy.max_source_event_share):
        result["value_status"] = "WITHHELD_SOURCE_DOMINANCE"
        return result
    if value_share > Decimal(policy.max_source_value_share):
        result["value_status"] = "WITHHELD_VALUE_DOMINANCE"
        return result
    result["usd_sum"] = _canonical_amount(total)
    result["value_status"] = "PUBLISHED_OBSERVED_SUM"
    return result


def build_daily_pulse(
    coverage: CoverageWindow,
    observations: Iterable[MonetaryObservation],
    *,
    policy: PublicationPolicy | None = None,
) -> dict[str, Any]:
    """Build a privacy-gated daily aggregate with no population extrapolation."""
    policy = policy or PublicationPolicy()
    deduplicated, duplicate_count = _deduplicate(observations)
    for observation in deduplicated:
        if not coverage.start_time <= observation.event_time < coverage.end_time:
            raise ValueError(
                f"observation {observation.observation_id!r} is outside coverage window"
            )
        if (
            observation.source_pseudonym
            and observation.source_pseudonym not in coverage.source_pseudonyms
        ):
            raise ValueError(
                f"observation {observation.observation_id!r} has uncounted source"
            )

    coverage_passes = (
        coverage.messages_observed >= policy.min_messages
        and len(coverage.source_pseudonyms) >= policy.min_sources
    )
    grouped = {measure: [] for measure in sorted(MEASURE_TYPES)}
    rail_counts: Counter[str] = Counter()
    for observation in deduplicated:
        grouped[observation.measure_type].append(observation)
        rail_counts[observation.rail] += 1

    limitations = [
        "Value mentions and payment requests are not realized criminal proceeds.",
        "Modeled estimates and suspicious activity are not added to observed sums.",
    ]
    if not coverage.sampling_frame_known:
        limitations.append(
            "Configured-source observations are not a Telegram-wide sample; coverage is unbounded."
        )
    if coverage.collection_errors:
        limitations.append(
            "Collection errors occurred in this window; changes may reflect coverage loss."
        )
    if duplicate_count:
        limitations.append("Repeated event keys were deduplicated before aggregation.")

    pulse = {
        "schema_version": PULSE_SCHEMA,
        "window": {"start": coverage.start, "end": coverage.end},
        "scope": {"surface": coverage.surface},
        "coverage": {
            "messages_observed": coverage.messages_observed,
            "messages_flagged": coverage.messages_flagged,
            "active_source_pseudonyms": len(coverage.source_pseudonyms),
            "distinct_campaigns": coverage.distinct_campaigns,
            "collection_errors": coverage.collection_errors,
            "sampling_frame_known": coverage.sampling_frame_known,
            "duplicate_events_removed": duplicate_count,
        },
        "monetary_observations": {
            measure: _bucket(
                measure, grouped[measure], coverage_passes=coverage_passes, policy=policy,
            )
            for measure in sorted(MEASURE_TYPES)
        },
        "rails": [
            {"rail": rail, "event_count": count}
            for rail, count in sorted(rail_counts.items())
        ],
        "publication_status": "OBSERVATIONAL" if coverage_passes else "INSUFFICIENT_DATA",
        "confidence": {
            "coverage": "bounded" if coverage.sampling_frame_known else "unbounded",
            "materiality": "not_estimated",
        },
        "limitations": limitations,
    }
    json.dumps(pulse, sort_keys=True, allow_nan=False)
    return pulse


__all__ = [
    "CoverageWindow", "MEASURE_TYPES", "MonetaryObservation", "OBSERVATION_SCHEMA",
    "PULSE_SCHEMA", "PublicationPolicy", "build_daily_pulse",
]
