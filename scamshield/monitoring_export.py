"""Privacy-minimized daily aggregate for downstream analyst review."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from .iocstore import IocStore


SCHEMA_VERSION = "scamshield-telegram-monitoring-summary/v1"
_MONITOR_SURFACES = ("public_channel", "authorized_private_channel")


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class MonitoringExportPolicy:
    min_messages: int = 20
    min_sources: int = 2

    def __post_init__(self) -> None:
        if (
            isinstance(self.min_messages, bool)
            or not isinstance(self.min_messages, int)
            or not 1 <= self.min_messages <= 1_000_000
        ):
            raise ValueError("min_messages must be in [1, 1000000]")
        if (
            isinstance(self.min_sources, bool)
            or not isinstance(self.min_sources, int)
            or not 1 <= self.min_sources <= 10_000
        ):
            raise ValueError("min_sources must be in [1, 10000]")


def build_monitoring_summary(
    store: IocStore,
    day: date,
    *,
    policy: MonitoringExportPolicy | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Build an aggregate with no source keys, IOCs, text, or assessment IDs."""

    if not isinstance(day, date) or isinstance(day, datetime):
        raise TypeError("day must be a date")
    rules = policy or MonitoringExportPolicy()
    current_day = datetime.now(timezone.utc).date() if today is None else today
    start_time = datetime.combine(day, time.min, tzinfo=timezone.utc)
    end_time = start_time + timedelta(days=1)
    start = _utc_iso(start_time)
    end = _utc_iso(end_time)

    placeholders = ",".join("?" for _ in _MONITOR_SURFACES)
    coverage_rows = store.conn.execute(
        f"""SELECT source_pseudonym, messages, flagged, errors
            FROM coverage_daily
            WHERE window_start = ? AND surface IN ({placeholders})""",
        (start, *_MONITOR_SURFACES),
    ).fetchall()
    messages_observed = sum(int(row[1]) for row in coverage_rows)
    messages_flagged = sum(int(row[2]) for row in coverage_rows)
    collection_errors = sum(int(row[3]) for row in coverage_rows)
    source_count = len({row[0] for row in coverage_rows if row[0]})

    message_rows = store.conn.execute(
        """SELECT tm.tier, a.assessment_json
           FROM telegram_messages AS tm
           LEFT JOIN assessments AS a ON a.assessment_id = tm.assessment_id
           WHERE tm.status = 'COMPLETE'
             AND tm.observed_at >= ? AND tm.observed_at < ?
             AND tm.tier IN ('CLEAN', 'WATCH', 'LIKELY_SCAM', 'CONFIRMED_PATTERN')""",
        (start, end),
    ).fetchall()
    tiers: Counter[str] = Counter()
    families: Counter[str] = Counter()
    for tier, encoded in message_rows:
        tiers[str(tier)] += 1
        if not encoded:
            continue
        try:
            assessment = json.loads(encoded)
        except (TypeError, json.JSONDecodeError):
            continue
        detector = assessment.get("detector", {})
        threats = assessment.get("threat_assessment", {})
        names = {
            value for value in (
                *detector.get("families", []),
                *threats.get("families", []),
            )
            if isinstance(value, str) and value
        }
        families.update(names)

    publish_counts = (
        messages_observed >= rules.min_messages and source_count >= rules.min_sources
    )
    detection_status = "AVAILABLE_FOR_REVIEW" if publish_counts else "INSUFFICIENT_COVERAGE"
    return {
        "schema_version": SCHEMA_VERSION,
        "producer": "ScamShield",
        "data_classification": "PRIVATE_ANALYST_REVIEW",
        "review_status": "HUMAN_REVIEW_REQUIRED",
        "publication_eligible": False,
        "intended_consumers": ["palimpsest_review", "narcoscope_analyst_import"],
        "window": {
            "start": start,
            "end": end,
            "complete": day < current_day,
        },
        "sampling_frame": {
            "surface": "configured_public_or_operator_authorized_telegram",
            "universal_telegram_coverage": False,
            "raw_messages_included": False,
            "exact_iocs_included": False,
            "source_identifiers_included": False,
        },
        "coverage": {
            "messages_observed": messages_observed,
            "messages_flagged": messages_flagged,
            "sources_observed": source_count,
            "collection_errors": collection_errors,
        },
        "detections": {
            "status": detection_status,
            "minimum_messages": rules.min_messages,
            "minimum_sources": rules.min_sources,
            "tier_counts": dict(sorted(tiers.items())) if publish_counts else {},
            "family_counts": dict(sorted(families.items())) if publish_counts else {},
        },
        "limitations": [
            "Counts describe classifier matches in a configured sample, not verified crimes or platform totals.",
            "A source can be public or explicitly operator-authorized; no private access control is bypassed.",
            "No count may be converted into proceeds, prevalence, guilt, ownership, or network membership.",
            "NarcoScope and Palimpsest must retain human review and their own evidence/licence gates.",
        ],
    }


def serialize_monitoring_summary(summary: dict[str, Any]) -> str:
    return json.dumps(
        summary,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n"


__all__ = [
    "MonitoringExportPolicy",
    "SCHEMA_VERSION",
    "build_monitoring_summary",
    "serialize_monitoring_summary",
]
