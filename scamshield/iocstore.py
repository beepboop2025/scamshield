"""SQLite store for indicators harvested from flagged messages.

Every flagged message's handles/phones/channels/wallets land here with
first/last-seen timestamps and a hit counter. The point is the digest:
a deduplicated, evidence-backed IOC list is what turns whack-a-mole
sightings into something reportable (I4C/1930 for accounts, Tether
compliance for wallets, abuse@telegram.org for handles).
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .liquidity import (
    CoverageWindow,
    MonetaryObservation,
    PublicationPolicy,
    build_daily_pulse,
)

if TYPE_CHECKING:
    from .analysis import AnalysisResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    kind TEXT NOT NULL,          -- handle | phone | channel | wallet
    value TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    sample TEXT,                 -- first message excerpt it appeared in
    PRIMARY KEY (kind, value)
);

CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    message_sha256 TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    surface TEXT NOT NULL,
    source_pseudonym TEXT NOT NULL,
    overall_tier TEXT NOT NULL,
    overall_score INTEGER NOT NULL,
    assessment_json TEXT NOT NULL,
    capsule_sha256 TEXT NOT NULL,
    bridge_status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS coverage (
    surface TEXT NOT NULL,
    source_pseudonym TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    messages INTEGER NOT NULL DEFAULT 1,
    flagged INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (surface, source_pseudonym)
);

CREATE TABLE IF NOT EXISTS coverage_daily (
    window_start TEXT NOT NULL,
    surface TEXT NOT NULL,
    source_pseudonym TEXT NOT NULL,
    messages INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (window_start, surface, source_pseudonym)
);

CREATE TABLE IF NOT EXISTS monetary_observations (
    observation_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    window_start TEXT NOT NULL,
    observation_json TEXT NOT NULL,
    reviewed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS monetary_observations_window
    ON monetary_observations(window_start);
"""

_IOC_KIND = {
    "handles": "handle",
    "phones": "phone",
    "channels": "channel",
    "wallets": "wallet",
    "emails": "email",
    "urls": "url",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("observed_at must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def _window_start(value: str | datetime | date) -> str:
    if isinstance(value, str):
        parsed = _parse_timestamp(value)
    elif isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime must include a timezone")
        parsed = value.astimezone(timezone.utc)
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    else:
        raise TypeError("window value must be a date, datetime, or timestamp")
    return parsed.replace(hour=0, minute=0, second=0, microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class IocStore:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(str(path), timeout=5.0)
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def record(self, iocs: dict[str, list[str]], sample: str = "") -> None:
        now = int(time.time())
        excerpt = sample[:300]
        with self.conn:
            for kind, values in iocs.items():
                k = _IOC_KIND.get(kind, kind.rstrip("s"))
                for v in values:
                    self.conn.execute(
                        """INSERT INTO iocs (kind, value, first_seen, last_seen, sample)
                           VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT(kind, value) DO UPDATE SET
                             last_seen = excluded.last_seen,
                             hits = hits + 1""",
                        (k, v, now, now, excerpt),
                    )

    def digest(self, min_hits: int = 1) -> list[tuple[str, str, int]]:
        cur = self.conn.execute(
            "SELECT kind, value, hits FROM iocs WHERE hits >= ? "
            "ORDER BY hits DESC, last_seen DESC",
            (min_hits,),
        )
        return cur.fetchall()

    def record_analysis(self, result: "AnalysisResult") -> None:
        """Persist structured evidence and aggregate coverage, never raw text."""
        now = int(time.time())
        assessment = result.provenance.to_dict()
        encoded = json.dumps(
            assessment, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
        source = result.collection.source_pseudonym
        flagged = result.overall_tier != "CLEAN"
        with self.conn:
            self.conn.execute(
                """INSERT INTO assessments (
                       assessment_id, message_sha256, first_seen, last_seen,
                       surface, source_pseudonym, overall_tier, overall_score,
                       assessment_json, capsule_sha256, bridge_status
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(assessment_id) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       hits = hits + 1,
                       capsule_sha256 = excluded.capsule_sha256,
                       bridge_status = excluded.bridge_status""",
                (
                    result.provenance.assessment_id,
                    result.provenance.message_sha256,
                    now,
                    now,
                    result.collection.surface,
                    source,
                    result.overall_tier,
                    result.overall_score,
                    encoded,
                    result.bridge.capsule_sha256,
                    result.bridge.status,
                ),
            )
            self.conn.execute(
                """INSERT INTO coverage (
                       surface, source_pseudonym, first_seen, last_seen,
                       messages, flagged, errors
                   ) VALUES (?, ?, ?, ?, 1, ?, 0)
                   ON CONFLICT(surface, source_pseudonym) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       messages = messages + 1,
                       flagged = flagged + excluded.flagged""",
                (result.collection.surface, source, now, now, int(flagged)),
            )
            self._record_daily_coverage(
                observed_at=result.collection.observed_at,
                surface=result.collection.surface,
                source_pseudonym=source,
                messages=1,
                flagged=int(flagged),
            )

    def record_coverage(self, result: "AnalysisResult") -> None:
        """Record only aggregate collection health for a non-evidence event."""
        now = int(time.time())
        source = result.collection.source_pseudonym
        flagged = result.overall_tier != "CLEAN"
        with self.conn:
            self.conn.execute(
                """INSERT INTO coverage (
                       surface, source_pseudonym, first_seen, last_seen,
                       messages, flagged, errors
                   ) VALUES (?, ?, ?, ?, 1, ?, 0)
                   ON CONFLICT(surface, source_pseudonym) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       messages = messages + 1,
                       flagged = flagged + excluded.flagged""",
                (result.collection.surface, source, now, now, int(flagged)),
            )
            self._record_daily_coverage(
                observed_at=result.collection.observed_at,
                surface=result.collection.surface,
                source_pseudonym=source,
                messages=1,
                flagged=int(flagged),
            )

    def record_collection_error(
        self,
        surface: str,
        source_pseudonym: str = "",
        *,
        observed_at: str = "",
    ) -> None:
        now = int(time.time())
        with self.conn:
            self.conn.execute(
                """INSERT INTO coverage (
                       surface, source_pseudonym, first_seen, last_seen,
                       messages, flagged, errors
                   ) VALUES (?, ?, ?, ?, 0, 0, 1)
                   ON CONFLICT(surface, source_pseudonym) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       errors = errors + 1""",
                (surface, source_pseudonym, now, now),
            )
            self._record_daily_coverage(
                observed_at=observed_at or datetime.now(timezone.utc),
                surface=surface,
                source_pseudonym=source_pseudonym,
                errors=1,
            )

    def _record_daily_coverage(
        self,
        *,
        observed_at: str | datetime,
        surface: str,
        source_pseudonym: str,
        messages: int = 0,
        flagged: int = 0,
        errors: int = 0,
    ) -> None:
        """Upsert one event into the UTC-day coverage ledger.

        The caller owns the surrounding transaction. Keeping this separate
        from the all-time ``coverage`` table prevents a partial write where a
        message appears in one view but not the other.
        """
        self.conn.execute(
            """INSERT INTO coverage_daily (
                   window_start, surface, source_pseudonym,
                   messages, flagged, errors
               ) VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(window_start, surface, source_pseudonym) DO UPDATE SET
                   messages = messages + excluded.messages,
                   flagged = flagged + excluded.flagged,
                   errors = errors + excluded.errors""",
            (
                _window_start(observed_at),
                surface,
                source_pseudonym,
                messages,
                flagged,
                errors,
            ),
        )

    def coverage_digest(self) -> list[tuple[str, str, int, int, int, int]]:
        cur = self.conn.execute(
            """SELECT surface, source_pseudonym, messages, flagged, errors, last_seen
               FROM coverage ORDER BY last_seen DESC, surface, source_pseudonym"""
        )
        return cur.fetchall()

    def recent_assessments(self, limit: int = 100) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be in [1, 1000]")
        cur = self.conn.execute(
            """SELECT assessment_json FROM assessments
               ORDER BY last_seen DESC LIMIT ?""",
            (limit,),
        )
        return [json.loads(row[0]) for row in cur.fetchall()]

    def assessment_review_context(
        self,
        message_sha256: str,
        *,
        surface: str,
        source_pseudonym: str,
    ) -> dict | None:
        """Return the exact privacy context needed for an owner review.

        Requiring both surface and HMAC pseudonym prevents identical forwarded
        text from being accidentally attached to another source's assessment.
        """
        if not isinstance(message_sha256, str) or not _SHA256.fullmatch(
            message_sha256
        ):
            raise ValueError("message_sha256 must be 64 lowercase hex characters")
        if not source_pseudonym:
            raise ValueError("a source pseudonym is required for monetary review")
        row = self.conn.execute(
            """SELECT assessment_id, source_pseudonym, surface, assessment_json
               FROM assessments
               WHERE message_sha256 = ? AND surface = ? AND source_pseudonym = ?
               ORDER BY last_seen DESC LIMIT 1""",
            (message_sha256, surface, source_pseudonym),
        ).fetchone()
        if row is None:
            return None
        return self._review_context(row)

    def assessment_review_context_by_id(self, assessment_id: str) -> dict | None:
        """Resolve a monitor alert's opaque review ID for the owner bot chat."""
        if not isinstance(assessment_id, str) or not re.fullmatch(
            r"[0-9a-f]{24}", assessment_id
        ):
            raise ValueError("assessment_id must be 24 lowercase hex characters")
        row = self.conn.execute(
            """SELECT assessment_id, source_pseudonym, surface, assessment_json
               FROM assessments WHERE assessment_id = ?""",
            (assessment_id,),
        ).fetchone()
        return None if row is None else self._review_context(row)

    @staticmethod
    def _review_context(row: tuple) -> dict:
        assessment = json.loads(row[3])
        collection = assessment.get("collection", {})
        observed_at = collection.get("observed_at", "")
        _parse_timestamp(observed_at)
        return {
            "assessment_id": row[0],
            "event_at": observed_at,
            "source_pseudonym": row[1],
            "surface": row[2],
        }

    def record_monetary_observation(
        self,
        observation: MonetaryObservation,
        *,
        assessment_id: str,
    ) -> None:
        """Persist an operator-reviewed observation bound to an assessment."""
        if not isinstance(observation, MonetaryObservation):
            raise TypeError("observation must be a MonetaryObservation")
        row = self.conn.execute(
            """SELECT source_pseudonym, surface, assessment_json
               FROM assessments WHERE assessment_id = ?""",
            (assessment_id,),
        ).fetchone()
        if row is None:
            raise ValueError("monetary observation references an unknown assessment")
        if observation.source_pseudonym != row[0]:
            raise ValueError("monetary observation source does not match assessment")
        if assessment_id not in observation.evidence_refs:
            raise ValueError("monetary observation must cite its assessment")
        assessment = json.loads(row[2])
        event_at = assessment.get("collection", {}).get("observed_at", "")
        if observation.event_at != event_at:
            raise ValueError("monetary observation timestamp does not match assessment")
        window_start = _window_start(observation.event_at)
        daily_coverage = self.conn.execute(
            """SELECT 1 FROM coverage_daily
               WHERE window_start = ? AND surface = ? AND source_pseudonym = ?""",
            (window_start, row[1], row[0]),
        ).fetchone()
        if daily_coverage is None:
            raise ValueError(
                "assessment predates exact daily coverage; resubmit it before review"
            )
        encoded = json.dumps(
            observation.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
        with self.conn:
            self.conn.execute(
                """INSERT INTO monetary_observations (
                       observation_id, assessment_id, window_start,
                       observation_json, reviewed_at
                   ) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(observation_id) DO UPDATE SET
                       observation_json = excluded.observation_json,
                       reviewed_at = excluded.reviewed_at""",
                (
                    observation.observation_id,
                    assessment_id,
                    window_start,
                    encoded,
                    int(time.time()),
                ),
            )

    def daily_liquidity_pulse(
        self,
        day: date,
        *,
        policy: PublicationPolicy | None = None,
    ) -> dict:
        """Build the UTC-day pulse from measured coverage and reviewed facts."""
        if not isinstance(day, date) or isinstance(day, datetime):
            raise TypeError("day must be a date")
        start = _window_start(day)
        start_time = _parse_timestamp(start)
        end = (start_time + timedelta(days=1)).isoformat().replace("+00:00", "Z")
        coverage_rows = self.conn.execute(
            """SELECT source_pseudonym, messages, flagged, errors
               FROM coverage_daily WHERE window_start = ?""",
            (start,),
        ).fetchall()
        sources = tuple(sorted({row[0] for row in coverage_rows if row[0]}))
        coverage = CoverageWindow(
            start=start,
            end=end,
            surface="authorized_telegram_surfaces",
            messages_observed=sum(row[1] for row in coverage_rows),
            messages_flagged=sum(row[2] for row in coverage_rows),
            source_pseudonyms=sources,
            distinct_campaigns=0,
            collection_errors=sum(row[3] for row in coverage_rows),
            sampling_frame_known=False,
        )
        observation_rows = self.conn.execute(
            """SELECT observation_json FROM monetary_observations
               WHERE window_start = ? ORDER BY observation_id""",
            (start,),
        ).fetchall()
        observations = []
        for row in observation_rows:
            payload = json.loads(row[0])
            payload.pop("schema_version", None)
            observations.append(MonetaryObservation(**payload))
        return build_daily_pulse(coverage, observations, policy=policy)

    def close(self) -> None:
        self.conn.close()
