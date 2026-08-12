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

CREATE TABLE IF NOT EXISTS telegram_messages (
    source_key TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    status TEXT NOT NULL,
    claimed_at INTEGER NOT NULL,
    completed_at INTEGER,
    tier TEXT NOT NULL DEFAULT '',
    assessment_id TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source_key, message_id)
);

CREATE INDEX IF NOT EXISTS telegram_messages_status
    ON telegram_messages(status, claimed_at);

CREATE TABLE IF NOT EXISTS collector_sources (
    source_key TEXT PRIMARY KEY,
    configured_ref_sha256 TEXT NOT NULL,
    surface TEXT NOT NULL,
    authorization TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_checked INTEGER NOT NULL,
    last_observed_at TEXT NOT NULL DEFAULT '',
    last_message_id INTEGER NOT NULL DEFAULT 0,
    history_initialized INTEGER NOT NULL DEFAULT 0,
    history_cursor INTEGER NOT NULL DEFAULT 0,
    messages INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    error_code TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS source_candidates (
    candidate TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'PENDING',
    referrer_source_key TEXT NOT NULL,
    families_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS source_candidates_review
    ON source_candidates(status, hits DESC, last_seen DESC);

CREATE TABLE IF NOT EXISTS source_candidate_sources (
    candidate TEXT NOT NULL,
    source_key TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (candidate, source_key)
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
    def __init__(self, path: str | Path, *, read_only: bool = False):
        if read_only:
            uri = f"{Path(path).expanduser().resolve().as_uri()}?mode=ro"
            self.conn = sqlite3.connect(uri, timeout=5.0, uri=True)
            self.conn.execute("PRAGMA query_only = ON")
        else:
            self.conn = sqlite3.connect(str(path), timeout=5.0)
        self.conn.execute("PRAGMA busy_timeout = 5000")
        if not read_only:
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.executescript(_SCHEMA)
            self.conn.commit()

    def record(self, iocs: dict[str, list[str]], sample: str = "") -> None:
        now = int(time.time())
        with self.conn:
            self._record_iocs(iocs, sample=sample, now=now)

    def _record_iocs(
        self, iocs: dict[str, list[str]], *, sample: str, now: int,
    ) -> None:
        """Record IOCs inside the caller's transaction."""

        excerpt = sample[:300]
        for kind, values in iocs.items():
            k = _IOC_KIND.get(kind, kind.rstrip("s"))
            for value in values:
                self.conn.execute(
                    """INSERT INTO iocs (kind, value, first_seen, last_seen, sample)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(kind, value) DO UPDATE SET
                         last_seen = excluded.last_seen,
                         hits = hits + 1""",
                    (k, value, now, now, excerpt),
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
        with self.conn:
            self._record_assessment(result, now=now)
            self._record_result_coverage(result, now=now)

    def _record_assessment(self, result: "AnalysisResult", *, now: int) -> None:
        """Persist one suspicious assessment inside the caller's transaction."""

        assessment = result.provenance.to_dict()
        encoded = json.dumps(
            assessment, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
        source = result.collection.source_pseudonym
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

    def record_coverage(self, result: "AnalysisResult") -> None:
        """Record only aggregate collection health for a non-evidence event."""
        now = int(time.time())
        with self.conn:
            self._record_result_coverage(result, now=now)

    def _record_result_coverage(self, result: "AnalysisResult", *, now: int) -> None:
        """Record coverage for one analyzed message inside a transaction."""

        source = result.collection.source_pseudonym
        flagged = result.overall_tier != "CLEAN"
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

    def register_collector_source(
        self,
        source_key: str,
        *,
        configured_ref_sha256: str,
        surface: str,
        authorization: str,
        status: str = "RESOLVED",
        error_code: str = "",
        now: int | None = None,
    ) -> None:
        """Upsert privacy-safe source health without storing its Telegram ID."""

        self._validate_source_key(source_key)
        if not re.fullmatch(r"[0-9a-f]{24}", configured_ref_sha256):
            raise ValueError("configured_ref_sha256 must be 24 lowercase hex characters")
        timestamp = int(time.time()) if now is None else now
        with self.conn:
            self.conn.execute(
                """INSERT INTO collector_sources (
                       source_key, configured_ref_sha256, surface, authorization,
                       status, first_seen, last_checked, error_code
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key) DO UPDATE SET
                       configured_ref_sha256 = excluded.configured_ref_sha256,
                       surface = excluded.surface,
                       authorization = excluded.authorization,
                       status = CASE
                           WHEN collector_sources.status = 'ACTIVE'
                                AND excluded.status = 'RESOLVED'
                           THEN 'ACTIVE'
                           ELSE excluded.status
                       END,
                       last_checked = excluded.last_checked,
                       error_code = excluded.error_code""",
                (
                    source_key,
                    configured_ref_sha256,
                    surface,
                    authorization,
                    status,
                    timestamp,
                    timestamp,
                    error_code[:128],
                ),
            )

    def source_cursor(self, source_key: str) -> tuple[bool, int]:
        self._validate_source_key(source_key)
        row = self.conn.execute(
            """SELECT history_initialized, history_cursor
               FROM collector_sources WHERE source_key = ?""",
            (source_key,),
        ).fetchone()
        if row is None:
            raise ValueError("collector source is not registered")
        return bool(row[0]), int(row[1])

    def initialize_source_cursor(self, source_key: str, baseline: int) -> bool:
        """Set the intentional first-history boundary exactly once."""

        self._validate_message_identity(source_key, baseline, allow_zero=True)
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE collector_sources
                   SET history_initialized = 1, history_cursor = ?
                   WHERE source_key = ? AND history_initialized = 0""",
                (baseline, source_key),
            )
        return cursor.rowcount == 1

    def advance_source_cursor(self, source_key: str, message_id: int) -> None:
        """Advance reconciled history; live events must never call this method."""

        self._validate_message_identity(source_key, message_id)
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE collector_sources
                   SET history_initialized = 1,
                       history_cursor = MAX(history_cursor, ?)
                   WHERE source_key = ?""",
                (message_id, source_key),
            )
        if cursor.rowcount != 1:
            raise ValueError("collector source is not registered")

    def claim_telegram_message(
        self,
        source_key: str,
        message_id: int,
        *,
        observed_at: str,
        lease_seconds: int = 900,
        now: int | None = None,
    ) -> str:
        """Claim a message for at-least-once analysis.

        Returns ``CLAIMED``, ``COMPLETE``, or ``BUSY``.  A process crash leaves
        a lease that can be reclaimed, while completed rows are idempotent.
        """

        self._validate_message_identity(source_key, message_id)
        _parse_timestamp(observed_at)
        if isinstance(lease_seconds, bool) or not 60 <= lease_seconds <= 86400:
            raise ValueError("lease_seconds must be in [60, 86400]")
        timestamp = int(time.time()) if now is None else now
        with self.conn:
            inserted = self.conn.execute(
                """INSERT OR IGNORE INTO telegram_messages (
                       source_key, message_id, observed_at, status, claimed_at
                   ) VALUES (?, ?, ?, 'PROCESSING', ?)""",
                (source_key, message_id, observed_at, timestamp),
            )
            if inserted.rowcount == 1:
                return "CLAIMED"
            row = self.conn.execute(
                """SELECT status, claimed_at FROM telegram_messages
                   WHERE source_key = ? AND message_id = ?""",
                (source_key, message_id),
            ).fetchone()
            if row[0] == "COMPLETE":
                return "COMPLETE"
            if row[0] == "PROCESSING" and row[1] > timestamp - lease_seconds:
                return "BUSY"
            self.conn.execute(
                """UPDATE telegram_messages
                   SET status = 'PROCESSING', claimed_at = ?, completed_at = NULL,
                       error_code = '', observed_at = ?
                   WHERE source_key = ? AND message_id = ?""",
                (timestamp, observed_at, source_key, message_id),
            )
        return "CLAIMED"

    def complete_telegram_skip(
        self,
        source_key: str,
        message_id: int,
        *,
        reason: str,
        observed_at: str,
        now: int | None = None,
    ) -> None:
        """Complete a non-text/service message without counting it as analyzed."""

        self._validate_message_identity(source_key, message_id)
        _parse_timestamp(observed_at)
        if not re.fullmatch(r"[A-Z0-9_]{1,64}", reason):
            raise ValueError("skip reason must be a bounded uppercase identifier")
        timestamp = int(time.time()) if now is None else now
        with self.conn:
            updated = self.conn.execute(
                """UPDATE telegram_messages
                   SET status = 'COMPLETE', completed_at = ?, tier = ?, error_code = ''
                   WHERE source_key = ? AND message_id = ? AND status = 'PROCESSING'""",
                (timestamp, reason, source_key, message_id),
            )
            if updated.rowcount != 1:
                raise ValueError("Telegram message is not claimed for processing")
            self.conn.execute(
                """UPDATE collector_sources
                   SET last_observed_at = ?, last_message_id = MAX(last_message_id, ?)
                   WHERE source_key = ?""",
                (observed_at, message_id, source_key),
            )

    def fail_telegram_message(
        self,
        source_key: str,
        message_id: int,
        *,
        surface: str,
        observed_at: str,
        error_code: str,
    ) -> None:
        """Release a failed claim for retry and record collection health."""

        self._validate_message_identity(source_key, message_id)
        _parse_timestamp(observed_at)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,127}", error_code):
            raise ValueError("error_code must be a bounded exception identifier")
        now = int(time.time())
        with self.conn:
            updated = self.conn.execute(
                """UPDATE telegram_messages
                   SET status = 'RETRY', claimed_at = 0, error_code = ?
                   WHERE source_key = ? AND message_id = ? AND status = 'PROCESSING'""",
                (error_code, source_key, message_id),
            )
            if updated.rowcount != 1:
                return
            self.conn.execute(
                """UPDATE collector_sources
                   SET status = 'DEGRADED', errors = errors + 1,
                       error_code = ?, last_checked = ?
                   WHERE source_key = ?""",
                (error_code, now, source_key),
            )
            self._record_collection_error(
                surface,
                source_key,
                observed_at=observed_at,
                now=now,
            )

    def record_telegram_result(
        self,
        source_key: str,
        message_id: int,
        result: "AnalysisResult",
        *,
        candidates: tuple[str, ...] = (),
        sample: str = "",
        now: int | None = None,
    ) -> None:
        """Atomically persist one monitor result and finish its receipt."""

        self._validate_message_identity(source_key, message_id)
        timestamp = int(time.time()) if now is None else now
        assessment_id = (
            result.provenance.assessment_id if result.overall_tier != "CLEAN" else ""
        )
        families = tuple(dict.fromkeys(
            (*result.threats.families, *sorted(result.detector.families))
        ))
        families_json = json.dumps(families, separators=(",", ":"))
        with self.conn:
            row = self.conn.execute(
                """SELECT status FROM telegram_messages
                   WHERE source_key = ? AND message_id = ?""",
                (source_key, message_id),
            ).fetchone()
            if row is None or row[0] != "PROCESSING":
                raise ValueError("Telegram message is not claimed for processing")
            if result.iocs:
                self._record_iocs(dict(result.iocs), sample=sample, now=timestamp)
            if result.overall_tier == "CLEAN":
                self._record_result_coverage(result, now=timestamp)
            else:
                self._record_assessment(result, now=timestamp)
                self._record_result_coverage(result, now=timestamp)
            for candidate in candidates:
                if not re.fullmatch(r"@[A-Za-z][A-Za-z0-9_]{3,31}", candidate):
                    raise ValueError("candidate must be a normalized public username")
                self.conn.execute(
                    """INSERT INTO source_candidates (
                           candidate, first_seen, last_seen, referrer_source_key,
                           families_json
                       ) VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(candidate) DO UPDATE SET
                           last_seen = excluded.last_seen,
                           hits = hits + 1,
                           referrer_source_key = excluded.referrer_source_key,
                           families_json = excluded.families_json""",
                    (candidate, timestamp, timestamp, source_key, families_json),
                )
                self.conn.execute(
                    """INSERT INTO source_candidate_sources (
                           candidate, source_key, first_seen, last_seen
                       ) VALUES (?, ?, ?, ?)
                       ON CONFLICT(candidate, source_key) DO UPDATE SET
                           last_seen = excluded.last_seen,
                           hits = hits + 1""",
                    (candidate, source_key, timestamp, timestamp),
                )
            self.conn.execute(
                """UPDATE telegram_messages
                   SET status = 'COMPLETE', completed_at = ?, tier = ?,
                       assessment_id = ?, error_code = ''
                   WHERE source_key = ? AND message_id = ?""",
                (
                    timestamp,
                    result.overall_tier,
                    assessment_id,
                    source_key,
                    message_id,
                ),
            )
            self.conn.execute(
                """UPDATE collector_sources
                   SET status = 'ACTIVE', last_checked = ?, last_observed_at = ?,
                       last_message_id = MAX(last_message_id, ?),
                       messages = messages + 1, error_code = ''
                   WHERE source_key = ?""",
                (
                    timestamp,
                    result.collection.observed_at,
                    message_id,
                    source_key,
                ),
            )

    def source_candidates(
        self, *, status: str = "PENDING", min_hits: int = 1, limit: int = 100,
    ) -> list[tuple[str, int, int, str, int]]:
        if status not in {"PENDING", "APPROVED", "REJECTED"}:
            raise ValueError("unknown candidate status")
        if isinstance(min_hits, bool) or not 1 <= min_hits <= 1_000_000:
            raise ValueError("min_hits must be in [1, 1000000]")
        if isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("limit must be in [1, 1000]")
        return self.conn.execute(
            """SELECT c.candidate, c.hits, c.last_seen, c.families_json,
                      COUNT(s.source_key) AS source_count
               FROM source_candidates AS c
               LEFT JOIN source_candidate_sources AS s
                 ON s.candidate = c.candidate
               WHERE c.status = ? AND c.hits >= ?
               GROUP BY c.candidate, c.hits, c.last_seen, c.families_json
               ORDER BY source_count DESC, c.hits DESC, c.last_seen DESC,
                        c.candidate
               LIMIT ?""",
            (status, min_hits, limit),
        ).fetchall()

    def source_candidate(self, candidate: str) -> tuple[str, int, str] | None:
        row = self.conn.execute(
            """SELECT status, hits, families_json
               FROM source_candidates WHERE candidate = ?""",
            (candidate,),
        ).fetchone()
        return None if row is None else (str(row[0]), int(row[1]), str(row[2]))

    def set_source_candidate_status(self, candidate: str, status: str) -> bool:
        if status not in {"APPROVED", "REJECTED"}:
            raise ValueError("candidate status must be APPROVED or REJECTED")
        with self.conn:
            updated = self.conn.execute(
                "UPDATE source_candidates SET status = ? WHERE candidate = ?",
                (status, candidate),
            )
        return updated.rowcount == 1

    @staticmethod
    def _validate_source_key(source_key: str) -> None:
        if not isinstance(source_key, str) or not re.fullmatch(
            r"[0-9a-f]{24}", source_key
        ):
            raise ValueError("source_key must be 24 lowercase hex characters")

    @classmethod
    def _validate_message_identity(
        cls, source_key: str, message_id: int, *, allow_zero: bool = False,
    ) -> None:
        cls._validate_source_key(source_key)
        minimum = 0 if allow_zero else 1
        if (
            isinstance(message_id, bool)
            or not isinstance(message_id, int)
            or not minimum <= message_id <= 2**63 - 1
        ):
            qualifier = "nonnegative" if allow_zero else "positive"
            raise ValueError(f"message_id must be a {qualifier} integer")

    def record_collection_error(
        self,
        surface: str,
        source_pseudonym: str = "",
        *,
        observed_at: str = "",
    ) -> None:
        now = int(time.time())
        with self.conn:
            self._record_collection_error(
                surface,
                source_pseudonym,
                observed_at=observed_at or datetime.now(timezone.utc),
                now=now,
            )

    def _record_collection_error(
        self,
        surface: str,
        source_pseudonym: str,
        *,
        observed_at: str | datetime,
        now: int,
    ) -> None:
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
            observed_at=observed_at,
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
