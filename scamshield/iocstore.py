"""SQLite store for indicators harvested from flagged messages.

Every flagged message's handles/phones/channels/wallets land here with
first/last-seen timestamps and a hit counter. The point is the digest:
a deduplicated, evidence-backed IOC list is what turns whack-a-mole
sightings into something reportable (I4C/1930 for accounts, Tether
compliance for wallets, abuse@telegram.org for handles).
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import TYPE_CHECKING

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
"""

_IOC_KIND = {
    "handles": "handle",
    "phones": "phone",
    "channels": "channel",
    "wallets": "wallet",
    "emails": "email",
    "urls": "url",
}


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

    def record_collection_error(self, surface: str, source_pseudonym: str = "") -> None:
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

    def close(self) -> None:
        self.conn.close()
