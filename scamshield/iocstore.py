"""SQLite store for indicators harvested from flagged messages.

Every flagged message's handles/phones/channels/wallets land here with
first/last-seen timestamps and a hit counter. The point is the digest:
a deduplicated, evidence-backed IOC list is what turns whack-a-mole
sightings into something reportable (I4C/1930 for accounts, Tether
compliance for wallets, abuse@telegram.org for handles).
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

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
"""


class IocStore:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(str(path))
        self.conn.execute(_SCHEMA)
        self.conn.commit()

    def record(self, iocs: dict[str, list[str]], sample: str = "") -> None:
        now = int(time.time())
        excerpt = sample[:300]
        with self.conn:
            for kind, values in iocs.items():
                k = kind.rstrip("s")  # handles -> handle
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
