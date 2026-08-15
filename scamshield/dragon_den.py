"""Durable routing contract for the raw Dragon Den Telegram mirror.

The mirror stores Telegram *references*, never copied message bodies or media.
Telegram remains the raw-content store and the dedicated bot uses native
forwarding so source attribution survives.  A separate Palimpsest bridge owns
the reviewed, privacy-minimized publication path.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


ROUTES_SCHEMA = "scamshield-dragon-den-routes/v1"
MAX_ROUTES_BYTES = 1024 * 1024
MAX_DESTINATIONS = 32
MAX_SOURCES = 500
MAX_ALBUM_MESSAGES = 100
_KEY = re.compile(r"^[a-z][a-z0-9-]{1,47}$")
_PUBLIC_USERNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_DESTINATION_CHAT = re.compile(r"^(?:@[A-Za-z][A-Za-z0-9_]{3,31}|-100[0-9]{5,16})$")
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class DragonDenError(ValueError):
    """The raw mirror configuration or delivery state is invalid."""


@dataclass(frozen=True)
class Destination:
    id: str
    chat_id: str
    label: str


@dataclass(frozen=True)
class SourceRoute:
    source: str
    label: str
    destination_ids: tuple[str, ...]


@dataclass(frozen=True)
class DragonDenRoutes:
    destinations: Mapping[str, Destination]
    catch_all_destination_ids: tuple[str, ...]
    sources: Mapping[str, SourceRoute]

    def destinations_for(self, source: str) -> tuple[Destination, ...]:
        normalized = normalize_public_source(source)
        route = self.sources.get(normalized.casefold())
        if route is None:
            return ()
        keys = tuple(dict.fromkeys(
            (*self.catch_all_destination_ids, *route.destination_ids)
        ))
        return tuple(self.destinations[key] for key in keys)


@dataclass(frozen=True)
class Delivery:
    receipt_id: str
    source: str
    source_chat_id: str
    source_message_id: int
    revision: str
    media_group_id: str
    observed_at: str
    destination_id: str
    destination_chat_id: str
    attempts: int
    header_message_id: int | None


@dataclass(frozen=True)
class DeliveryBatch:
    deliveries: tuple[Delivery, ...]

    @property
    def first(self) -> Delivery:
        return self.deliveries[0]

    @property
    def receipt_label(self) -> str:
        digest = hashlib.sha256(
            "\n".join(item.receipt_id for item in self.deliveries).encode("ascii")
        ).hexdigest()
        return f"den-{digest[:16]}"


def _exact(value: Any, fields: set[str], path: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise DragonDenError(f"{path} does not use its exact field set")
    return value


def _text(value: Any, path: str, *, maximum: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise DragonDenError(f"{path} must be non-empty bounded text")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise DragonDenError(f"{path} contains unsafe Unicode")
    return value.strip()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DragonDenError(f"route registry repeats JSON key {key!r}")
        value[key] = item
    return value


def normalize_public_source(value: str) -> str:
    """Return one public ``@username``; invite links and numeric peers fail."""

    if not isinstance(value, str):
        raise DragonDenError("source must be a public Telegram username")
    candidate = value.strip()
    if candidate.startswith("@"):
        username = candidate[1:]
    elif candidate.startswith("https://"):
        parsed = urlsplit(candidate)
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() not in {"t.me", "www.t.me"}
            or parsed.query
            or parsed.fragment
        ):
            raise DragonDenError("source URL must be a plain https://t.me/<username>")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 1:
            raise DragonDenError("source URL must identify one public channel")
        username = parts[0]
    else:
        raise DragonDenError("raw publication sources must use a public @username")
    if not _PUBLIC_USERNAME.fullmatch(username):
        raise DragonDenError("source is not a valid public Telegram username")
    return f"@{username.lower()}"


def load_routes(path: str | Path) -> DragonDenRoutes:
    """Load the strict root-owned routing file without accepting extra policy."""

    route_path = Path(path)
    try:
        raw = route_path.read_bytes()
        if not 1 <= len(raw) <= MAX_ROUTES_BYTES:
            raise DragonDenError("Dragon Den routes must be between 1 byte and 1 MiB")
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                DragonDenError(f"non-finite JSON number {token}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DragonDenError(f"cannot load Dragon Den routes: {exc}") from exc
    top = _exact(
        value,
        {"schema_version", "destinations", "catch_all_destination_ids", "sources"},
        "routes",
    )
    if top["schema_version"] != ROUTES_SCHEMA:
        raise DragonDenError("unsupported Dragon Den routes schema")

    destination_rows = top["destinations"]
    if (
        type(destination_rows) is not list
        or not 1 <= len(destination_rows) <= MAX_DESTINATIONS
    ):
        raise DragonDenError("routes.destinations must contain 1 to 32 rows")
    destinations: dict[str, Destination] = {}
    destination_chats: set[str] = set()
    for index, raw_destination in enumerate(destination_rows):
        row = _exact(raw_destination, {"id", "chat_id", "label"}, f"destinations[{index}]")
        key = _text(row["id"], f"destinations[{index}].id", maximum=48)
        if not _KEY.fullmatch(key) or key in destinations:
            raise DragonDenError(f"destinations[{index}].id is invalid or duplicated")
        chat_id = _text(row["chat_id"], f"destinations[{index}].chat_id", maximum=64)
        if not _DESTINATION_CHAT.fullmatch(chat_id):
            raise DragonDenError(f"destinations[{index}].chat_id is invalid")
        chat_key = chat_id.casefold()
        if chat_key in destination_chats:
            raise DragonDenError(f"destinations[{index}].chat_id is duplicated")
        destination_chats.add(chat_key)
        if chat_id.startswith("@"):
            chat_id = chat_id.lower()
        destinations[key] = Destination(
            id=key,
            chat_id=chat_id,
            label=_text(row["label"], f"destinations[{index}].label", maximum=120),
        )

    catch_all = top["catch_all_destination_ids"]
    if type(catch_all) is not list or not catch_all:
        raise DragonDenError("at least one catch-all destination is required")
    catch_all_ids: list[str] = []
    for index, key in enumerate(catch_all):
        if type(key) is not str or key not in destinations or key in catch_all_ids:
            raise DragonDenError(f"catch_all_destination_ids[{index}] is invalid")
        catch_all_ids.append(key)

    source_rows = top["sources"]
    if type(source_rows) is not list or not 1 <= len(source_rows) <= MAX_SOURCES:
        raise DragonDenError("routes.sources must contain 1 to 500 public sources")
    sources: dict[str, SourceRoute] = {}
    for index, raw_source in enumerate(source_rows):
        row = _exact(
            raw_source,
            {"source", "label", "destination_ids", "enabled"},
            f"sources[{index}]",
        )
        if type(row["enabled"]) is not bool:
            raise DragonDenError(f"sources[{index}].enabled must be boolean")
        if not row["enabled"]:
            continue
        source = normalize_public_source(row["source"])
        source_key = source.casefold()
        if source_key in sources:
            raise DragonDenError(f"sources[{index}].source is duplicated")
        extra = row["destination_ids"]
        if type(extra) is not list or len(extra) > MAX_DESTINATIONS:
            raise DragonDenError(f"sources[{index}].destination_ids is invalid")
        destination_ids: list[str] = []
        for destination_index, key in enumerate(extra):
            if type(key) is not str or key not in destinations or key in destination_ids:
                raise DragonDenError(
                    f"sources[{index}].destination_ids[{destination_index}] is invalid"
                )
            destination_ids.append(key)
        sources[source_key] = SourceRoute(
            source=source,
            label=_text(row["label"], f"sources[{index}].label", maximum=120),
            destination_ids=tuple(destination_ids),
        )
    if not sources:
        raise DragonDenError("routes.sources has no enabled public source")
    return DragonDenRoutes(
        destinations=destinations,
        catch_all_destination_ids=tuple(catch_all_ids),
        sources=sources,
    )


def source_from_chat(chat: Any) -> str:
    """Resolve an incoming Telegram chat to an allowlist-compatible source."""

    username = getattr(chat, "username", None)
    if not isinstance(username, str) or not username:
        raise DragonDenError("raw mirror refuses a non-public source chat")
    return normalize_public_source(f"@{username}")


def canonical_observed_at(value: Any) -> str:
    """Accept the Telegram timestamp shape and return canonical UTC seconds."""

    from datetime import datetime, timezone

    if not isinstance(value, datetime):
        raise DragonDenError("message date is missing")
    if value.tzinfo is None or value.utcoffset() is None:
        raise DragonDenError("message date is timezone-free")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def receipt_id(
    *, source_chat_id: str, message_id: int, revision: str, destination_id: str,
) -> str:
    if not source_chat_id or not 0 < message_id <= 2**63 - 1:
        raise DragonDenError("message identity is invalid")
    material = "\0".join(
        (source_chat_id, str(message_id), revision, destination_id)
    ).encode("utf-8")
    return f"whisper-{hashlib.sha256(material).hexdigest()[:24]}"


def disclaimer_text(batch: DeliveryBatch) -> str:
    """Return the mandatory per-forward warning; operators cannot weaken it."""

    first = batch.first
    edition = " · SOURCE EDIT" if first.revision else ""
    album = f" · {len(batch.deliveries)}-POST ALBUM" if len(batch.deliveries) > 1 else ""
    username = first.source.removeprefix("@")
    original = f"https://t.me/{username}/{first.source_message_id}"
    return (
        f"⚠️ UNVERIFIED RAW FORWARD{edition}{album}\n"
        f"Receipt: {batch.receipt_label}\n"
        f"Original: {original}\n\n"
        "This is an automatic, unreviewed forward from an allowlisted public "
        "Telegram source. It may be false, incomplete, manipulated, illegal, "
        "or malicious. Palimpsest does not endorse it. Do not treat it as "
        "evidence, contact named people, send money, or open links/files "
        "without independent verification. ScamShield analysis runs separately "
        "and never blocks this raw mirror."
    )


_OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS deliveries (
    receipt_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_chat_id TEXT NOT NULL,
    source_message_id INTEGER NOT NULL,
    revision TEXT NOT NULL,
    media_group_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    destination_chat_id TEXT NOT NULL,
    status TEXT NOT NULL,
    ready_at INTEGER NOT NULL,
    next_attempt_at INTEGER NOT NULL,
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    header_message_id INTEGER,
    forwarded_message_ids_json TEXT NOT NULL DEFAULT '[]',
    last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(source_chat_id, source_message_id, revision, destination_id)
);
CREATE INDEX IF NOT EXISTS deliveries_due
    ON deliveries(status, next_attempt_at, ready_at, created_at);
CREATE INDEX IF NOT EXISTS deliveries_album
    ON deliveries(source_chat_id, destination_id, media_group_id, status);
"""


class DragonDenOutbox:
    """A private SQLite queue containing references, not Telegram content."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(_OUTBOX_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def enqueue(
        self,
        *,
        source: str,
        source_chat_id: str,
        source_message_id: int,
        revision: str,
        media_group_id: str,
        observed_at: str,
        destinations: Iterable[Destination],
        now: int | None = None,
        album_wait_seconds: int = 2,
    ) -> tuple[str, ...]:
        normalized_source = normalize_public_source(source)
        if not source_chat_id or not 0 < source_message_id <= 2**63 - 1:
            raise DragonDenError("message identity is invalid")
        if revision and not _ISO_UTC.fullmatch(revision):
            raise DragonDenError("revision must be empty or canonical UTC")
        if not _ISO_UTC.fullmatch(observed_at):
            raise DragonDenError("observed_at must be canonical UTC")
        if not 0 <= album_wait_seconds <= 30:
            raise DragonDenError("album wait must be in [0, 30]")
        timestamp = int(time.time()) if now is None else int(now)
        ready_at = timestamp + (album_wait_seconds if media_group_id else 0)
        rows = tuple(destinations)
        if not rows:
            return ()
        receipts: list[str] = []
        with self.conn:
            for destination in rows:
                item_id = receipt_id(
                    source_chat_id=source_chat_id,
                    message_id=source_message_id,
                    revision=revision,
                    destination_id=destination.id,
                )
                receipts.append(item_id)
                self.conn.execute(
                    """INSERT OR IGNORE INTO deliveries (
                           receipt_id, source, source_chat_id, source_message_id,
                           revision, media_group_id, observed_at, destination_id,
                           destination_chat_id, status, ready_at, next_attempt_at,
                           created_at, updated_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)""",
                    (
                        item_id, normalized_source, source_chat_id, source_message_id,
                        revision, str(media_group_id or ""), observed_at,
                        destination.id, destination.chat_id, ready_at, timestamp,
                        timestamp, timestamp,
                    ),
                )
                if media_group_id:
                    self.conn.execute(
                        """UPDATE deliveries
                           SET ready_at = MAX(ready_at, ?), updated_at = ?
                           WHERE source_chat_id = ? AND destination_id = ?
                             AND media_group_id = ? AND revision = ?
                             AND status IN ('PENDING', 'RETRY')""",
                        (
                            ready_at, timestamp, source_chat_id, destination.id,
                            str(media_group_id), revision,
                        ),
                    )
        return tuple(receipts)

    @staticmethod
    def _delivery(row: sqlite3.Row | tuple[Any, ...]) -> Delivery:
        return Delivery(
            receipt_id=str(row[0]),
            source=str(row[1]),
            source_chat_id=str(row[2]),
            source_message_id=int(row[3]),
            revision=str(row[4]),
            media_group_id=str(row[5]),
            observed_at=str(row[6]),
            destination_id=str(row[7]),
            destination_chat_id=str(row[8]),
            attempts=int(row[9]),
            header_message_id=(int(row[10]) if row[10] is not None else None),
        )

    def claim(
        self,
        *,
        now: int | None = None,
        lease_seconds: int = 120,
    ) -> DeliveryBatch | None:
        timestamp = int(time.time()) if now is None else int(now)
        if not 10 <= lease_seconds <= 3600:
            raise DragonDenError("delivery lease must be in [10, 3600]")
        columns = (
            "receipt_id, source, source_chat_id, source_message_id, revision, "
            "media_group_id, observed_at, destination_id, destination_chat_id, "
            "attempts, header_message_id"
        )
        with self.conn:
            self.conn.execute(
                """UPDATE deliveries SET status = 'RETRY', lease_until = 0,
                          next_attempt_at = ?, updated_at = ?
                   WHERE status = 'SENDING' AND lease_until <= ?""",
                (timestamp, timestamp, timestamp),
            )
            first = self.conn.execute(
                f"""SELECT {columns} FROM deliveries
                    WHERE status IN ('PENDING', 'RETRY')
                      AND ready_at <= ? AND next_attempt_at <= ?
                    ORDER BY observed_at, created_at, source_message_id
                    LIMIT 1""",
                (timestamp, timestamp),
            ).fetchone()
            if first is None:
                return None
            seed = self._delivery(first)
            if seed.media_group_id:
                rows = self.conn.execute(
                    f"""SELECT {columns} FROM deliveries
                        WHERE source_chat_id = ? AND destination_id = ?
                          AND media_group_id = ? AND revision = ?
                          AND status IN ('PENDING', 'RETRY')
                          AND ready_at <= ? AND next_attempt_at <= ?
                        ORDER BY source_message_id LIMIT ?""",
                    (
                        seed.source_chat_id, seed.destination_id,
                        seed.media_group_id, seed.revision, timestamp, timestamp,
                        MAX_ALBUM_MESSAGES,
                    ),
                ).fetchall()
            else:
                rows = [first]
            deliveries = tuple(self._delivery(row) for row in rows)
            ids = [item.receipt_id for item in deliveries]
            placeholders = ",".join("?" for _ in ids)
            cursor = self.conn.execute(
                f"""UPDATE deliveries
                    SET status = 'SENDING', lease_until = ?, attempts = attempts + 1,
                        updated_at = ?
                    WHERE receipt_id IN ({placeholders})
                      AND status IN ('PENDING', 'RETRY')""",
                (timestamp + lease_seconds, timestamp, *ids),
            )
            if cursor.rowcount != len(ids):
                raise DragonDenError("delivery claim lost an atomicity race")
        claimed = tuple(
            Delivery(**{**item.__dict__, "attempts": item.attempts + 1})
            for item in deliveries
        )
        return DeliveryBatch(claimed)

    def record_header(
        self, batch: DeliveryBatch, message_id: int, *, now: int | None = None,
    ) -> None:
        if not 0 < message_id <= 2**63 - 1:
            raise DragonDenError("header message ID is invalid")
        self._update_batch(
            batch,
            "header_message_id = ?, updated_at = ?",
            (message_id, int(time.time()) if now is None else int(now)),
            required_status="SENDING",
        )

    def complete(
        self,
        batch: DeliveryBatch,
        forwarded_message_ids: Iterable[int],
        *,
        now: int | None = None,
    ) -> None:
        message_ids = list(forwarded_message_ids)
        if (
            len(message_ids) != len(batch.deliveries)
            or any(type(value) is not int or value <= 0 for value in message_ids)
        ):
            raise DragonDenError("forward result does not match the claimed batch")
        self._update_batch(
            batch,
            "status = 'COMPLETE', lease_until = 0, "
            "forwarded_message_ids_json = ?, last_error = '', updated_at = ?",
            (
                json.dumps(message_ids, separators=(",", ":")),
                int(time.time()) if now is None else int(now),
            ),
            required_status="SENDING",
        )

    def retry(
        self,
        batch: DeliveryBatch,
        error_code: str,
        *,
        retry_after: int | None = None,
        now: int | None = None,
        max_attempts: int = 12,
    ) -> None:
        timestamp = int(time.time()) if now is None else int(now)
        code = _text(error_code, "delivery error code", maximum=120)
        attempts = max(item.attempts for item in batch.deliveries)
        if attempts >= max_attempts:
            status = "DEAD"
            next_attempt = timestamp
        else:
            status = "RETRY"
            backoff = min(3600, 2 ** min(attempts, 11))
            next_attempt = timestamp + max(backoff, int(retry_after or 0))
        self._update_batch(
            batch,
            "status = ?, lease_until = 0, next_attempt_at = ?, "
            "last_error = ?, updated_at = ?",
            (status, next_attempt, code, timestamp),
            required_status="SENDING",
        )

    def unforwardable(
        self, batch: DeliveryBatch, error_code: str, *, now: int | None = None,
    ) -> None:
        self._update_batch(
            batch,
            "status = 'UNFORWARDABLE', lease_until = 0, last_error = ?, updated_at = ?",
            (
                _text(error_code, "delivery error code", maximum=120),
                int(time.time()) if now is None else int(now),
            ),
            required_status="SENDING",
        )

    def _update_batch(
        self,
        batch: DeliveryBatch,
        assignment: str,
        values: tuple[Any, ...],
        *,
        required_status: str,
    ) -> None:
        ids = [item.receipt_id for item in batch.deliveries]
        if not ids:
            raise DragonDenError("delivery batch is empty")
        placeholders = ",".join("?" for _ in ids)
        with self.conn:
            cursor = self.conn.execute(
                f"""UPDATE deliveries SET {assignment}
                    WHERE receipt_id IN ({placeholders}) AND status = ?""",
                (*values, *ids, required_status),
            )
            if cursor.rowcount != len(ids):
                raise DragonDenError("delivery batch is no longer in the expected state")

    def status_counts(self) -> dict[str, int]:
        return {
            str(status): int(count)
            for status, count in self.conn.execute(
                "SELECT status, COUNT(*) FROM deliveries GROUP BY status"
            )
        }


__all__ = [
    "Delivery",
    "DeliveryBatch",
    "Destination",
    "DragonDenError",
    "DragonDenOutbox",
    "DragonDenRoutes",
    "MAX_ROUTES_BYTES",
    "ROUTES_SCHEMA",
    "SourceRoute",
    "canonical_observed_at",
    "disclaimer_text",
    "load_routes",
    "normalize_public_source",
    "receipt_id",
    "source_from_chat",
]
