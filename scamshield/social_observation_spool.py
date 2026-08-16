"""Private Telegram spool and exact Palimpsest social-observation export.

The monitor calls :meth:`SocialObservationSpool.capture` at its existing
pre-analysis Telethon seam.  This database is separate from ScamShield's
analysis receipts and history cursor, so failure here never gates the monitor.

The local registry mirrors every public Palimpsest source.  A Telegram row may
add one collection-only ``telegram_handle``; that field is excluded from the
    public registry digest and output. Telegram numeric peer IDs and standalone
    native identity fields remain private; the public post number appears only
    inside the canonical Telegram permalink.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import threading
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from .telegram_sources import normalize_source_reference


log = logging.getLogger(__name__)

REGISTRY_SCHEMA_VERSION = "palimpsest-social-sources.v1"
EXPORT_SCHEMA_VERSION = "palimpsest-social-observations.v1"
LEDGER_SCHEMA_VERSION = "palimpsest-social-observation-version.v1"
SIGNATURE_SCHEMA_VERSION = "palimpsest-social-observations-signature.v1"
SOURCE_REGISTRY_URL = "https://palimpsest.info/config/social_sources.json"
SCOPE = "bounded-registry-not-global"
RELATION = "attributed-source-report-not-corroboration"
RIGHTS_POLICY = "metadata-bounded-excerpt-link-only"
COLLECTION_POLICY = "public-or-operator-authorized"

TITLE_LIMIT = 240
EXCERPT_LIMIT = 320
MAX_REGISTRY_BYTES = 1_000_000
MAX_SOURCES = 256
MAX_RELATED_URLS = 16
MAX_URL_LENGTH = 2_048
MAX_LATEST_BYTES = 16 * 1024 * 1024
# Keep terminal observation payloads below the wire-format cap with enough
# headroom for bounded coverage receipts and the fixed snapshot envelope. This
# is enforced before a new terminal revision is appended, so reaching the v1
# limit revokes freshness without making the latest view unpublishable.
MAX_LATEST_PAYLOAD_BYTES = 12 * 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_GENERATIONS = 4
DEFAULT_MAX_STALENESS_SECONDS = 15 * 60
DEFAULT_DB_PATH = "/var/lib/scamshield/social/social-observations.db"
DEFAULT_REGISTRY_PATH = "/etc/scamshield/palimpsest-social-sources.json"
DEFAULT_OUTPUT_PATH = "/var/lib/scamshield/social-export"

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,79}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OBSERVATION_ID = re.compile(r"^social-[0-9a-f]{32}$")
_VERSION_ID = re.compile(r"^socialv-[0-9a-f]{32}$")
_NATIVE_CHANNEL_PEER_ID = re.compile(r"^-100[0-9]{1,16}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_TELEGRAM_PERMALINK = re.compile(
    r"^https://t\.me/([a-z0-9_]{1,64})/([1-9][0-9]{0,19})/$"
)
_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_URL = re.compile(r"https://[^\s<>\[\]{}\"']+", re.IGNORECASE)
_INLINE_URI = re.compile(
    r"(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>\[\]{}\"']+",
    re.IGNORECASE,
)
_BARE_DOMAIN_URI = re.compile(
    r"(?<![a-z0-9_@])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?::[0-9]{1,5})?(?:[/?#][^\s<>\[\]{}\"']*)?",
    re.IGNORECASE,
)
_CHINA_RELEVANCE_GATES: Mapping[str, tuple[str, ...]] = {
    # Intentionally bounded and auditable. Publisher identity alone is never
    # evidence that a mixed CGTN channel post is about China.
    "cgtn-telegram": (
        "beijing",
        "china",
        "chinese",
        "communist party of china",
        "guangdong",
        "hong kong",
        "macao",
        "macau",
        "renminbi",
        "shanghai",
        "shenzhen",
        "taiwan",
        "tibet",
        "xinjiang",
        "yuan",
        "中国",
        "中國",
        "北京",
        "上海",
        "深圳",
        "香港",
        "澳门",
        "澳門",
        "台湾",
        "台灣",
        "新疆",
        "西藏",
    ),
}
_SOURCE_TYPE_PLATFORM = {
    "telegram_channel": "telegram",
    "instagram_professional": "instagram",
    "instagram_hashtag": "instagram",
}
_CONTENT_TYPES = {
    "text",
    "link",
    "image",
    "video",
    "audio",
    "document",
    "carousel",
    "other",
    "unavailable",
}
_REGISTRY_KEYS = {"schema_version", "scope", "relation", "sources"}
_PUBLIC_SOURCE_KEYS = {
    "id",
    "name",
    "source_type",
    "platform",
    "independence_group",
    "article_hosts",
    "collection_policy",
    "rights_policy",
}
_LOCAL_TELEGRAM_SOURCE_KEYS = _PUBLIC_SOURCE_KEYS | {"telegram_handle"}
_OBSERVATION_FIELDS = {
    "observation_id",
    "version_id",
    "supersedes_version_id",
    "platform",
    "source_id",
    "source_name",
    "source_type",
    "independence_group",
    "relation",
    "rights_policy",
    "permalink",
    "published_at",
    "first_observed_at",
    "title",
    "excerpt",
    "content_type",
    "content_sha256",
    "state",
    "china_relevance_labels",
    "related_urls",
}
_VERSION_PAYLOAD_FIELDS = tuple(
    sorted(
        _OBSERVATION_FIELDS
        - {"version_id", "first_observed_at"}
    )
)
_REVISION_CONTENT_FIELDS = tuple(
    field for field in _VERSION_PAYLOAD_FIELDS if field != "supersedes_version_id"
)


class SocialObservationError(ValueError):
    """Raised when the social-observation security contract is invalid."""


class TotalCollectionFailure(RuntimeError):
    """Raised when every configured Telegram acquisition is failing."""


class LedgerCapacityExceeded(SocialObservationError):
    """Raised before append-only history can exceed its v1 artifact cap."""


class LatestCapacityExceeded(SocialObservationError):
    """Raised before terminal observations can exceed the v1 snapshot cap."""


class PublicationCommittedError(RuntimeError):
    """Raised when ``current`` switched but its directory fsync did not finish."""


@dataclass(frozen=True)
class SocialPublisher:
    source_id: str
    source_name: str
    source_type: str
    platform: str
    independence_group: str
    article_hosts: tuple[str, ...]
    collection_policy: str
    rights_policy: str
    telegram_handle: str | None = None

    def public_document(self) -> dict[str, Any]:
        return {
            "id": self.source_id,
            "name": self.source_name,
            "source_type": self.source_type,
            "platform": self.platform,
            "independence_group": self.independence_group,
            "article_hosts": list(self.article_hosts),
            "collection_policy": self.collection_policy,
            "rights_policy": self.rights_policy,
        }


@dataclass(frozen=True)
class SocialSourceRegistry:
    sources: tuple[SocialPublisher, ...]
    digest: str

    @property
    def telegram_sources(self) -> tuple[SocialPublisher, ...]:
        return tuple(
            source
            for source in self.sources
            if source.platform == "telegram" and source.telegram_handle is not None
        )

    @property
    def by_handle(self) -> dict[str, SocialPublisher]:
        return {
            source.telegram_handle.casefold(): source
            for source in self.telegram_sources
            if source.telegram_handle is not None
        }

    @property
    def by_id(self) -> dict[str, SocialPublisher]:
        return {source.source_id: source for source in self.sources}


@dataclass(frozen=True)
class CaptureResult:
    status: str
    observation_id: str = ""
    version_id: str = ""
    created_version: bool = False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise SocialObservationError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _canonical_json(document: Any) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(document: bytes) -> str:
    return hashlib.sha256(document).hexdigest()


def _stable_id(prefix: str, payload: Any) -> str:
    return f"{prefix}-{_sha256(_canonical_json(payload))[:32]}"


def _utc_iso(value: datetime | None = None) -> str:
    current = datetime.now(timezone.utc) if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    return current.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(value: Any, *, fallback: datetime | None = None) -> str:
    if not isinstance(value, datetime):
        value = datetime.now(timezone.utc) if fallback is None else fallback
    return _utc_iso(value)


def _safe_text(
    value: Any,
    *,
    name: str,
    limit: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str:
        raise SocialObservationError(f"{name} must be text")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized) > limit or (not allow_empty and not normalized.strip()):
        raise SocialObservationError(f"{name} is not bounded text")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in normalized):
        raise SocialObservationError(f"{name} contains unsafe Unicode")
    return normalized


def _identifier(value: Any, *, name: str) -> str:
    text = _safe_text(value, name=name, limit=80)
    if not _IDENTIFIER.fullmatch(text):
        raise SocialObservationError(f"{name} must be a lowercase identifier")
    return text


def _normalize_host(value: Any) -> str:
    if type(value) is not str or value != value.lower() or not _HOST.fullmatch(value):
        raise SocialObservationError("article_hosts must be exact lowercase DNS hostnames")
    if value == "palimpsest.info" or value.endswith(".palimpsest.info"):
        raise SocialObservationError("article_hosts must not target Palimpsest")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise SocialObservationError("article_hosts must not contain IP addresses")


def load_social_source_registry(path: str | Path) -> SocialSourceRegistry:
    """Load local bindings and compute the exact public-registry digest.

    Non-Telegram rows are mirrored without local fields and receive explicit
    ``not-attempted`` coverage receipts from this adapter.  Telegram rows may
    omit ``telegram_handle`` to remain mirrored but intentionally uncollected.
    """

    try:
        encoded = Path(path).read_bytes()
    except OSError as exc:
        raise SocialObservationError("social source registry is unreadable") from exc
    if len(encoded) > MAX_REGISTRY_BYTES:
        raise SocialObservationError("social source registry is too large")
    try:
        document = json.loads(encoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SocialObservationError("social source registry is not valid JSON") from exc
    if type(document) is not dict or set(document) != _REGISTRY_KEYS:
        raise SocialObservationError("social source registry has unexpected fields")
    if document["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise SocialObservationError("unsupported social source registry schema")
    if document["scope"] != SCOPE or document["relation"] != RELATION:
        raise SocialObservationError("social source registry broadens the evidence boundary")
    rows = document["sources"]
    if type(rows) is not list or len(rows) > MAX_SOURCES:
        raise SocialObservationError(f"sources must contain at most {MAX_SOURCES} rows")

    sources: list[SocialPublisher] = []
    seen_ids: set[str] = set()
    seen_handles: set[str] = set()
    for row in rows:
        if type(row) is not dict:
            raise SocialObservationError("social source row must be an object")
        source_type = row.get("source_type")
        expected_fields = (
            _LOCAL_TELEGRAM_SOURCE_KEYS
            if source_type == "telegram_channel" and "telegram_handle" in row
            else _PUBLIC_SOURCE_KEYS
        )
        if set(row) != expected_fields:
            raise SocialObservationError("social source row has unexpected fields")
        if source_type not in _SOURCE_TYPE_PLATFORM:
            raise SocialObservationError("source_type is unsupported")
        platform = row["platform"]
        if platform != _SOURCE_TYPE_PLATFORM[source_type]:
            raise SocialObservationError("platform does not match source_type")
        source_id = _identifier(row["id"], name="source id")
        source_name = _safe_text(row["name"], name="source name", limit=120)
        independence_group = _identifier(
            row["independence_group"], name="independence group"
        )
        article_hosts_value = row["article_hosts"]
        if type(article_hosts_value) is not list or len(article_hosts_value) > 64:
            raise SocialObservationError("article_hosts must be a bounded array")
        article_hosts = tuple(_normalize_host(value) for value in article_hosts_value)
        if list(article_hosts) != sorted(set(article_hosts)):
            raise SocialObservationError("article_hosts must be sorted and unique")
        if row["collection_policy"] != COLLECTION_POLICY:
            raise SocialObservationError("collection_policy broadens authorization")
        if row["rights_policy"] != RIGHTS_POLICY:
            raise SocialObservationError("rights_policy broadens publication")
        telegram_handle: str | None = None
        if "telegram_handle" in row:
            try:
                telegram_handle = normalize_source_reference(row["telegram_handle"])
            except ValueError as exc:
                raise SocialObservationError(
                    "telegram_handle must be a public Telegram username"
                ) from exc
            if not telegram_handle.startswith("@"):
                raise SocialObservationError(
                    "telegram_handle must be a public Telegram username"
                )
            if telegram_handle.casefold() in seen_handles:
                raise SocialObservationError("telegram_handle must be unique")
            seen_handles.add(telegram_handle.casefold())
        if source_id in seen_ids:
            raise SocialObservationError("source id must be unique")
        seen_ids.add(source_id)
        sources.append(
            SocialPublisher(
                source_id=source_id,
                source_name=source_name,
                source_type=source_type,
                platform=platform,
                independence_group=independence_group,
                article_hosts=article_hosts,
                collection_policy=COLLECTION_POLICY,
                rights_policy=RIGHTS_POLICY,
                telegram_handle=telegram_handle,
            )
        )
    if [source.source_id for source in sources] != sorted(seen_ids):
        raise SocialObservationError("sources must be sorted by id")

    # Hash the exact public projection of the parsed document.  Rebuilding the
    # rows from normalized dataclasses can silently produce a different digest
    # from Palimpsest for valid-but-non-NFC source text.
    public_registry = {
        "schema_version": document["schema_version"],
        "scope": document["scope"],
        "relation": document["relation"],
        "sources": [
            {key: value for key, value in row.items() if key != "telegram_handle"}
            for row in rows
        ],
    }
    return SocialSourceRegistry(
        tuple(sources),
        _sha256(_canonical_json(public_registry)),
    )


def validate_public_registry_projection(
    local_path: str | Path,
    public_path: str | Path,
) -> str:
    """Require the collection registry to project to the deployed public file."""

    try:
        public_encoded = Path(public_path).read_bytes()
    except OSError as exc:
        raise SocialObservationError("public social registry is unreadable or invalid") from exc
    if len(public_encoded) > MAX_REGISTRY_BYTES:
        raise SocialObservationError("public social registry is too large")
    try:
        public_document = json.loads(
            public_encoded, object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SocialObservationError(
            "public social registry is unreadable or invalid"
        ) from exc
    public_rows = (
        public_document.get("sources") if type(public_document) is dict else None
    )
    if type(public_rows) is not list or any(
        type(row) is not dict or "telegram_handle" in row for row in public_rows
    ):
        raise SocialObservationError("public social registry contains collection-only fields")
    local = load_social_source_registry(local_path)
    public = load_social_source_registry(public_path)
    if local.digest != public.digest:
        raise SocialObservationError(
            "local social registry projection differs from Palimpsest"
        )
    return local.digest


def _clean_source_text(value: Any) -> str:
    if type(value) is not str:
        return ""
    normalized = unicodedata.normalize("NFC", value).replace("\x00", "")
    # URLs have their own strict, allowlisted output field.  Never duplicate a
    # raw URI into the human-readable title/excerpt: query strings and userinfo
    # are common places for credentials, and truncation is not redaction.
    without_uris = _BARE_DOMAIN_URI.sub(
        "[link]", _INLINE_URI.sub("[link]", normalized)
    )
    cleaned = " ".join(without_uris.split())
    return "".join(
        char
        for char in cleaned
        if unicodedata.category(char) not in {"Cc", "Cf", "Cs"}
    )


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def _base_content_type(message: Any) -> str:
    if getattr(message, "photo", None) is not None:
        return "image"
    if getattr(message, "video", None) is not None:
        return "video"
    if getattr(message, "audio", None) is not None or getattr(message, "voice", None) is not None:
        return "audio"
    document = getattr(message, "document", None)
    if document is not None:
        mime_type = str(getattr(document, "mime_type", "")).lower()
        if mime_type.startswith("video/"):
            return "video"
        if mime_type.startswith("audio/"):
            return "audio"
        if mime_type.startswith("image/"):
            return "image"
        return "document"
    media = getattr(message, "media", None)
    if media is not None:
        name = type(media).__name__.casefold()
        if "photo" in name:
            return "image"
        if "document" in name:
            return "document"
        return "other"
    return "text"


def _allowed_article_url(value: str, article_hosts: Sequence[str]) -> str | None:
    if type(value) is not str:
        return None
    candidate = value.rstrip(".,;:!?)]}")
    if (
        not candidate
        or len(candidate) > MAX_URL_LENGTH
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in candidate)
    ):
        return None
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.casefold() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or host not in article_hosts
        or not parsed.path.startswith("/")
        or len(parsed.path) > 1_500
    ):
        return None
    decoded_paths: list[str] = []
    decoded_path = parsed.path
    try:
        # Inspect nested escaping as well as the URL's visible representation;
        # double-encoding must not turn a bearer value into an apparent slug.
        for _ in range(3):
            decoded_path = unquote(decoded_path, errors="strict")
            if decoded_paths and decoded_path == decoded_paths[-1]:
                break
            decoded_paths.append(decoded_path)
    except (UnicodeDecodeError, ValueError):
        return None
    if any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        for candidate_path in decoded_paths
        for char in candidate_path
    ):
        return None
    if decoded_paths and re.search(r"%[0-9A-Fa-f]{2}", decoded_paths[-1]):
        # More than three nested escaping layers are not a plausible canonical
        # article path and can conceal an otherwise detectable credential.
        return None
    # Credential-like opaque path components are not meaningful article URLs.
    # Reject rather than publish them; ordinary prose slugs contain separators
    # and have substantially lower character entropy.
    for candidate_path in decoded_paths:
        for segment in candidate_path.split("/"):
            if len(segment) < 24:
                continue
            # JWTs and similar bearer artefacts use three opaque base64url
            # chunks. A dot-separated credential must never become part of the
            # public URL even if each chunk is short.
            if re.fullmatch(
                r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                segment,
            ):
                return None
            if re.fullmatch(r"[0-9a-fA-F]{24,}", segment) or re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
                segment,
            ):
                return None
            if re.fullmatch(r"[A-Za-z0-9_=-]{24,}", segment):
                frequencies = {
                    char: segment.count(char) / len(segment) for char in set(segment)
                }
                entropy = -sum(
                    value * math.log2(value) for value in frequencies.values()
                )
                if entropy >= 3.75:
                    return None
    # Query values are neither needed for attribution nor safe to export.  The
    # canonical public URL always drops the complete query and fragment.
    return urlunsplit(("https", host, parsed.path or "/", "", ""))


def _related_urls(
    message: Any,
    raw_text: str,
    article_hosts: Sequence[str],
) -> tuple[str, ...]:
    candidates = list(_URL.findall(raw_text))
    for entity in getattr(message, "entities", None) or ():
        url = getattr(entity, "url", None)
        if type(url) is str:
            candidates.append(url)
    webpage = getattr(getattr(message, "media", None), "webpage", None)
    webpage_url = getattr(webpage, "url", None)
    if type(webpage_url) is str:
        candidates.append(webpage_url)
    accepted = {
        normalized
        for candidate in candidates
        if (normalized := _allowed_article_url(candidate, article_hosts)) is not None
    }
    return tuple(sorted(accepted)[:MAX_RELATED_URLS])


def _is_china_relevant(
    publisher: SocialPublisher,
    raw_text: str,
    related_urls: Sequence[str],
) -> bool:
    terms = _CHINA_RELEVANCE_GATES.get(publisher.source_id)
    if terms is None:
        return True
    # Relevance must not be smuggled through a query/fragment or userinfo. Use
    # the same URI-redacted prose published in excerpts, then add only paths
    # from URLs that passed the exact article-host/privacy allowlist.
    candidate = unicodedata.normalize("NFC", _clean_source_text(raw_text)).casefold()
    for url in related_urls:
        candidate += " " + unquote(urlsplit(url).path).casefold()
    for term in terms:
        folded = term.casefold()
        if any("\u4e00" <= char <= "\u9fff" for char in folded):
            if folded in candidate:
                return True
        elif re.search(
            rf"(?<![a-z0-9]){re.escape(folded)}(?![a-z0-9])",
            candidate,
        ):
            return True
    return False


def _message_identity(message: Any) -> int | None:
    value = getattr(message, "id", None)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= 2_147_483_647
    ):
        return None
    return value


def _source_reference(source: Any) -> str | None:
    try:
        reference = normalize_source_reference(getattr(source, "reference", ""))
    except ValueError:
        return None
    return reference if reference.startswith("@") else None


def _validated_timestamp(value: Any, *, name: str) -> str:
    if type(value) is not str or not _TIMESTAMP.fullmatch(value):
        raise SocialObservationError(f"{name} is not a canonical timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SocialObservationError(f"{name} is not a real timestamp") from exc
    return value


def _validate_sanitized_observation(
    value: Any,
    registry: SocialSourceRegistry,
    *,
    native_peer_id: str,
    native_message_id: int,
) -> dict[str, Any]:
    """Reject SQLite drift before any bytes reach an authenticated bundle."""

    if type(value) is not dict or set(value) != _OBSERVATION_FIELDS:
        raise SocialObservationError("stored social observation fields changed")
    if _NATIVE_CHANNEL_PEER_ID.fullmatch(native_peer_id) is None:
        raise SocialObservationError("stored native channel identity is invalid")
    if type(value["observation_id"]) is not str or not _OBSERVATION_ID.fullmatch(
        value["observation_id"]
    ):
        raise SocialObservationError("stored observation_id is invalid")
    if type(value["version_id"]) is not str or not _VERSION_ID.fullmatch(
        value["version_id"]
    ):
        raise SocialObservationError("stored version_id is invalid")
    previous = value["supersedes_version_id"]
    if previous is not None and (
        type(previous) is not str or not _VERSION_ID.fullmatch(previous)
    ):
        raise SocialObservationError("stored supersedes_version_id is invalid")
    publisher = registry.by_id.get(value["source_id"])
    if publisher is None:
        raise SocialObservationError("stored source is outside the current registry")
    locked = {
        "platform": publisher.platform,
        "source_name": publisher.source_name,
        "source_type": publisher.source_type,
        "independence_group": publisher.independence_group,
        "relation": RELATION,
        "rights_policy": publisher.rights_policy,
    }
    if any(value[field] != expected for field, expected in locked.items()):
        raise SocialObservationError("stored observation changes locked source metadata")
    permalink = value["permalink"]
    match = _TELEGRAM_PERMALINK.fullmatch(permalink) if type(permalink) is str else None
    if publisher.platform != "telegram" or match is None:
        raise SocialObservationError("stored Telegram permalink is not canonical")
    if publisher.telegram_handle is not None and (
        match.group(1) != publisher.telegram_handle.removeprefix("@").casefold()
    ):
        raise SocialObservationError("stored permalink changes the reviewed handle")
    if int(match.group(2)) != native_message_id:
        raise SocialObservationError("stored permalink changes the native message identity")
    expected_observation = _stable_id(
        "social",
        {
            "platform": "telegram",
            "source_id": publisher.source_id,
            "native_id": f"{native_peer_id}:{native_message_id}",
        },
    )
    if value["observation_id"] != expected_observation:
        raise SocialObservationError("stored observation_id does not match private identity")
    published = _validated_timestamp(value["published_at"], name="published_at")
    observed = _validated_timestamp(value["first_observed_at"], name="first_observed_at")
    if published > observed:
        raise SocialObservationError("stored observation predates publication")
    state = value["state"]
    title = _safe_text(
        value["title"],
        name="title",
        limit=TITLE_LIMIT,
        allow_empty=state == "tombstone",
    )
    _safe_text(value["excerpt"], name="excerpt", limit=EXCERPT_LIMIT, allow_empty=True)
    if state not in {"published", "edited", "tombstone"}:
        raise SocialObservationError("stored observation state is unsupported")
    if value["content_type"] not in _CONTENT_TYPES:
        raise SocialObservationError("stored content_type is unsupported")
    if type(value["content_sha256"]) is not str or not _SHA256.fullmatch(
        value["content_sha256"]
    ):
        raise SocialObservationError("stored content_sha256 is invalid")
    labels = value["china_relevance_labels"]
    if (
        type(labels) is not list
        or not labels
        or len(labels) > 12
        or labels != sorted(set(labels))
        or any(type(label) is not str or not _IDENTIFIER.fullmatch(label) for label in labels)
    ):
        raise SocialObservationError("stored China relevance labels are not canonical")
    urls = value["related_urls"]
    if type(urls) is not list or len(urls) > MAX_RELATED_URLS or urls != sorted(set(urls)):
        raise SocialObservationError("stored related URLs are not canonical")
    if any(_allowed_article_url(url, publisher.article_hosts) != url for url in urls):
        raise SocialObservationError("stored related URL left the publisher allowlist")
    if state == "tombstone":
        if title or value["excerpt"] or value["content_type"] != "unavailable" or urls:
            raise SocialObservationError("stored tombstone retains removed content")
    elif not title or value["content_type"] == "unavailable":
        raise SocialObservationError("stored published content is incomplete")
    expected_version = _stable_id(
        "socialv",
        {field: value[field] for field in _VERSION_PAYLOAD_FIELDS},
    )
    if value["version_id"] != expected_version:
        raise SocialObservationError("stored version_id does not match sanitized metadata")
    return value


def _validate_revision_chain(
    versions: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    terminals: dict[str, Mapping[str, Any]] = {}
    seen_versions: set[str] = set()
    for row in versions:
        version_id = row["version_id"]
        if version_id in seen_versions:
            raise SocialObservationError("stored ledger duplicates a version_id")
        previous = terminals.get(row["observation_id"])
        expected_previous = previous["version_id"] if previous is not None else None
        if row["supersedes_version_id"] != expected_previous:
            raise SocialObservationError("stored ledger breaks its revision chain")
        if previous is not None and row["first_observed_at"] < previous["first_observed_at"]:
            raise SocialObservationError("stored ledger moves observation time backwards")
        terminals[row["observation_id"]] = row
        seen_versions.add(version_id)
    return terminals


def _serialized(method):
    """Serialize access to one SQLite connection used by worker threads."""

    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return locked


class SocialObservationSpool:
    """Append-only private spool for double-allowlisted publisher posts."""

    def __init__(
        self,
        db_path: str | Path,
        registry_path: str | Path,
        *,
        read_only: bool = False,
        max_staleness_seconds: int | None = None,
    ):
        self._lock = threading.RLock()
        self.db_path = Path(db_path)
        self.registry_path = Path(registry_path)
        self.registry = load_social_source_registry(self.registry_path)
        self.read_only = read_only
        if max_staleness_seconds is not None and not 60 <= max_staleness_seconds <= 86_400:
            raise SocialObservationError("social export staleness must be 60..86400 seconds")
        self.max_staleness_seconds = max_staleness_seconds
        if read_only:
            uri = f"file:{self.db_path.resolve()}?mode=ro"
            self.conn = sqlite3.connect(
                uri, uri=True, timeout=15, check_same_thread=False,
            )
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(
                self.db_path, timeout=15, check_same_thread=False,
            )
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 15000")
        if not read_only:
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = FULL")
            self._migrate()
            os.chmod(self.db_path, 0o640)

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> SocialObservationSpool | None:
        env = os.environ if environment is None else environment
        enabled = env.get("SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED", "0").strip()
        if enabled not in {"0", "1"}:
            raise SocialObservationError(
                "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED must be 0 or 1"
            )
        if enabled == "0":
            return None
        raw_staleness = env.get(
            "SCAMSHIELD_SOCIAL_MAX_STALENESS_SECONDS",
            str(DEFAULT_MAX_STALENESS_SECONDS),
        ).strip()
        try:
            max_staleness = int(raw_staleness)
        except ValueError as exc:
            raise SocialObservationError(
                "SCAMSHIELD_SOCIAL_MAX_STALENESS_SECONDS must be an integer"
            ) from exc
        configured_db = env.get("SCAMSHIELD_SOCIAL_DB", DEFAULT_DB_PATH)
        if configured_db != DEFAULT_DB_PATH:
            raise SocialObservationError(
                "SCAMSHIELD_SOCIAL_DB cannot override the private production path"
            )
        configured_registry = env.get(
            "SCAMSHIELD_SOCIAL_SOURCES_FILE", DEFAULT_REGISTRY_PATH,
        )
        if configured_registry != DEFAULT_REGISTRY_PATH:
            raise SocialObservationError(
                "SCAMSHIELD_SOCIAL_SOURCES_FILE cannot override the production registry"
            )
        return cls(
            DEFAULT_DB_PATH,
            DEFAULT_REGISTRY_PATH,
            max_staleness_seconds=max_staleness,
        )

    def _migrate(self) -> None:
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_bindings (
                    source_id TEXT PRIMARY KEY,
                    public_handle TEXT NOT NULL,
                    native_peer_id TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    attested INTEGER NOT NULL DEFAULT 0 CHECK(attested IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    native_peer_id TEXT NOT NULL,
                    native_message_id INTEGER NOT NULL,
                    latest_version_id TEXT NOT NULL,
                    latest_observed_at TEXT NOT NULL,
                    first_collected_at TEXT NOT NULL,
                    last_collected_at TEXT NOT NULL,
                    UNIQUE(native_peer_id, native_message_id)
                );
                CREATE TABLE IF NOT EXISTS versions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id TEXT NOT NULL UNIQUE,
                    observation_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    first_observed_at TEXT NOT NULL,
                    native_edited_at TEXT,
                    sanitized_json TEXT NOT NULL,
                    FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
                        DEFERRABLE INITIALLY DEFERRED
                );
                CREATE INDEX IF NOT EXISTS versions_observation_idx
                    ON versions(observation_id, sequence);
                CREATE INDEX IF NOT EXISTS versions_source_idx
                    ON versions(source_id, sequence);
                CREATE TABLE IF NOT EXISTS coverage (
                    source_id TEXT PRIMARY KEY,
                    current_status TEXT NOT NULL DEFAULT 'not-attempted',
                    last_available_at TEXT,
                    last_success_at TEXT,
                    last_error_at TEXT,
                    capture_calls INTEGER NOT NULL DEFAULT 0,
                    accepted_versions INTEGER NOT NULL DEFAULT 0,
                    replayed_versions INTEGER NOT NULL DEFAULT 0,
                    rejected_records INTEGER NOT NULL DEFAULT 0,
                    collection_errors INTEGER NOT NULL DEFAULT 0,
                    last_error_code TEXT,
                    collection_in_progress INTEGER NOT NULL DEFAULT 0
                        CHECK(collection_in_progress IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS monitor_registry (
                    source_id TEXT PRIMARY KEY,
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS social_cursors (
                    source_id TEXT PRIMARY KEY,
                    initialized INTEGER NOT NULL CHECK(initialized IN (0, 1)),
                    last_message_id INTEGER NOT NULL CHECK(last_message_id >= 0)
                );
                PRAGMA user_version = 5;
                """
            )
            binding_columns = {
                str(row[1])
                for row in self.conn.execute("PRAGMA table_info(source_bindings)")
            }
            if "attested" not in binding_columns:
                # An upgraded process must perform fresh Telegram I/O before
                # any pre-existing identity pin is trusted for publication.
                self.conn.execute(
                    "ALTER TABLE source_bindings ADD COLUMN attested "
                    "INTEGER NOT NULL DEFAULT 0 CHECK(attested IN (0, 1))"
                )
            coverage_columns = {
                str(row[1])
                for row in self.conn.execute("PRAGMA table_info(coverage)")
            }
            if "collection_in_progress" not in coverage_columns:
                self.conn.execute(
                    "ALTER TABLE coverage ADD COLUMN collection_in_progress "
                    "INTEGER NOT NULL DEFAULT 0 "
                    "CHECK(collection_in_progress IN (0, 1))"
                )

    def _ledger_serialized_size(self, *, added_sanitized_bytes: int = 0) -> int:
        """Return the exact v1 JSONL byte size without materializing the ledger."""

        stored_bytes, count = self.conn.execute(
            """SELECT COALESCE(SUM(length(CAST(sanitized_json AS BLOB))), 0),
                      COUNT(*)
               FROM versions"""
        ).fetchone()
        if added_sanitized_bytes:
            stored_bytes = int(stored_bytes) + added_sanitized_bytes
            count = int(count) + 1
        schema_field_bytes = len(
            _canonical_json({"schema_version": LEDGER_SCHEMA_VERSION})
        ) - 2
        # Each non-empty sanitized object gains one comma, the schema field,
        # and one JSONL newline.
        return int(stored_bytes) + int(count) * (schema_field_bytes + 2)

    def _ensure_ledger_capacity(self, encoded: str) -> None:
        if self._ledger_serialized_size(
            added_sanitized_bytes=len(encoded.encode("utf-8"))
        ) > MAX_LEDGER_BYTES:
            raise LedgerCapacityExceeded(
                "social version ledger has reached its v1 capacity"
            )

    def _latest_payload_serialized_size(
        self,
        *,
        replacing_encoded: str | None = None,
        added_encoded: str | None = None,
    ) -> int:
        """Return terminal sanitized-object bytes without materializing latest."""

        stored_bytes = self.conn.execute(
            """SELECT COALESCE(SUM(length(CAST(v.sanitized_json AS BLOB))), 0)
               FROM observations AS o
               JOIN versions AS v ON v.version_id = o.latest_version_id"""
        ).fetchone()[0]
        projected = int(stored_bytes)
        if replacing_encoded is not None:
            projected -= len(replacing_encoded.encode("utf-8"))
        if added_encoded is not None:
            projected += len(added_encoded.encode("utf-8"))
        return projected

    def _ensure_latest_capacity(
        self,
        encoded: str,
        *,
        replacing_encoded: str | None = None,
    ) -> None:
        if self._latest_payload_serialized_size(
            replacing_encoded=replacing_encoded,
            added_encoded=encoded,
        ) > MAX_LATEST_PAYLOAD_BYTES:
            raise LatestCapacityExceeded(
                "social latest view has reached its v1 capacity"
            )

    @_serialized
    def close(self) -> None:
        self.conn.close()

    @_serialized
    def reload_registry(self) -> None:
        """Keep the prior valid registry if a replacement fails validation."""

        replacement = load_social_source_registry(self.registry_path)
        self.registry = replacement

    def _publisher_for_source(self, source: Any) -> SocialPublisher | None:
        reference = _source_reference(source)
        if reference is None:
            return None
        publisher = self.registry.by_handle.get(reference.casefold())
        if publisher is None:
            return None
        if (
            getattr(source, "surface", "") != "public_channel"
            or getattr(source, "authorization", "") != "public"
        ):
            return None
        entity = getattr(source, "entity", None)
        entity_username = getattr(entity, "username", None)
        if (
            type(entity_username) is not str
            or getattr(entity, "broadcast", None) is not True
            or getattr(entity, "megagroup", False) is not False
        ):
            return None
        try:
            entity_reference = normalize_source_reference(f"@{entity_username}")
        except ValueError:
            return None
        if entity_reference.casefold() != reference.casefold():
            return None
        active = self.conn.execute(
            "SELECT active FROM monitor_registry WHERE source_id = ?",
            (publisher.source_id,),
        ).fetchone()
        if active is None or int(active[0]) != 1:
            return None
        return publisher

    def _bind_source(
        self,
        publisher: SocialPublisher,
        source: Any,
        observed_at: str,
        *,
        attested: bool = False,
    ) -> None:
        native_peer_id = str(getattr(source, "peer_id", ""))
        handle = publisher.telegram_handle
        if _NATIVE_CHANNEL_PEER_ID.fullmatch(native_peer_id) is None or handle is None:
            raise SocialObservationError("resolved source lacks a reviewed identity")
        existing = self.conn.execute(
            "SELECT public_handle, native_peer_id, attested "
            "FROM source_bindings WHERE source_id = ?",
            (publisher.source_id,),
        ).fetchone()
        if existing is not None and (
            existing[0] != handle or existing[1] != native_peer_id
        ):
            raise SocialObservationError("reviewed publisher identity pin changed")
        if existing is None and not attested:
            raise SocialObservationError(
                "reviewed publisher identity has not been re-attested"
            )
        if existing is not None and not attested and int(existing[2]) != 1:
            raise SocialObservationError(
                "reviewed publisher identity attestation is no longer current"
            )
        if not attested:
            return
        self.conn.execute(
            """INSERT INTO source_bindings(
                   source_id, public_handle, native_peer_id, first_seen_at,
                   last_seen_at, attested
               ) VALUES (?, ?, ?, ?, ?, 1)
               ON CONFLICT(source_id) DO UPDATE SET
                   last_seen_at = excluded.last_seen_at,
                   attested = 1""",
            (publisher.source_id, handle, native_peer_id, observed_at, observed_at),
        )

    @_serialized
    def begin_source_batch(
        self,
        source: Any,
        *,
        observed_at: datetime | None = None,
    ) -> bool:
        """Attest one source and make partial reconciliation unpublishable."""

        publisher = self._publisher_for_source(source)
        if publisher is None:
            return False
        now = _utc_iso(observed_at)
        try:
            with self.conn:
                self._bind_source(publisher, source, now, attested=True)
                self.conn.execute(
                    """INSERT INTO coverage(
                           source_id, current_status, last_available_at,
                           last_error_code, collection_in_progress
                       ) VALUES (?, 'failure', ?, 'collection-in-progress', 1)
                       ON CONFLICT(source_id) DO UPDATE SET
                           current_status = 'failure',
                           last_available_at = excluded.last_available_at,
                           last_error_code = excluded.last_error_code,
                           collection_in_progress = 1""",
                    (publisher.source_id, now),
                )
        except sqlite3.Error as exc:
            raise SocialObservationError("social coverage spool is unavailable") from exc
        return True

    @_serialized
    def note_source_available(
        self,
        source: Any,
        *,
        observed_at: datetime | None = None,
    ) -> bool:
        publisher = self._publisher_for_source(source)
        if publisher is None:
            return False
        now = _utc_iso(observed_at)
        try:
            with self.conn:
                self._bind_source(publisher, source, now, attested=True)
                self.conn.execute(
                    """INSERT INTO coverage(
                           source_id, current_status, last_available_at, last_success_at
                       ) VALUES (?, 'success', ?, ?)
                       ON CONFLICT(source_id) DO UPDATE SET
                           current_status = 'success',
                           last_available_at = excluded.last_available_at,
                           last_success_at = excluded.last_success_at,
                           last_error_code = NULL,
                           collection_in_progress = 0""",
                    (publisher.source_id, now, now),
                )
        except sqlite3.Error as exc:
            raise SocialObservationError("social coverage spool is unavailable") from exc
        return True

    @_serialized
    def note_monitor_registry(self, references: Iterable[str]) -> None:
        """Persist the second allowlist used by every capture decision."""

        normalized: set[str] = set()
        for reference in references:
            try:
                candidate = normalize_source_reference(reference)
            except ValueError:
                continue
            normalized.add(candidate.casefold())
        now = _utc_iso()
        active_by_id = {
            source.source_id: int(
                source.telegram_handle is not None
                and source.telegram_handle.casefold() in normalized
            )
            for source in self.registry.telegram_sources
        }
        try:
            with self.conn:
                # Deactivate rows left behind by a registry removal or source
                # type change. The subsequent upserts reactivate only current
                # Telegram publishers present in both reviewed allowlists.
                self.conn.execute(
                    "UPDATE monitor_registry SET active = 0, updated_at = ?",
                    (now,),
                )
                self.conn.executemany(
                    """INSERT INTO monitor_registry(source_id, active, updated_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT(source_id) DO UPDATE SET
                           active = excluded.active,
                           updated_at = excluded.updated_at""",
                    (
                        (source_id, active, now)
                        for source_id, active in active_by_id.items()
                    ),
                )
                self.conn.execute(
                    """UPDATE source_bindings SET attested = 0
                       WHERE source_id NOT IN (
                           SELECT source_id FROM monitor_registry WHERE active = 1
                       )"""
                )
                self.conn.executemany(
                    """INSERT INTO coverage(source_id, current_status)
                       VALUES (?, 'not-attempted')
                       ON CONFLICT(source_id) DO UPDATE SET
                           current_status = 'not-attempted',
                           last_error_code = NULL,
                           collection_in_progress = 0""",
                    (
                        (source_id,)
                        for source_id, active in active_by_id.items()
                        if not active
                    ),
                )
        except sqlite3.Error as exc:
            raise SocialObservationError("social coverage spool is unavailable") from exc

    @_serialized
    def note_source_error(
        self,
        reference: str,
        error_code: str,
        *,
        observed_at: datetime | None = None,
        rejected: int = 0,
    ) -> bool:
        try:
            normalized = normalize_source_reference(reference)
        except ValueError:
            return False
        publisher = self.registry.by_handle.get(normalized.casefold())
        if publisher is None:
            return False
        if type(error_code) is not str or not _IDENTIFIER.fullmatch(error_code):
            error_code = "collection-error"
        if type(rejected) is not int or not 0 <= rejected <= 1_000_000:
            rejected = 0
        now = _utc_iso(observed_at)
        try:
            with self.conn:
                # A failed resolution/read invalidates the prior live identity
                # assertion. Capture remains closed until a fresh public
                # broadcast re-resolution and successful Telegram read calls
                # note_source_available again.
                self.conn.execute(
                    "UPDATE source_bindings SET attested = 0 WHERE source_id = ?",
                    (publisher.source_id,),
                )
                self.conn.execute(
                    """INSERT INTO coverage(
                           source_id, current_status, last_error_at, rejected_records,
                           collection_errors, last_error_code
                       ) VALUES (?, 'failure', ?, ?, 1, ?)
                       ON CONFLICT(source_id) DO UPDATE SET
                           current_status = 'failure',
                           last_error_at = excluded.last_error_at,
                           rejected_records = coverage.rejected_records + excluded.rejected_records,
                           collection_errors = coverage.collection_errors + 1,
                           last_error_code = excluded.last_error_code,
                           collection_in_progress = 0""",
                    (publisher.source_id, now, rejected, error_code),
                )
        except sqlite3.Error as exc:
            raise SocialObservationError("social coverage spool is unavailable") from exc
        return True

    @_serialized
    def capture(
        self,
        source: Any,
        message: Any,
        *,
        collected_at: datetime | None = None,
    ) -> CaptureResult:
        """Capture one append-only revision without retaining raw content."""

        publisher = self._publisher_for_source(source)
        if publisher is None:
            return CaptureResult("SKIPPED_NOT_DOUBLE_ALLOWLISTED")
        message_id = _message_identity(message)
        if message_id is None:
            self.note_source_error(
                publisher.telegram_handle or "",
                "invalid-message",
                rejected=1,
            )
            return CaptureResult("FAILED")
        native_peer_id = str(getattr(source, "peer_id", ""))
        collection_at = _utc_iso(collected_at)
        observed_at = collection_at
        raw_value = getattr(message, "raw_text", None)
        if type(raw_value) is not str:
            raw_value = getattr(message, "text", None)
        raw_text = raw_value if type(raw_value) is str else ""
        cleaned = _clean_source_text(raw_text)
        title = _truncate(cleaned, TITLE_LIMIT)
        if not title:
            title = _truncate(f"Media post from {publisher.source_name}", TITLE_LIMIT)
        excerpt = _truncate(cleaned, EXCERPT_LIMIT)
        published_at = _timestamp(getattr(message, "date", None), fallback=collected_at)
        observed_at = max(observed_at, published_at)
        related_urls = _related_urls(message, raw_text, publisher.article_hosts)
        if not _is_china_relevant(publisher, raw_text, related_urls):
            try:
                with self.conn:
                    self._bind_source(publisher, source, collection_at)
                    self._record_outside_scope(publisher.source_id, collection_at)
            except sqlite3.Error as exc:
                raise SocialObservationError(
                    "social observation spool is unavailable"
                ) from exc
            # If an in-scope post is edited out of scope, retain its legitimate
            # historical versions but withdraw the public terminal view. A new
            # outside-scope post has no observation and therefore no tombstone.
            self.tombstone(source, message_id, collected_at=collected_at)
            return CaptureResult("SKIPPED_OUTSIDE_SCOPE")
        content_type = _base_content_type(message)
        if content_type == "text" and related_urls:
            content_type = "link"
        if content_type not in _CONTENT_TYPES:
            content_type = "other"
        state = (
            "edited"
            if isinstance(getattr(message, "edit_date", None), datetime)
            else "published"
        )
        native_edited_at = (
            _timestamp(message.edit_date) if state == "edited" else None
        )
        native_id = f"{native_peer_id}:{message_id}"
        observation_id = _stable_id(
            "social",
            {
                "platform": "telegram",
                "source_id": publisher.source_id,
                "native_id": native_id,
            },
        )
        permalink = (
            f"https://t.me/"
            f"{(publisher.telegram_handle or '').removeprefix('@').casefold()}/"
            f"{message_id}/"
        )
        normalized: dict[str, Any] = {
            "observation_id": observation_id,
            "version_id": "",
            "supersedes_version_id": None,
            "platform": "telegram",
            "source_id": publisher.source_id,
            "source_name": publisher.source_name,
            "source_type": publisher.source_type,
            "independence_group": publisher.independence_group,
            "relation": RELATION,
            "rights_policy": publisher.rights_policy,
            "permalink": permalink,
            "published_at": published_at,
            "first_observed_at": observed_at,
            "title": title,
            "excerpt": excerpt,
            "content_type": content_type,
            "content_sha256": _sha256(raw_text.encode("utf-8")),
            "state": state,
            "china_relevance_labels": ["china"],
            "related_urls": list(related_urls),
        }
        try:
            with self.conn:
                self._bind_source(publisher, source, collection_at)
                previous_terminal_encoded: str | None = None
                previous = self.conn.execute(
                    """SELECT source_id, native_peer_id, native_message_id,
                              latest_version_id, latest_observed_at
                       FROM observations WHERE observation_id = ?""",
                    (observation_id,),
                ).fetchone()
                if previous is not None and (
                    previous[0] != publisher.source_id
                    or previous[1] != native_peer_id
                    or int(previous[2]) != message_id
                ):
                    raise SocialObservationError("social observation identity collision")
                if previous is not None:
                    terminal_row = self.conn.execute(
                        "SELECT sanitized_json FROM versions WHERE version_id = ?",
                        (previous[3],),
                    ).fetchone()
                    if terminal_row is None:
                        raise SocialObservationError("social latest revision is missing")
                    previous_terminal_encoded = str(terminal_row[0])
                    terminal = json.loads(
                        terminal_row[0], object_pairs_hook=_reject_duplicate_keys,
                    )
                    if terminal.get("state") == "tombstone":
                        # Telegram channel message IDs are never reused. A
                        # delayed live/backlog copy must not resurrect content
                        # after an authenticated deletion update won the race.
                        self.conn.execute(
                            "UPDATE observations SET last_collected_at = ? "
                            "WHERE observation_id = ?",
                            (collection_at, observation_id),
                        )
                        self._record_capture_coverage(
                            publisher.source_id,
                            collection_at,
                            created_version=False,
                        )
                        return CaptureResult(
                            "SKIPPED_TOMBSTONED",
                            observation_id,
                            previous[3],
                            False,
                        )
                    if observed_at < previous[4]:
                        raise SocialObservationError(
                            "social revision predates append-only terminal"
                        )
                    if all(
                        terminal[field] == normalized[field]
                        for field in _REVISION_CONTENT_FIELDS
                    ):
                        self.conn.execute(
                            "UPDATE observations SET last_collected_at = ? "
                            "WHERE observation_id = ?",
                            (collection_at, observation_id),
                        )
                        self._record_capture_coverage(
                            publisher.source_id,
                            collection_at,
                            created_version=False,
                        )
                        return CaptureResult(
                            "REPLAYED", observation_id, previous[3], False,
                        )
                normalized["supersedes_version_id"] = previous[3] if previous else None
                normalized["version_id"] = _stable_id(
                    "socialv",
                    {field: normalized[field] for field in _VERSION_PAYLOAD_FIELDS},
                )
                version_id = normalized["version_id"]
                existing_version = self.conn.execute(
                    "SELECT sanitized_json FROM versions WHERE version_id = ?",
                    (version_id,),
                ).fetchone()
                if existing_version is not None:
                    existing = json.loads(
                        existing_version[0], object_pairs_hook=_reject_duplicate_keys,
                    )
                    if any(
                        existing[field] != normalized[field]
                        for field in _VERSION_PAYLOAD_FIELDS
                    ):
                        raise SocialObservationError("social revision identity collision")
                    raise SocialObservationError("social revision chain contains a cycle")
                encoded = _canonical_json(normalized).decode("utf-8")
                self._ensure_ledger_capacity(encoded)
                self._ensure_latest_capacity(
                    encoded,
                    replacing_encoded=previous_terminal_encoded,
                )
                if previous is None:
                    self.conn.execute(
                        """INSERT INTO observations(
                               observation_id, source_id, native_peer_id,
                               native_message_id, latest_version_id,
                               latest_observed_at, first_collected_at,
                               last_collected_at
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            observation_id,
                            publisher.source_id,
                            native_peer_id,
                            message_id,
                            version_id,
                            observed_at,
                            collection_at,
                            collection_at,
                        ),
                    )
                else:
                    self.conn.execute(
                        """UPDATE observations SET latest_version_id = ?,
                               latest_observed_at = ?, last_collected_at = ?
                           WHERE observation_id = ?""",
                        (version_id, observed_at, collection_at, observation_id),
                    )
                self.conn.execute(
                    """INSERT INTO versions(
                           version_id, observation_id, source_id,
                           first_observed_at, native_edited_at, sanitized_json
                       ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        version_id,
                        observation_id,
                        publisher.source_id,
                        observed_at,
                        native_edited_at,
                        encoded,
                    ),
                )
                self._record_capture_coverage(
                    publisher.source_id,
                    collection_at,
                    created_version=True,
                )
        except SocialObservationError as exc:
            try:
                self.note_source_error(
                    publisher.telegram_handle or "",
                    (
                        "ledger-capacity-error"
                        if isinstance(exc, LedgerCapacityExceeded)
                        else "latest-capacity-error"
                        if isinstance(exc, LatestCapacityExceeded)
                        else "identity-or-revision-error"
                    ),
                    rejected=1,
                )
            except SocialObservationError:
                pass
            raise
        except sqlite3.Error as exc:
            raise SocialObservationError("social observation spool is unavailable") from exc
        return CaptureResult("CAPTURED", observation_id, version_id, True)

    @_serialized
    def is_source_authorized(self, source: Any) -> bool:
        """Return whether both registries and the resolved entity authorize capture."""

        return self._publisher_for_source(source) is not None

    @_serialized
    def source_cursor(self, source: Any) -> tuple[bool, int]:
        publisher = self._publisher_for_source(source)
        if publisher is None:
            raise SocialObservationError("social source is not double allowlisted")
        row = self.conn.execute(
            "SELECT initialized, last_message_id FROM social_cursors WHERE source_id = ?",
            (publisher.source_id,),
        ).fetchone()
        return (False, 0) if row is None else (bool(row[0]), int(row[1]))

    @_serialized
    def initialize_source_cursor(self, source: Any, message_id: int) -> None:
        publisher = self._publisher_for_source(source)
        if publisher is None:
            raise SocialObservationError("social source is not double allowlisted")
        if (
            isinstance(message_id, bool)
            or not isinstance(message_id, int)
            or not 0 <= message_id <= 2_147_483_647
        ):
            raise SocialObservationError("social cursor is invalid")
        with self.conn:
            self.conn.execute(
                """INSERT INTO social_cursors(source_id, initialized, last_message_id)
                   VALUES (?, 1, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                       initialized = 1,
                       last_message_id = MAX(social_cursors.last_message_id,
                                             excluded.last_message_id)""",
                (publisher.source_id, message_id),
            )

    @_serialized
    def advance_source_cursor(self, source: Any, message_id: int) -> None:
        self.initialize_source_cursor(source, message_id)

    @_serialized
    def recent_live_message_ids(
        self,
        source: Any,
        *,
        limit: int,
    ) -> tuple[int, ...]:
        """Return bounded recent non-tombstoned IDs for deletion recovery.

        Telegram does not replay deletion updates indefinitely.  The monitor
        compares this private list with a fresh bounded channel tail; native
        identifiers never leave the spool/exporter boundary.
        """

        publisher = self._publisher_for_source(source)
        if publisher is None:
            raise SocialObservationError("social source is not double allowlisted")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise SocialObservationError("social revision lookback must be 1..500")
        native_peer_id = str(getattr(source, "peer_id", ""))
        live: list[int] = []
        try:
            rows = self.conn.execute(
                """SELECT o.native_message_id, v.sanitized_json
                   FROM observations AS o
                   JOIN versions AS v ON v.version_id = o.latest_version_id
                   WHERE o.source_id = ? AND o.native_peer_id = ?
                   ORDER BY o.native_message_id DESC""",
                (publisher.source_id, native_peer_id),
            )
            for message_id, encoded in rows:
                normalized = _validate_sanitized_observation(
                    json.loads(encoded, object_pairs_hook=_reject_duplicate_keys),
                    self.registry,
                    native_peer_id=native_peer_id,
                    native_message_id=int(message_id),
                )
                if normalized["state"] != "tombstone":
                    live.append(int(message_id))
                    if len(live) == limit:
                        break
        except sqlite3.Error as exc:
            raise SocialObservationError("social observation spool is unavailable") from exc
        return tuple(live)

    @_serialized
    def tombstone(
        self,
        source: Any,
        message_id: int,
        *,
        collected_at: datetime | None = None,
    ) -> CaptureResult:
        """Append a content-free deletion revision for a previously captured post."""

        publisher = self._publisher_for_source(source)
        if publisher is None:
            return CaptureResult("SKIPPED_NOT_DOUBLE_ALLOWLISTED")
        if (
            isinstance(message_id, bool)
            or not isinstance(message_id, int)
            or not 0 < message_id <= 2_147_483_647
        ):
            return CaptureResult("FAILED")
        native_peer_id = str(getattr(source, "peer_id", ""))
        collection_at = _utc_iso(collected_at)
        try:
            with self.conn:
                self._bind_source(publisher, source, collection_at)
                row = self.conn.execute(
                    """SELECT o.observation_id, o.latest_version_id,
                              o.latest_observed_at, v.sanitized_json
                       FROM observations AS o
                       JOIN versions AS v ON v.version_id = o.latest_version_id
                       WHERE o.source_id = ? AND o.native_peer_id = ?
                             AND o.native_message_id = ?""",
                    (publisher.source_id, native_peer_id, message_id),
                ).fetchone()
                if row is None:
                    return CaptureResult("NOT_FOUND")
                previous = json.loads(row[3], object_pairs_hook=_reject_duplicate_keys)
                if previous.get("state") == "tombstone":
                    self.conn.execute(
                        "UPDATE observations SET last_collected_at = ? "
                        "WHERE observation_id = ?",
                        (collection_at, row[0]),
                    )
                    self._record_capture_coverage(
                        publisher.source_id, collection_at, created_version=False,
                    )
                    return CaptureResult(
                        "REPLAYED", row[0], row[1], False,
                    )
                observed_at = max(collection_at, str(row[2]))
                normalized = dict(previous)
                normalized.update(
                    {
                        "version_id": "",
                        "supersedes_version_id": row[1],
                        "first_observed_at": observed_at,
                        "title": "",
                        "excerpt": "",
                        "content_type": "unavailable",
                        "content_sha256": _sha256(b""),
                        "state": "tombstone",
                        "related_urls": [],
                    }
                )
                version_id = _stable_id(
                    "socialv",
                    {field: normalized[field] for field in _VERSION_PAYLOAD_FIELDS},
                )
                normalized["version_id"] = version_id
                encoded = _canonical_json(normalized).decode("utf-8")
                self._ensure_ledger_capacity(encoded)
                self._ensure_latest_capacity(
                    encoded,
                    replacing_encoded=str(row[3]),
                )
                self.conn.execute(
                    """INSERT INTO versions(
                           version_id, observation_id, source_id,
                           first_observed_at, native_edited_at, sanitized_json
                       ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        version_id,
                        row[0],
                        publisher.source_id,
                        observed_at,
                        collection_at,
                        encoded,
                    ),
                )
                self.conn.execute(
                    """UPDATE observations SET latest_version_id = ?,
                           latest_observed_at = ?, last_collected_at = ?
                       WHERE observation_id = ?""",
                    (version_id, observed_at, collection_at, row[0]),
                )
                self._record_capture_coverage(
                    publisher.source_id, collection_at, created_version=True,
                )
                return CaptureResult("CAPTURED", row[0], version_id, True)
        except (LedgerCapacityExceeded, LatestCapacityExceeded) as exc:
            try:
                self.note_source_error(
                    publisher.telegram_handle or "",
                    (
                        "ledger-capacity-error"
                        if isinstance(exc, LedgerCapacityExceeded)
                        else "latest-capacity-error"
                    ),
                    rejected=1,
                )
            except SocialObservationError:
                pass
            raise
        except sqlite3.Error as exc:
            raise SocialObservationError("social observation spool is unavailable") from exc

    def _record_capture_coverage(
        self,
        source_id: str,
        observed_at: str,
        *,
        created_version: bool,
    ) -> None:
        self.conn.execute(
            """INSERT INTO coverage(
                   source_id, current_status, last_available_at, last_success_at,
                   capture_calls, accepted_versions, replayed_versions
               ) VALUES (?, 'success', ?, ?, 1, ?, ?)
               ON CONFLICT(source_id) DO UPDATE SET
                   current_status = CASE coverage.collection_in_progress
                       WHEN 1 THEN coverage.current_status ELSE 'success' END,
                   last_available_at = excluded.last_available_at,
                   last_success_at = CASE coverage.collection_in_progress
                       WHEN 1 THEN coverage.last_success_at
                       ELSE excluded.last_success_at END,
                   capture_calls = coverage.capture_calls + 1,
                   accepted_versions = coverage.accepted_versions + excluded.accepted_versions,
                   replayed_versions = coverage.replayed_versions + excluded.replayed_versions,
                   last_error_code = CASE coverage.collection_in_progress
                       WHEN 1 THEN coverage.last_error_code ELSE NULL END""",
            (
                source_id,
                observed_at,
                observed_at,
                int(created_version),
                int(not created_version),
            ),
        )

    def _record_outside_scope(self, source_id: str, observed_at: str) -> None:
        self.conn.execute(
            """INSERT INTO coverage(
                   source_id, current_status, last_available_at, last_success_at,
                   capture_calls, rejected_records, last_error_code
               ) VALUES (?, 'success', ?, ?, 1, 1, 'outside-scope')
               ON CONFLICT(source_id) DO UPDATE SET
                   current_status = CASE coverage.collection_in_progress
                       WHEN 1 THEN coverage.current_status ELSE 'success' END,
                   last_available_at = excluded.last_available_at,
                   last_success_at = CASE coverage.collection_in_progress
                       WHEN 1 THEN coverage.last_success_at
                       ELSE excluded.last_success_at END,
                   capture_calls = coverage.capture_calls + 1,
                   rejected_records = coverage.rejected_records + 1,
                   last_error_code = CASE coverage.collection_in_progress
                       WHEN 1 THEN coverage.last_error_code ELSE 'outside-scope' END""",
            (source_id, observed_at, observed_at),
        )

    def _coverage_receipt(
        self,
        publisher: SocialPublisher,
        observation_counts: Mapping[str, int],
        *,
        active: bool,
        generated_at: str,
    ) -> dict[str, Any]:
        if (
            publisher.platform != "telegram"
            or publisher.telegram_handle is None
            or not active
        ):
            return {
                "source_id": publisher.source_id,
                "platform": publisher.platform,
                "status": "not-attempted",
                "accepted": 0,
                "rejected": 0,
                "error_code": None,
            }
        row = self.conn.execute(
            """SELECT current_status, last_available_at, last_success_at,
                      last_error_at, rejected_records, last_error_code
               FROM coverage WHERE source_id = ?""",
            (publisher.source_id,),
        ).fetchone()
        binding = self.conn.execute(
            "SELECT attested FROM source_bindings WHERE source_id = ?",
            (publisher.source_id,),
        ).fetchone()
        if binding is None or int(binding[0]) != 1:
            status = "failure"
            accepted = 0
            rejected = int(row[4]) if row is not None else 0
            error_code = "identity-not-attested"
        elif row is None:
            status = "failure"
            accepted = 0
            rejected = 0
            error_code = "collection-not-attempted"
        else:
            if row[0] == "failure":
                status = "failure"
                accepted = 0
                error_code = row[5] or "collection-error"
            elif row[0] == "success":
                stale = False
                if self.max_staleness_seconds is not None:
                    if row[2] is None:
                        stale = True
                    else:
                        generated = datetime.strptime(
                            generated_at, "%Y-%m-%dT%H:%M:%SZ"
                        ).replace(tzinfo=timezone.utc)
                        last_success = datetime.strptime(
                            row[2], "%Y-%m-%dT%H:%M:%SZ"
                        ).replace(tzinfo=timezone.utc)
                        stale = generated - last_success > timedelta(
                            seconds=self.max_staleness_seconds
                        )
                status = "failure" if stale else "success"
                accepted = (
                    0
                    if stale
                    else int(observation_counts.get(publisher.source_id, 0))
                )
                error_code = "collection-stale" if stale else None
            else:
                status = "failure"
                accepted = 0
                error_code = "collection-not-attempted"
            rejected = int(row[4])
        return {
            "source_id": publisher.source_id,
            "platform": publisher.platform,
            "status": status,
            "accepted": accepted,
            "rejected": rejected,
            "error_code": error_code,
        }

    @_serialized
    def build_export(
        self,
        *,
        generated_at: datetime | None = None,
    ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
        """Build both artifacts from one stable SQLite read transaction."""

        self.conn.execute("BEGIN")
        try:
            return self._build_export_in_transaction(generated_at=generated_at)
        finally:
            self.conn.rollback()

    def _build_export_in_transaction(
        self,
        *,
        generated_at: datetime | None = None,
    ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
        """Build exact Palimpsest latest and append-only ledger documents."""

        registered_ids = set(self.registry.by_id)
        bindings = tuple(
            (str(source_id), str(handle))
            for source_id, handle in self.conn.execute(
                "SELECT source_id, public_handle FROM source_bindings"
            )
        )
        stored_source_ids = {
            str(row[0])
            for row in self.conn.execute(
                """SELECT source_id FROM observations
                   UNION SELECT source_id FROM versions
                   UNION SELECT source_id FROM source_bindings
                   UNION SELECT source_id FROM coverage
                   UNION SELECT source_id FROM monitor_registry
                   UNION SELECT source_id FROM social_cursors"""
            )
        }
        retired_ids = stored_source_ids - registered_ids
        if retired_ids:
            raise SocialObservationError(
                "stored social history references a retired registry source"
            )
        if any(
            (publisher := self.registry.by_id.get(source_id)) is None
            or publisher.platform != "telegram"
            or publisher.telegram_handle is None
            or publisher.telegram_handle != handle
            for source_id, handle in bindings
        ):
            raise SocialObservationError(
                "stored social identity binding differs from the current registry"
            )
        in_progress_ids = {
            str(source_id)
            for source_id, in_progress, active in self.conn.execute(
                """SELECT c.source_id, c.collection_in_progress, m.active
                   FROM coverage AS c
                   JOIN monitor_registry AS m ON m.source_id = c.source_id"""
            )
            if int(in_progress) == 1 and int(active) == 1
        }
        if any(
            (publisher := self.registry.by_id.get(source_id)) is not None
            and publisher.platform == "telegram"
            and publisher.telegram_handle is not None
            for source_id in in_progress_ids
        ):
            raise SocialObservationError(
                "social collection reconciliation is still in progress"
            )
        if self._ledger_serialized_size() > MAX_LEDGER_BYTES:
            raise LedgerCapacityExceeded(
                "stored social version ledger exceeds its v1 capacity"
            )
        if self._latest_payload_serialized_size() > MAX_LATEST_PAYLOAD_BYTES:
            raise LatestCapacityExceeded(
                "stored social latest view exceeds its v1 capacity"
            )
        latest_rows = self.conn.execute(
            """SELECT v.source_id, o.native_peer_id, o.native_message_id,
                      v.sanitized_json
               FROM observations AS o
               JOIN versions AS v ON v.version_id = o.latest_version_id"""
        ).fetchall()
        version_rows = self.conn.execute(
            """SELECT v.source_id, o.native_peer_id, o.native_message_id,
                      v.sanitized_json
               FROM versions AS v
               JOIN observations AS o ON o.observation_id = v.observation_id
               ORDER BY v.sequence"""
        )
        observations = [
            _validate_sanitized_observation(
                json.loads(encoded, object_pairs_hook=_reject_duplicate_keys),
                self.registry,
                native_peer_id=str(native_peer_id),
                native_message_id=int(native_message_id),
            )
            for source_id, native_peer_id, native_message_id, encoded in latest_rows
        ]
        del latest_rows
        observations.sort(
            key=lambda value: (
                -datetime.strptime(
                    value["published_at"], "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc).timestamp(),
                value["observation_id"],
            )
        )
        version_observations = tuple(
            _validate_sanitized_observation(
                json.loads(encoded, object_pairs_hook=_reject_duplicate_keys),
                self.registry,
                native_peer_id=str(native_peer_id),
                native_message_id=int(native_message_id),
            )
            for source_id, native_peer_id, native_message_id, encoded in version_rows
        )
        terminals = _validate_revision_chain(version_observations)
        latest_by_id = {row["observation_id"]: row for row in observations}
        if set(latest_by_id) != set(terminals) or any(
            latest_by_id[observation_id]["version_id"]
            != terminals[observation_id]["version_id"]
            for observation_id in terminals
        ):
            raise SocialObservationError("stored latest view does not match ledger terminals")
        versions = tuple(
            {"schema_version": LEDGER_SCHEMA_VERSION, **observation}
            for observation in version_observations
        )
        observation_counts = {
            str(source_id): int(count)
            for source_id, count in self.conn.execute(
                "SELECT source_id, COUNT(*) FROM observations GROUP BY source_id"
            )
        }
        active_ids = {
            str(source_id)
            for source_id, active in self.conn.execute(
                "SELECT source_id, active FROM monitor_registry"
            )
            if int(active) == 1
            and (publisher := self.registry.by_id.get(str(source_id))) is not None
            and publisher.platform == "telegram"
            and publisher.telegram_handle is not None
        }
        generated_timestamp = _utc_iso(generated_at)
        receipts = [
            self._coverage_receipt(
                source,
                observation_counts,
                active=source.source_id in active_ids,
                generated_at=generated_timestamp,
            )
            for source in self.registry.sources
        ]
        failed_active = [
            receipt
            for receipt in receipts
            if receipt["source_id"] in active_ids and receipt["status"] == "failure"
        ]
        if active_ids and len(failed_active) == len(active_ids):
            raise TotalCollectionFailure(
                "all active Telegram social sources are failing or stale"
            )
        coverage = {
            "scope": SCOPE,
            "configured": len(self.registry.sources),
            "successful": sum(row["status"] == "success" for row in receipts),
            "failed": sum(row["status"] == "failure" for row in receipts),
            "rejected": sum(int(row["rejected"]) for row in receipts),
            "receipts": receipts,
        }
        snapshot = {
            "schema_version": EXPORT_SCHEMA_VERSION,
            "generated_at": generated_timestamp,
            "source_registry": SOURCE_REGISTRY_URL,
            "source_registry_sha256": self.registry.digest,
            "scope": SCOPE,
            "relation": RELATION,
            "coverage": coverage,
            "n_observations": len(observations),
            "observations": observations,
        }
        return snapshot, versions


def serialize_latest(snapshot: Mapping[str, Any]) -> bytes:
    return _canonical_json(snapshot) + b"\n"


def serialize_versions(versions: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(_canonical_json(version) + b"\n" for version in versions)


def _write_durable(path: Path, content: bytes, *, mode: int = 0o640) -> None:
    with path.open("xb") as stream:
        os.chmod(path, mode)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prune_generations(generations: Path, *, current_bundle: str) -> None:
    candidates: list[tuple[int, Path]] = []
    for entry in generations.iterdir():
        if (
            entry.is_symlink()
            or not entry.is_dir()
            or re.fullmatch(r"[0-9a-f]{32}", entry.name) is None
        ):
            continue
        candidates.append((entry.stat().st_mtime_ns, entry))
    newest = {current_bundle}
    for _mtime, path in sorted(candidates, reverse=True):
        if len(newest) >= MAX_GENERATIONS:
            break
        newest.add(path.name)
    for _mtime, path in candidates:
        if path.name not in newest:
            shutil.rmtree(path)
    _fsync_directory(generations)


def _remove_stale_temporary_generations(generations: Path) -> None:
    """Remove only directories bearing this publisher's mkdtemp prefix."""

    for entry in generations.iterdir():
        if (
            entry.is_symlink()
            or not entry.is_dir()
            or re.fullmatch(r"\.social-export-[A-Za-z0-9_-]{6,64}", entry.name)
            is None
        ):
            continue
        shutil.rmtree(entry)
    _fsync_directory(generations)


def _existing_bundle_matches(final: Path, expected: Mapping[str, bytes]) -> bool:
    """Accept an existing content-addressed generation only byte-for-byte."""

    if final.is_symlink() or not final.is_dir():
        return False
    try:
        parent_metadata = final.parent.stat()
        directory_metadata = final.stat()
        if (
            stat.S_IMODE(directory_metadata.st_mode) != 0o750
            or directory_metadata.st_uid != parent_metadata.st_uid
            or directory_metadata.st_gid != parent_metadata.st_gid
        ):
            return False
        entries = {entry.name: entry for entry in final.iterdir()}
    except OSError:
        return False
    if set(entries) != set(expected):
        return False
    for name, content in expected.items():
        entry = entries[name]
        try:
            metadata = entry.stat()
            if (
                entry.is_symlink()
                or not entry.is_file()
                or stat.S_IMODE(metadata.st_mode) != 0o640
                or metadata.st_uid != directory_metadata.st_uid
                or metadata.st_gid != directory_metadata.st_gid
                or metadata.st_size != len(content)
                or entry.read_bytes() != content
            ):
                return False
        except OSError:
            return False
    return True


def publish_export_bundle(
    spool: SocialObservationSpool,
    output_dir: str | Path,
    hmac_key: str | bytes,
    *,
    generated_at: datetime | None = None,
) -> Path:
    """Atomically switch ``current`` to one complete authenticated bundle."""

    key = hmac_key.encode("utf-8") if isinstance(hmac_key, str) else hmac_key
    if not isinstance(key, bytes) or len(key) < 32:
        raise SocialObservationError("social export HMAC key must contain at least 32 bytes")
    snapshot, versions = spool.build_export(generated_at=generated_at)
    latest_bytes = serialize_latest(snapshot)
    versions_bytes = serialize_versions(versions)
    if len(latest_bytes) > MAX_LATEST_BYTES:
        raise SocialObservationError("social latest artifact exceeds 16 MiB")
    if len(versions_bytes) > MAX_LEDGER_BYTES:
        raise SocialObservationError("social version ledger exceeds 64 MiB")
    bundle_id = _sha256(latest_bytes + b"\x00" + versions_bytes)[:32]
    root = Path(output_dir)
    if root.exists() or root.is_symlink():
        if root.is_symlink() or not root.is_dir():
            raise SocialObservationError("social export root must be a real directory")
    else:
        root.mkdir(parents=True, mode=0o750)
    generations = root / "generations"
    if generations.exists() or generations.is_symlink():
        if generations.is_symlink() or not generations.is_dir():
            raise SocialObservationError(
                "social export generations path must be a real directory"
            )
    else:
        generations.mkdir(mode=0o750)
    # Production preflight requires a root-created setgid caddy-group parent,
    # so every immutable generation inherits Caddy readability. The exporter
    # never sets SGID itself (its systemd sandbox deliberately forbids that).
    _remove_stale_temporary_generations(generations)
    temporary = Path(tempfile.mkdtemp(prefix=".social-export-", dir=generations))
    final = generations / bundle_id
    try:
        latest_name = "social-observations-latest.json"
        versions_name = "social-observations-versions.jsonl"
        latest_path = temporary / latest_name
        versions_path = temporary / versions_name
        _write_durable(latest_path, latest_bytes)
        _write_durable(versions_path, versions_bytes)
        sidecar = {
            "schema_version": SIGNATURE_SCHEMA_VERSION,
            "algorithm": "hmac-sha256",
            "bundle_id": bundle_id,
            "artifacts": {
                latest_name: {
                    "sha256": _sha256(latest_bytes),
                    "hmac_sha256": hmac.new(key, latest_bytes, hashlib.sha256).hexdigest(),
                },
                versions_name: {
                    "sha256": _sha256(versions_bytes),
                    "hmac_sha256": hmac.new(key, versions_bytes, hashlib.sha256).hexdigest(),
                },
            },
        }
        _write_durable(
            temporary / "social-observations.hmac.json",
            sidecar_bytes := _canonical_json(sidecar) + b"\n",
        )
        # Short immutable aliases are the fixed HTTPS importer contract. They
        # are hard links inside the same generation, so a caller can never
        # combine the latest view, ledger and receipt from different runs.
        os.link(latest_path, temporary / "latest.json")
        os.link(versions_path, temporary / "versions.jsonl")
        _write_durable(temporary / "hmac.json", sidecar_bytes)
        os.chmod(temporary, 0o750)
        directory_fd = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        expected_files = {
            latest_name: latest_bytes,
            versions_name: versions_bytes,
            "social-observations.hmac.json": sidecar_bytes,
            "latest.json": latest_bytes,
            "versions.jsonl": versions_bytes,
            "hmac.json": sidecar_bytes,
        }
        if not _existing_bundle_matches(temporary, expected_files):
            raise SocialObservationError(
                "new social export generation has unsafe permissions"
            )
        if final.exists() or final.is_symlink():
            if not _existing_bundle_matches(final, expected_files):
                raise SocialObservationError(
                    "existing social export generation is not immutable"
                )
            shutil.rmtree(temporary)
        else:
            os.replace(temporary, final)
        _fsync_directory(generations)
        link = root / "current"
        if link.exists() and not link.is_symlink():
            raise SocialObservationError("social export current path must be a symlink")
        temporary_link = root / f".current-{os.getpid()}"
        if temporary_link.exists() or temporary_link.is_symlink():
            temporary_link.unlink()
        temporary_link.symlink_to(Path("generations") / bundle_id)
        os.replace(temporary_link, link)
        try:
            _fsync_directory(root)
        except OSError as exc:
            raise PublicationCommittedError(
                "social export switched current but could not confirm durability"
            ) from exc
        # Replacing and fsyncing ``current`` is the publication commit point.
        # Retention cleanup is best-effort after that point: reporting failure
        # would falsely tell operators that the prior bundle remained active.
        try:
            _prune_generations(generations, current_bundle=bundle_id)
        except Exception as exc:
            log.warning(
                "social export generation pruning failed after commit (%s)",
                type(exc).__name__,
            )
        return link
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


__all__ = [
    "COLLECTION_POLICY",
    "DEFAULT_DB_PATH",
    "DEFAULT_MAX_STALENESS_SECONDS",
    "DEFAULT_OUTPUT_PATH",
    "DEFAULT_REGISTRY_PATH",
    "EXPORT_SCHEMA_VERSION",
    "LEDGER_SCHEMA_VERSION",
    "REGISTRY_SCHEMA_VERSION",
    "RELATION",
    "RIGHTS_POLICY",
    "SCOPE",
    "SIGNATURE_SCHEMA_VERSION",
    "SOURCE_REGISTRY_URL",
    "CaptureResult",
    "LatestCapacityExceeded",
    "LedgerCapacityExceeded",
    "PublicationCommittedError",
    "SocialObservationError",
    "SocialObservationSpool",
    "SocialPublisher",
    "SocialSourceRegistry",
    "TotalCollectionFailure",
    "load_social_source_registry",
    "publish_export_bundle",
    "serialize_latest",
    "serialize_versions",
    "validate_public_registry_projection",
]
