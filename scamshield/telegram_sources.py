"""Bounded source-registry and discovery helpers for the Telegram monitor.

The monitor intentionally accepts only explicit public usernames/links or
numeric identifiers already available to the dedicated account.  Private
invite links are not a collection primitive: an operator must join an
authorized private source in an official client and then configure its ID.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import urlsplit


MAX_CONFIGURED_SOURCES = 500
_USERNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_NUMERIC_ID = re.compile(r"^-?[0-9]{5,20}$")


@dataclass(frozen=True)
class RegistryIssue:
    line_number: int
    reason: str


@dataclass(frozen=True)
class SourceRegistry:
    references: tuple[str, ...]
    issues: tuple[RegistryIssue, ...] = ()


def normalize_source_reference(value: str) -> str:
    """Normalize one explicit Telegram source without accepting invite links."""

    if not isinstance(value, str):
        raise ValueError("source reference must be text")
    candidate = value.strip()
    if not candidate:
        raise ValueError("source reference is empty")

    if _NUMERIC_ID.fullmatch(candidate):
        return candidate

    if candidate.startswith("@"):
        username = candidate[1:]
    else:
        link = candidate
        if link.lower().startswith("t.me/"):
            link = f"https://{link}"
        parsed = urlsplit(link)
        if parsed.scheme or parsed.netloc:
            if (
                parsed.scheme.lower() != "https"
                or parsed.hostname not in {"t.me", "www.t.me"}
                or parsed.username
                or parsed.password
                or parsed.port not in {None, 443}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Telegram links must be plain https://t.me/<username> URLs")
            parts = [part for part in parsed.path.split("/") if part]
            if parts[:1] == ["s"]:
                parts = parts[1:]
            if len(parts) != 1:
                raise ValueError("Telegram links must identify one public username")
            username = parts[0]
        else:
            username = candidate

    if username.startswith("+") or username.lower() == "joinchat":
        raise ValueError("private invite links are not accepted")
    if not _USERNAME.fullmatch(username):
        raise ValueError("source must be a Telegram username or numeric chat ID")
    return f"@{username.lower()}"


def parse_source_registry(path: str | Path) -> SourceRegistry:
    """Parse the operator registry, retaining valid rows and reporting bad ones."""

    registry_path = Path(path)
    if not registry_path.exists():
        return SourceRegistry((), (RegistryIssue(0, "registry file is missing"),))

    references: list[str] = []
    issues: list[RegistryIssue] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(registry_path.read_text().splitlines(), start=1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            normalized = normalize_source_reference(value)
        except ValueError as exc:
            issues.append(RegistryIssue(line_number, str(exc)))
            continue
        key = normalized.casefold()
        if key in seen:
            continue
        if len(references) >= MAX_CONFIGURED_SOURCES:
            issues.append(
                RegistryIssue(line_number, f"registry exceeds {MAX_CONFIGURED_SOURCES} sources")
            )
            break
        seen.add(key)
        references.append(normalized)
    return SourceRegistry(tuple(references), tuple(issues))


def source_reference_digest(reference: str) -> str:
    """Return a log/database-safe identifier for an operator source reference."""

    return hashlib.sha256(reference.casefold().encode("utf-8")).hexdigest()[:24]


def discovery_candidates(iocs: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
    """Extract review-only public Telegram references from a flagged result.

    Handles can identify people, bots, groups, or channels.  They are therefore
    only candidates for an operator to inspect; this function never resolves or
    joins them.  Invite links and numeric identifiers are deliberately omitted.
    """

    candidates: list[str] = []
    seen: set[str] = set()
    for value in (*iocs.get("channels", ()), *iocs.get("handles", ())):
        try:
            normalized = normalize_source_reference(value)
        except ValueError:
            continue
        if not normalized.startswith("@"):
            continue
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            candidates.append(normalized)
    return tuple(candidates)


def _bounded_int(
    environment: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = environment.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be in [{minimum}, {maximum}]")
    return value


@dataclass(frozen=True)
class MonitorSettings:
    initial_history: int = 100
    backfill_batch: int = 250
    reconcile_seconds: int = 300
    claim_lease_seconds: int = 900
    max_analysis_concurrency: int = 4
    flood_sleep_threshold: int = 60
    auto_join_public: bool = True

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None,
    ) -> "MonitorSettings":
        env = os.environ if environment is None else environment
        auto_join = env.get("SCAMSHIELD_AUTO_JOIN_PUBLIC", "1").strip()
        if auto_join not in {"0", "1"}:
            raise ValueError("SCAMSHIELD_AUTO_JOIN_PUBLIC must be 0 or 1")
        return cls(
            initial_history=_bounded_int(
                env, "SCAMSHIELD_INITIAL_HISTORY", 100, minimum=0, maximum=1000,
            ),
            backfill_batch=_bounded_int(
                env, "SCAMSHIELD_BACKFILL_BATCH", 250, minimum=1, maximum=1000,
            ),
            reconcile_seconds=_bounded_int(
                env, "SCAMSHIELD_RECONCILE_SECONDS", 300, minimum=60, maximum=3600,
            ),
            claim_lease_seconds=_bounded_int(
                env, "SCAMSHIELD_CLAIM_LEASE_SECONDS", 900, minimum=60, maximum=86400,
            ),
            max_analysis_concurrency=_bounded_int(
                env, "SCAMSHIELD_ANALYSIS_CONCURRENCY", 4, minimum=1, maximum=16,
            ),
            flood_sleep_threshold=_bounded_int(
                env, "SCAMSHIELD_FLOOD_SLEEP_THRESHOLD", 60, minimum=0, maximum=86400,
            ),
            auto_join_public=auto_join == "1",
        )


__all__ = [
    "MAX_CONFIGURED_SOURCES",
    "MonitorSettings",
    "RegistryIssue",
    "SourceRegistry",
    "discovery_candidates",
    "normalize_source_reference",
    "parse_source_registry",
    "source_reference_digest",
]
