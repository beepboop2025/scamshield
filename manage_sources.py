#!/usr/bin/env python3
"""Operator review for ScamShield's persistent Telegram source registry."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from scamshield.iocstore import IocStore
from scamshield.runtime import channels_file_path
from scamshield.telegram_sources import (
    MAX_CONFIGURED_SOURCES,
    normalize_source_reference,
    parse_source_registry,
)


def _public_reference(value: str) -> str:
    try:
        normalized = normalize_source_reference(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if not normalized.startswith("@"):
        raise argparse.ArgumentTypeError(
            "this command accepts public usernames only; add an authorized private ID manually"
        )
    return normalized


def append_public_source(path: str | Path, reference: str) -> bool:
    """Append one normalized public source under an exclusive file lock."""

    normalized = _public_reference(reference)
    registry_path = Path(path)
    if not registry_path.is_file():
        raise FileNotFoundError(f"source registry does not exist: {registry_path}")
    with registry_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        existing_text = handle.read()
        existing = parse_source_registry(registry_path)
        if normalized.casefold() in {item.casefold() for item in existing.references}:
            return False
        if len(existing.references) >= MAX_CONFIGURED_SOURCES:
            raise ValueError(
                f"source registry is limited to {MAX_CONFIGURED_SOURCES} entries"
            )
        handle.seek(0, os.SEEK_END)
        if existing_text and not existing_text.endswith("\n"):
            handle.write("\n")
        handle.write(f"{normalized}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return True


def _timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def auto_promote_sources(
    store: IocStore,
    path: str | Path,
    *,
    min_hits: int = 2,
    min_sources: int = 2,
    limit: int = 5,
    max_configured: int = 100,
    verification_max_age: int = 86_400,
    now: int | None = None,
) -> tuple[str, ...]:
    """Append only fresh, corroborated, Telegram-verified public channels."""

    registry_path = Path(path)
    registry = parse_source_registry(registry_path)
    if registry.issues:
        raise ValueError("source registry has parse errors; refusing automatic changes")
    if isinstance(max_configured, bool) or not 1 <= max_configured <= MAX_CONFIGURED_SOURCES:
        raise ValueError(f"max_configured must be in [1, {MAX_CONFIGURED_SOURCES}]")
    remaining = max(0, max_configured - len(registry.references))
    if remaining == 0:
        return ()
    candidates = store.verified_source_candidates(
        min_hits=min_hits,
        min_sources=min_sources,
        max_age=verification_max_age,
        limit=min(limit, remaining),
        now=now,
    )
    added: list[str] = []
    for reference, _hits, _source_count, _checked_at in candidates:
        current = parse_source_registry(registry_path)
        if current.issues:
            raise ValueError("source registry changed to an invalid state")
        if len(current.references) >= max_configured:
            break
        if append_public_source(registry_path, reference):
            added.append(reference)
    return tuple(added)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Review public-source candidates; never auto-join private invitations."
    )
    parser.add_argument(
        "--db", default=os.environ.get("SCAMSHIELD_DB", "scamshield.db"),
    )
    parser.add_argument("--channels", default=str(channels_file_path()))
    commands = parser.add_subparsers(dest="command", required=True)
    list_parser = commands.add_parser("candidates")
    list_parser.add_argument("--min-hits", type=int, default=1)
    list_parser.add_argument("--limit", type=int, default=100)
    approve = commands.add_parser("approve")
    approve.add_argument("reference", type=_public_reference)
    reject = commands.add_parser("reject")
    reject.add_argument("reference", type=_public_reference)
    add = commands.add_parser("add-public")
    add.add_argument("reference", type=_public_reference)
    auto = commands.add_parser("auto-promote")
    auto.add_argument("--min-hits", type=int, default=2)
    auto.add_argument("--min-sources", type=int, default=2)
    auto.add_argument("--limit", type=int, default=5)
    auto.add_argument("--max-configured", type=int, default=100)
    auto.add_argument("--verification-max-age", type=int, default=86_400)
    args = parser.parse_args()

    if args.command == "add-public":
        changed = append_public_source(args.channels, args.reference)
        action = "added" if changed else "already configured"
        print(f"{action}: {args.reference}")
        return

    store = IocStore(
        args.db,
        read_only=args.command in {"candidates", "approve", "auto-promote"},
    )
    try:
        if args.command == "auto-promote":
            added = auto_promote_sources(
                store,
                args.channels,
                min_hits=args.min_hits,
                min_sources=args.min_sources,
                limit=args.limit,
                max_configured=args.max_configured,
                verification_max_age=args.verification_max_age,
            )
            print(f"auto-promoted {len(added)} verified public source(s)")
            return

        if args.command == "candidates":
            configured = {
                item.casefold()
                for item in parse_source_registry(args.channels).references
            }
            rows = store.source_candidates(
                min_hits=args.min_hits,
                limit=args.limit,
            )
            for candidate, hits, last_seen, families_json, source_count in rows:
                if candidate.casefold() in configured:
                    continue
                print(json.dumps({
                    "candidate": candidate,
                    "hits": hits,
                    "distinct_sources": source_count,
                    "last_seen": _timestamp(last_seen),
                    "families": json.loads(families_json),
                }, sort_keys=True, separators=(",", ":")))
            return

        reference = args.reference
        if args.command == "reject":
            if not store.set_source_candidate_status(reference, "REJECTED"):
                raise SystemExit("candidate was not found")
            print(f"rejected {reference}")
            return

        if args.command == "approve":
            candidate = store.source_candidate(reference)
            if candidate is None:
                raise SystemExit("candidate was not found; use add-public for an operator source")
            if candidate[0] == "REJECTED":
                raise SystemExit("candidate is rejected; use add-public for an explicit override")

        changed = append_public_source(args.channels, reference)
        action = "added" if changed else "already configured"
        print(f"{action}: {reference}")
    finally:
        store.close()


if __name__ == "__main__":
    main()
