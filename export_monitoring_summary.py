#!/usr/bin/env python3
"""Render one private, aggregate ScamShield Telegram monitoring summary."""

from __future__ import annotations

import argparse
import os
from datetime import date, datetime, timezone

from scamshield.iocstore import IocStore
from scamshield.monitoring_export import (
    MonitoringExportPolicy,
    build_monitoring_summary,
    serialize_monitoring_summary,
)


def _day(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("day must use YYYY-MM-DD") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--db", default=os.environ.get("SCAMSHIELD_DB", "scamshield.db"),
    )
    parser.add_argument(
        "--day", type=_day, default=datetime.now(timezone.utc).date(),
    )
    parser.add_argument(
        "--min-messages",
        type=int,
        default=int(os.environ.get("SCAMSHIELD_EXPORT_MIN_MESSAGES", "20")),
    )
    parser.add_argument(
        "--min-sources",
        type=int,
        default=int(os.environ.get("SCAMSHIELD_EXPORT_MIN_SOURCES", "2")),
    )
    args = parser.parse_args()
    store = IocStore(args.db, read_only=True)
    try:
        summary = build_monitoring_summary(
            store,
            args.day,
            policy=MonitoringExportPolicy(
                min_messages=args.min_messages,
                min_sources=args.min_sources,
            ),
        )
        print(serialize_monitoring_summary(summary), end="")
    finally:
        store.close()


if __name__ == "__main__":
    main()
