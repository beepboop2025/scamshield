#!/usr/bin/env python3
"""Materialize one atomic, authenticated Palimpsest social-observation bundle."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

from scamshield.social_observation_spool import (
    DEFAULT_DB_PATH,
    DEFAULT_MAX_STALENESS_SECONDS,
    DEFAULT_OUTPUT_PATH,
    DEFAULT_REGISTRY_PATH,
    PublicationCommittedError,
    SocialObservationError,
    SocialObservationSpool,
    publish_export_bundle,
)


def _load_hmac_key() -> bytes:
    credentials = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    key_path = (
        Path(credentials) / "social_export_hmac"
        if credentials
        else Path("/etc/scamshield/social-export-hmac.key")
    )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(key_path, flags)
    except OSError as exc:
        raise SocialObservationError("social export signing credential is unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            raise SocialObservationError("social export signing credential is invalid")
        value = os.read(descriptor, 4097).strip()
    finally:
        os.close(descriptor)
    if len(value) < 32:
        raise SocialObservationError(
            "social export signing credential must contain at least 32 bytes"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
    )
    parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY_PATH,
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_PATH,
    )
    args = parser.parse_args()
    fixed_paths = {
        "--db": (args.db, DEFAULT_DB_PATH),
        "--registry": (args.registry, DEFAULT_REGISTRY_PATH),
        "--output-dir": (args.output_dir, DEFAULT_OUTPUT_PATH),
    }
    for option, (configured, expected) in fixed_paths.items():
        if configured != expected:
            parser.error(f"{option} cannot override the production path")

    enabled = os.environ.get("SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED", "0").strip()
    if enabled not in {"0", "1"}:
        parser.error("SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED must be 0 or 1")
    if enabled == "0":
        return 0
    try:
        max_staleness = int(
            os.environ.get(
                "SCAMSHIELD_SOCIAL_MAX_STALENESS_SECONDS",
                str(DEFAULT_MAX_STALENESS_SECONDS),
            )
        )
    except ValueError:
        parser.error("SCAMSHIELD_SOCIAL_MAX_STALENESS_SECONDS must be an integer")
    spool: SocialObservationSpool | None = None
    try:
        hmac_key = _load_hmac_key()
        spool = SocialObservationSpool(
            Path(args.db),
            Path(args.registry),
            read_only=True,
            max_staleness_seconds=max_staleness,
        )
        current = publish_export_bundle(spool, Path(args.output_dir), hmac_key)
    except PublicationCommittedError:
        # ``current`` already names the new complete generation. Surface the
        # durability problem without making the false last-good claim used for
        # failures before the atomic switch.
        print("social observation export switched current; durability confirmation failed")
        return 1
    except Exception as exc:  # noqa: BLE001 - preserve last good on pre-commit failure
        # Errors are intentionally identity- and credential-free.  Crucially,
        # publication happens only after the complete replacement validates,
        # so an existing ``current`` bundle remains the last known good.
        print(f"social observation export preserved last good: {type(exc).__name__}")
        return 1
    finally:
        if spool is not None:
            spool.close()
    print(f"social observation export active: {current}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
