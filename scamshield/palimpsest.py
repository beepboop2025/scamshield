"""Bounded local client for the Palimpsest ScamShield bridge."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .provenance import validate_assessment_shape

MAX_ASSESSMENT_BYTES = 1024 * 1024
MAX_CAPSULE_BYTES = 32 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class BridgeReceipt:
    status: str
    capsule_sha256: str = ""
    outbox_path: str = ""
    error: str = ""
    capsule: Mapping[str, Any] | None = None

    def to_dict(self, *, include_capsule: bool = False) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "capsule_sha256": self.capsule_sha256,
            "outbox_path": self.outbox_path,
            "error": self.error,
        }
        if include_capsule:
            value["capsule"] = dict(self.capsule or {})
        return value


def _canonical_content(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _validate_capsule(capsule: Any, assessment_bytes: bytes) -> str:
    if not isinstance(capsule, dict) or set(capsule) != {
        "content", "content_sha256", "attestations",
    }:
        raise ValueError("Palimpsest returned an invalid capsule envelope")
    content = capsule["content"]
    digest = capsule["content_sha256"]
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ValueError("Palimpsest capsule digest is invalid")
    if hashlib.sha256(_canonical_content(content)).hexdigest() != digest:
        raise ValueError("Palimpsest capsule content digest does not verify")
    if not isinstance(capsule["attestations"], list):
        raise ValueError("Palimpsest capsule attestations are invalid")
    if not isinstance(content, dict):
        raise ValueError("Palimpsest capsule content is invalid")
    artifacts = content.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("Palimpsest capsule has no artifacts")
    artifact = next(
        (item for item in artifacts if isinstance(item, dict)
         and item.get("id") == "assessment"), None,
    )
    if artifact is None:
        raise ValueError("Palimpsest capsule does not bind the assessment")
    location = artifact.get("location", {})
    if not isinstance(location, dict) or location.get("type") != "inline":
        raise ValueError("Palimpsest assessment artifact is not inline")
    try:
        decoded = base64.b64decode(location.get("data", ""), validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Palimpsest assessment artifact is not valid base64") from exc
    if decoded != assessment_bytes:
        raise ValueError("Palimpsest capsule binds different assessment bytes")
    if artifact.get("sha256") != hashlib.sha256(decoded).hexdigest():
        raise ValueError("Palimpsest assessment artifact digest is invalid")
    if artifact.get("size") != len(decoded):
        raise ValueError("Palimpsest assessment artifact size is invalid")
    return digest


class PalimpsestBridge:
    """Invoke Palimpsest as a one-shot subprocess, never a shell command."""

    def __init__(
        self,
        root: str | Path,
        *,
        outbox: str = "var/scamshield-inbox",
        timeout_seconds: float = 15.0,
    ):
        self.root = Path(root).expanduser().resolve()
        self.script = self.root / "scripts" / "scamshield_bridge.py"
        relative = Path(outbox)
        if (not outbox or relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)):
            raise ValueError("Palimpsest outbox must be a safe relative path")
        self.outbox = relative.as_posix()
        if not 0 < timeout_seconds <= 120:
            raise ValueError("Palimpsest timeout must be in (0, 120] seconds")
        self.timeout_seconds = timeout_seconds

    def publish(self, assessment: Mapping[str, Any]) -> BridgeReceipt:
        try:
            validate_assessment_shape(assessment)
            raw = _canonical_content(assessment)
            if len(raw) > MAX_ASSESSMENT_BYTES:
                raise ValueError("assessment exceeds the 1 MiB bridge limit")
            if not self.script.is_file():
                raise ValueError(f"Palimpsest bridge is missing: {self.script}")
            # The bridge needs locale/path information, not Telegram tokens,
            # API keys, database URLs, or the source-pseudonym HMAC key.
            environment = {
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1",
            }
            for name in ("PATH", "LANG", "LC_ALL", "TZ"):
                if os.environ.get(name):
                    environment[name] = os.environ[name]
            result = subprocess.run(
                [sys.executable, str(self.script), "--outbox", self.outbox],
                input=raw,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.root,
                env=environment,
                timeout=self.timeout_seconds,
                check=False,
            )
            if len(result.stdout) > MAX_CAPSULE_BYTES:
                raise ValueError("Palimpsest response exceeds the capsule limit")
            if result.returncode != 0:
                detail = result.stderr.decode("utf-8", "replace")[:2048].strip()
                raise ValueError(
                    f"Palimpsest bridge exited {result.returncode}: {detail}"
                )
            try:
                capsule = json.loads(
                    result.stdout.decode("utf-8"),
                    parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError(f"non-finite JSON number {value}")
                    ),
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Palimpsest returned invalid JSON: {exc}") from exc
            capsule_sha256 = _validate_capsule(capsule, raw)
            return BridgeReceipt(
                status="STORED",
                capsule_sha256=capsule_sha256,
                outbox_path=(self.root / self.outbox / f"{capsule_sha256}.json").as_posix(),
                capsule=capsule,
            )
        except subprocess.TimeoutExpired:
            return BridgeReceipt(status="FAILED", error="Palimpsest bridge timed out")
        except (OSError, TypeError, ValueError) as exc:
            return BridgeReceipt(status="FAILED", error=str(exc)[:2048])


__all__ = ["BridgeReceipt", "PalimpsestBridge"]
