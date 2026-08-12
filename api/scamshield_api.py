#!/usr/bin/env python3
"""Loopback-first REST API for ScamShield's non-persisting analyzer."""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scamshield.surfaces import (  # noqa: E402
    MAX_TEXT_BYTES,
    assess_message,
    capabilities,
    reporting_steps,
    typology_catalog,
)

MAX_BODY_BYTES = MAX_TEXT_BYTES + 4096


class ScamShieldAPI(BaseHTTPRequestHandler):
    server_version = "ScamShieldAPI/1.0"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _path(self) -> str:
        return urlsplit(self.path).path.rstrip("/") or "/"

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        routes = {
            "/v1/health": lambda: {"ok": True, "service": "scamshield", "version": "1.0.0"},
            "/v1/capabilities": capabilities,
            "/v1/typologies": typology_catalog,
            "/v1/reporting": reporting_steps,
            "/openapi.json": lambda: json.loads((ROOT / "openapi.json").read_text(encoding="utf-8")),
        }
        handler = routes.get(self._path())
        if handler is None:
            self._json(404, {"error": "not_found"})
            return
        try:
            self._json(200, handler())
        except Exception:
            self._json(503, {"error": "surface_unavailable"})

    def do_POST(self) -> None:  # noqa: N802
        if self._path() != "/v1/assess":
            self._json(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid_content_length"})
            return
        if size <= 0 or size > MAX_BODY_BYTES:
            self._json(413, {"error": "request_too_large"})
            return
        try:
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("body must be a JSON object")
            self._json(200, assess_message(payload.get("text")))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            self._json(400, {"error": "invalid_request", "message": str(exc)})
        except Exception:
            self._json(503, {"error": "assessment_unavailable"})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Deliberately do not emit request headers or bodies. The standard
        # format contains only the method/path/status and is sufficient here.
        sys.stderr.write("scamshield-api " + (fmt % args) + "\n")


def main() -> None:
    host = os.environ.get("SCAMSHIELD_API_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "::1", "localhost"} and os.environ.get(
        "SCAMSHIELD_ALLOW_REMOTE_API", "0"
    ) != "1":
        raise SystemExit(
            "Refusing a non-loopback bind. Set SCAMSHIELD_ALLOW_REMOTE_API=1 only "
            "behind authentication and rate limiting."
        )
    port = int(os.environ.get("SCAMSHIELD_API_PORT", "8794"))
    server = ThreadingHTTPServer((host, port), ScamShieldAPI)
    print(f"ScamShield API listening on http://{host}:{port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
