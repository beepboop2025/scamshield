"""Exercise ScamShield's actual loopback HTTP boundary."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_api():
    path = ROOT / "api" / "scamshield_api.py"
    spec = importlib.util.spec_from_file_location("scamshield_api_contract", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class LoopbackHTTPContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.api.ScamShieldAPI)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def get(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=2) as response:
            return response.status, dict(response.headers), json.load(response)

    def post(self, path: str, payload: bytes):
        request = urllib.request.Request(
            self.base + path,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.load(exc)
            finally:
                exc.close()

    def test_health_and_openapi_are_discoverable(self):
        status, headers, health = self.get("/v1/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["ok"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, _headers, contract = self.get("/openapi.json")
        self.assertEqual(status, 200)
        self.assertEqual(contract["openapi"], "3.1.0")

    def test_assessment_serializes_shared_contract_without_persistence(self):
        expected = {
            "schema_version": "scamshield-public-assessment/v1",
            "privacy": {"stored": False, "bridged": False},
        }
        with patch.object(self.api, "assess_message", return_value=expected) as assess:
            status, payload = self.post(
                "/v1/assess", json.dumps({"text": "untrusted sample"}).encode()
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload, expected)
        assess.assert_called_once_with("untrusted sample")

    def test_invalid_json_and_oversized_requests_fail_before_assessment(self):
        with patch.object(self.api, "assess_message") as assess:
            status, payload = self.post("/v1/assess", b"{not-json")
            self.assertEqual(status, 400)
            self.assertEqual(payload["error"], "invalid_request")
            status, payload = self.post(
                "/v1/assess", b"x" * (self.api.MAX_BODY_BYTES + 1)
            )
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"], "request_too_large")
        assess.assert_not_called()

    def test_unknown_route_is_explicit(self):
        try:
            self.get("/v1/private-review-queue")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.load(exc)
                self.assertEqual(exc.code, 404)
                self.assertEqual(payload["error"], "not_found")
            finally:
                exc.close()
        else:
            self.fail("private-looking route unexpectedly existed")


if __name__ == "__main__":
    unittest.main()
