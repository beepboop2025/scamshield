"""Contract tests for ScamShield REST/MCP-facing behavior."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scamshield.analysis import AnalysisService
from scamshield.provenance import ProvenanceEngine
from scamshield.rates import RateQuote
from scamshield.surfaces import (
    ASSESSMENT_SCHEMA,
    MAX_TEXT_CHARS,
    assess_message,
    capabilities,
    typology_catalog,
)


class _FixedOracle:
    def quote(self) -> RateQuote:
        return RateQuote(
            rate=90.0,
            status="FALLBACK",
            observed_at="2026-08-12T00:00:00Z",
            sources=("offline_fixture",),
            source_urls=(),
            spread_pct=None,
            warnings=("offline test quote",),
        )


def _service() -> AnalysisService:
    pack = ROOT / "scamshield" / "data" / "intelligence-pack-v1.json"
    return AnalysisService(
        rate_oracle=_FixedOracle(),
        provenance_engine=ProvenanceEngine.from_path(pack),
        bridge=None,
    )


def _load_mcp_module():
    path = ROOT / "mcp" / "scamshield_mcp.py"
    spec = importlib.util.spec_from_file_location("scamshield_mcp_contract", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class PublicSurfaceContract(unittest.TestCase):
    def test_capabilities_make_privacy_and_transport_explicit(self):
        payload = capabilities()
        self.assertEqual(payload["product"], "ScamShield")
        self.assertEqual(payload["interfaces"]["mcp"]["transport"], "stdio")
        self.assertEqual(payload["interfaces"]["rest"]["transport"], "loopback HTTP by default")
        self.assertFalse(payload["privacy"]["bridge_side_effects"])
        self.assertFalse(payload["privacy"]["ioc_values_returned"])

    def test_typology_catalog_is_bounded_and_versioned(self):
        payload = typology_catalog()
        self.assertEqual(payload["version"], "2026-08-08.2")
        self.assertEqual(payload["source_count"], 18)
        self.assertEqual(len(payload["typologies"]), 8)
        rendered = json.dumps(payload)
        self.assertNotIn("any_terms", rendered)
        self.assertNotIn("all_signals", rendered)

    def test_assessment_never_reemits_text_or_exact_iocs(self):
        secret_handle = "@do_not_echo_948217"
        secret_url = "https://example.invalid/credential-check-948217"
        text = (
            f"Your bank account suspended. Click {secret_url} to verify and "
            f"send your OTP to {secret_handle} now."
        )
        payload = assess_message(text, service=_service())
        rendered = json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["schema_version"], ASSESSMENT_SCHEMA)
        self.assertFalse(payload["privacy"]["stored"])
        self.assertFalse(payload["privacy"]["bridged"])
        self.assertNotIn(secret_handle, rendered)
        self.assertNotIn(secret_url, rendered)
        self.assertGreaterEqual(payload["result"]["ioc_summary"].get("urls", 0), 1)

    def test_input_boundaries_fail_before_analysis(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            assess_message("", service=_service())
        with self.assertRaisesRegex(ValueError, "exceeds"):
            assess_message("x" * (MAX_TEXT_CHARS + 1), service=_service())
        with self.assertRaisesRegex(TypeError, "must be a string"):
            assess_message({"text": "not a string"}, service=_service())

    def test_openapi_matches_local_safety_boundary(self):
        payload = json.loads((ROOT / "openapi.json").read_text())
        self.assertEqual(payload["info"]["version"], "1.0.0")
        self.assertEqual(payload["servers"][0]["url"], "http://127.0.0.1:8794")
        self.assertIn("/v1/assess", payload["paths"])


class MCPContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mcp = _load_mcp_module()

    def test_initialize_and_tools_list(self):
        initialized = self.mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        })
        self.assertEqual(initialized["result"]["serverInfo"]["version"], "1.0.0")
        self.assertEqual(initialized["result"]["protocolVersion"], "2025-03-26")
        listed = self.mcp.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {item["name"] for item in listed["result"]["tools"]}
        self.assertEqual(names, {
            "list_capabilities", "assess_message", "list_typologies", "get_reporting_steps",
        })

    def test_assess_tool_returns_structured_content(self):
        fake = {"schema_version": ASSESSMENT_SCHEMA, "result": {"tier": "WATCH"}}
        with patch.object(self.mcp, "assess_message", return_value=fake):
            response = self.mcp.dispatch({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "assess_message", "arguments": {"text": "hello"}},
            })
        self.assertEqual(response["result"]["structuredContent"], fake)
        self.assertFalse(response["result"]["isError"])

    def test_invalid_assess_input_is_an_mcp_parameter_error(self):
        response = self.mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "assess_message", "arguments": {}},
        })
        self.assertEqual(response["error"]["code"], -32602)

    def test_every_valid_notification_is_processed_without_a_response(self):
        self.assertIsNone(self.mcp.dispatch({"jsonrpc": "2.0", "method": "ping"}))
        with patch.object(self.mcp, "assess_message", return_value={}) as assess:
            response = self.mcp.dispatch({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "assess_message", "arguments": {"text": "hello"}},
            })
        self.assertIsNone(response)
        assess.assert_called_once_with("hello")


if __name__ == "__main__":
    unittest.main()
