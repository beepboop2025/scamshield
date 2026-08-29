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
    reporting_steps,
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
        self.assertEqual(payload["interfaces"]["mcp"]["visibility"], "local-only")
        self.assertEqual(
            payload["interfaces"]["mcp"]["protocol_versions"][0],
            "2026-07-28",
        )
        self.assertEqual(
            payload["interfaces"]["mcp"]["manifest"],
            "mcp/server.local.json",
        )
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
        self.assertEqual(payload["info"]["version"], "1.1.0")
        self.assertEqual(payload["servers"][0]["url"], "http://127.0.0.1:8794")
        self.assertIn("/v1/assess", payload["paths"])


class MCPContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mcp = _load_mcp_module()

    def test_initialize_negotiates_current_and_prior_protocols(self):
        for request_id, protocol in enumerate(
            ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"),
            start=1,
        ):
            with self.subTest(protocol=protocol):
                initialized = self.mcp.dispatch({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "initialize",
                    "params": {"protocolVersion": protocol},
                })
                self.assertEqual(initialized["result"]["serverInfo"]["version"], "1.1.0")
                self.assertEqual(initialized["result"]["protocolVersion"], protocol)

        fallback = self.mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "initialize",
            "params": {"protocolVersion": "2099-01-01"},
        })
        self.assertEqual(fallback["result"]["protocolVersion"], "2026-07-28")

    def test_tools_list_has_closed_typed_contracts_and_annotations(self):
        listed = self.mcp.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = listed["result"]["tools"]
        names = {item["name"] for item in tools}
        self.assertEqual(names, {
            "list_capabilities", "assess_message", "list_typologies", "get_reporting_steps",
        })
        for tool in tools:
            with self.subTest(tool=tool["name"]):
                self.assertEqual(
                    tool["inputSchema"]["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertEqual(
                    tool["outputSchema"]["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertFalse(tool["outputSchema"]["additionalProperties"])
                self.assertTrue(tool["annotations"]["readOnlyHint"])
                self.assertTrue(tool["annotations"]["idempotentHint"])
                self.assertFalse(tool["annotations"]["destructiveHint"])

    def test_every_tool_returns_text_and_structured_content_in_parity(self):
        expected_by_name = {
            "list_capabilities": capabilities(),
            "assess_message": assess_message(
                "A suspicious payment request for review",
                service=_service(),
            ),
            "list_typologies": typology_catalog(),
            "get_reporting_steps": reporting_steps(),
        }
        patches = {
            "list_capabilities": "capabilities",
            "assess_message": "assess_message",
            "list_typologies": "typology_catalog",
            "get_reporting_steps": "reporting_steps",
        }
        for request_id, (name, expected) in enumerate(expected_by_name.items(), start=20):
            arguments = {"text": "ignored by patched analyzer"} if name == "assess_message" else {}
            with self.subTest(tool=name), patch.object(
                self.mcp,
                patches[name],
                return_value=expected,
            ):
                response = self.mcp.dispatch({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                })
                result = response["result"]
                self.assertEqual(result["structuredContent"], expected)
                self.assertEqual(json.loads(result["content"][0]["text"]), expected)
                self.assertFalse(result["isError"])

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

        unexpected = self.mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "assess_message",
                "arguments": {"text": "hello", "persist": True},
            },
        })
        self.assertEqual(unexpected["error"]["code"], -32602)
        self.assertIn("unexpected argument", unexpected["error"]["message"])

        no_arg_tool = self.mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "list_capabilities", "arguments": {"verbose": True}},
        })
        self.assertEqual(no_arg_tool["error"]["code"], -32602)

    def test_local_manifest_is_truthful_and_installable_without_publication_claims(self):
        manifest = json.loads((ROOT / "mcp" / "server.local.json").read_text())
        template = json.loads((ROOT / "mcp" / "client-config.example.json").read_text())
        self.assertEqual(manifest["version"], "1.1.0")
        self.assertEqual(manifest["visibility"], "local-only")
        self.assertEqual(manifest["transport"]["type"], "stdio")
        self.assertIsNone(manifest["privacy"]["remote_endpoint"])
        self.assertFalse(manifest["publication"]["mcp_registry"])
        self.assertFalse(manifest["publication"]["public_remote_server"])
        self.assertFalse(manifest["publication"]["a2a_agent_card"])
        self.assertEqual(
            set(manifest["tools"]),
            {item["name"] for item in self.mcp.TOOLS},
        )
        self.assertEqual(
            template["mcpServers"]["scamshield"]["command"],
            "python3",
        )

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
