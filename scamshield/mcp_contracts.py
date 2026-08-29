"""Machine-readable contracts for ScamShield's local MCP server.

The schemas in this module are deliberately self-contained.  MCP clients can
validate ``structuredContent`` without importing ScamShield or learning its
internal detector classes, while the closed object shapes prevent accidental
disclosure of raw message or IOC fields.
"""

from __future__ import annotations

from typing import Any

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
LATEST_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = frozenset(
    {
        "2025-03-26",
        "2025-06-18",
        "2025-11-25",
        LATEST_PROTOCOL_VERSION,
    }
)
SERVER_VERSION = "1.1.0"


def _closed_object(
    properties: dict[str, Any],
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": False,
    }


def _string(*, const: str | None = None, uri: bool = False) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "minLength": 1}
    if const is not None:
        schema["const"] = const
    if uri:
        schema["format"] = "uri"
    return schema


def _string_array(*, max_items: int | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "items": _string(),
    }
    if max_items is not None:
        schema["maxItems"] = max_items
    return schema


REPORTING_BODY_SCHEMA = _closed_object(
    {
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": _closed_object(
                {
                    "scope": _string(),
                    "action": _string(),
                }
            ),
        },
        "preserve": _string_array(),
        "do_not": _string_array(),
    }
)

REPORTING_OUTPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    **REPORTING_BODY_SCHEMA,
}

CAPABILITIES_OUTPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    **_closed_object(
        {
            "product": _string(const="ScamShield"),
            "version": _string(const=SERVER_VERSION),
            "purpose": _string(),
            "interfaces": _closed_object(
                {
                    "telegram": _closed_object(
                        {
                            "handle": _string(),
                            "mode": _string(),
                        }
                    ),
                    "rest": _closed_object(
                        {
                            "transport": _string(const="loopback HTTP by default"),
                            "resources": _string_array(),
                        }
                    ),
                    "mcp": _closed_object(
                        {
                            "transport": _string(const="stdio"),
                            "visibility": _string(const="local-only"),
                            "protocol_versions": {
                                "type": "array",
                                "items": _string(),
                                "minItems": 1,
                                "uniqueItems": True,
                            },
                            "manifest": _string(const="mcp/server.local.json"),
                            "tools": _string_array(),
                        }
                    ),
                }
            ),
            "privacy": _closed_object(
                {
                    "assessment_storage": _string(const="none"),
                    "bridge_side_effects": {"const": False},
                    "raw_text_returned": {"const": False},
                    "ioc_values_returned": {"const": False},
                    "max_text_characters": {"type": "integer", "minimum": 1},
                    "max_text_bytes": {"type": "integer", "minimum": 1},
                }
            ),
            "limitations": _string_array(),
        }
    ),
}

TYPOLOGY_OUTPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    **_closed_object(
        {
            "schema_version": _string(),
            "version": _string(),
            "generated_at": {**_string(), "format": "date-time"},
            "publisher": _closed_object(
                {
                    "name": _string(),
                    "url": _string(uri=True),
                }
            ),
            "digest_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_count": {"type": "integer", "minimum": 0},
            "typologies": {
                "type": "array",
                "items": _closed_object(
                    {
                        "id": _string(),
                        "dimension": _string(),
                        "label": _string(),
                        "description": _string(),
                        "indicator_count": {"type": "integer", "minimum": 0},
                        "source_count": {"type": "integer", "minimum": 0},
                        "limitations": _string_array(),
                    }
                ),
            },
            "principles": _string_array(),
        }
    ),
}

ASSESSMENT_OUTPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    **_closed_object(
        {
            "schema_version": _string(const="scamshield-public-assessment/v1"),
            "result": _closed_object(
                {
                    "tier": {
                        "type": "string",
                        "enum": ["CLEAN", "WATCH", "LIKELY_SCAM", "CONFIRMED_PATTERN"],
                    },
                    "score": {"type": "integer", "minimum": 0},
                    "money_flow_signals": {
                        "type": "array",
                        "maxItems": 12,
                        "items": _closed_object(
                            {
                                "name": _string(),
                                "family": _string(),
                                "weight": {"type": "integer", "minimum": 1},
                            }
                        ),
                    },
                    "threat_findings": {
                        "type": "array",
                        "maxItems": 8,
                        "items": _closed_object(
                            {
                                "rule_id": _string(),
                                "family": _string(),
                                "label": _string(),
                                "tier": {
                                    "type": "string",
                                    "enum": [
                                        "WATCH",
                                        "LIKELY_SCAM",
                                        "CONFIRMED_PATTERN",
                                    ],
                                },
                                "score": {"type": "integer", "minimum": 0},
                                "evidence_classes": _string_array(),
                                "limitations": _string_array(),
                            }
                        ),
                    },
                    "provenance_hypotheses": {
                        "type": "array",
                        "maxItems": 8,
                        "items": _closed_object(
                            {
                                "typology_id": _string(),
                                "dimension": _string(),
                                "label": _string(),
                                "support_level": {
                                    "type": "string",
                                    "enum": [
                                        "TYPOLOGY_MATCH",
                                        "CORROBORATED_LEAD",
                                        "DIRECT_LINK",
                                    ],
                                },
                                "evidence_classes": _string_array(),
                                "matched_indicators": {
                                    "type": "array",
                                    "items": _closed_object(
                                        {
                                            "id": _string(),
                                            "label": _string(),
                                            "specificity": {
                                                "type": "string",
                                                "enum": ["low", "medium", "high"],
                                            },
                                        }
                                    ),
                                },
                                "limitations": _string_array(),
                            }
                        ),
                    },
                    "ioc_summary": _closed_object(
                        {
                            "handles": {"type": "integer", "minimum": 1},
                            "phones": {"type": "integer", "minimum": 1},
                            "channels": {"type": "integer", "minimum": 1},
                            "wallets": {"type": "integer", "minimum": 1},
                            "emails": {"type": "integer", "minimum": 1},
                            "urls": {"type": "integer", "minimum": 1},
                        },
                        required=[],
                    ),
                    "market_rate": _closed_object(
                        {
                            "status": {
                                "type": "string",
                                "enum": [
                                    "CORROBORATED",
                                    "SINGLE_SOURCE",
                                    "DIVERGENT",
                                    "STALE",
                                    "FALLBACK",
                                ],
                            },
                            "observed_at": {**_string(), "format": "date-time"},
                            "source_count": {"type": "integer", "minimum": 0},
                            "warnings": _string_array(),
                        }
                    ),
                }
            ),
            "privacy": _closed_object(
                {
                    "stored": {"const": False},
                    "bridged": {"const": False},
                    "raw_text_returned": {"const": False},
                    "ioc_values_returned": {"const": False},
                }
            ),
            "limitations": _string_array(),
            "reporting": REPORTING_BODY_SCHEMA,
        }
    ),
}


EMPTY_INPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

ASSESS_INPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    "type": "object",
    "properties": {
        "text": {"type": "string", "minLength": 1, "maxLength": 8000},
    },
    "required": ["text"],
    "additionalProperties": False,
}

TOOL_CONTRACTS = (
    {
        "name": "list_capabilities",
        "title": "List ScamShield capabilities",
        "description": "Discover ScamShield's supported, privacy-bounded interfaces.",
        "inputSchema": EMPTY_INPUT_SCHEMA,
        "outputSchema": CAPABILITIES_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "assess_message",
        "title": "Assess a suspicious message",
        "description": (
            "Classify one user-supplied message in memory. Returns pattern evidence, "
            "limits, and reporting steps; never returns raw text or IOC values."
        ),
        "inputSchema": ASSESS_INPUT_SCHEMA,
        "outputSchema": ASSESSMENT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "list_typologies",
        "title": "List evidence typologies",
        "description": "Inspect the versioned ScamShield typology catalog and its limits.",
        "inputSchema": EMPTY_INPUT_SCHEMA,
        "outputSchema": TYPOLOGY_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_reporting_steps",
        "title": "Get scam reporting steps",
        "description": "Return preservation, reporting, and immediate-safety guidance.",
        "inputSchema": EMPTY_INPUT_SCHEMA,
        "outputSchema": REPORTING_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
)

TOOL_NAMES = frozenset(contract["name"] for contract in TOOL_CONTRACTS)


__all__ = [
    "LATEST_PROTOCOL_VERSION",
    "SERVER_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "TOOL_CONTRACTS",
    "TOOL_NAMES",
]
