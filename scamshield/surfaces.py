"""Privacy-safe contracts shared by ScamShield's API, MCP, and bots.

The production Telegram bot has an evidence store and an optional Palimpsest
bridge.  Public developer surfaces deliberately do not: submitted text is
classified in memory, is never written to the IOC/review databases, and is
never sent to the bridge.  Keeping this boundary in one module prevents an API
or MCP wrapper from growing a subtly different disclosure policy.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .analysis import AnalysisService, ObservationContext
from .provenance import ProvenanceEngine, load_intelligence_pack
from .rates import MarketRateOracle

SURFACE_VERSION = "1.0.0"
ASSESSMENT_SCHEMA = "scamshield-public-assessment/v1"
MAX_TEXT_CHARS = 8_000
MAX_TEXT_BYTES = 32_000
DEFAULT_PACK = Path(__file__).with_name("data") / "intelligence-pack-v1.json"

REPORTING_STEPS = (
    {
        "scope": "India financial cyber fraud",
        "action": "Call 1930 promptly and file at https://cybercrime.gov.in/.",
    },
    {
        "scope": "Telegram",
        "action": "Preserve the message link or screenshot, then use Report > Scam.",
    },
    {
        "scope": "Immediate danger",
        "action": "Contact local emergency services; do not confront the sender.",
    },
)

LIMITATIONS = (
    "A pattern match is a triage signal, not proof that a person, account, or payment is criminal.",
    "No supported pattern is not a guarantee of safety.",
    "Message text alone cannot establish the origin of funds or verify physical goods.",
    "Human review is required before moderation, reporting, or publication.",
)


def _pack_path() -> Path:
    override = os.environ.get("SCAMSHIELD_INTELLIGENCE_PACK", "").strip()
    return Path(override).expanduser() if override else DEFAULT_PACK


def create_public_service() -> AnalysisService:
    """Build the non-persisting analyzer used by API and MCP entrypoints."""
    return AnalysisService(
        rate_oracle=MarketRateOracle(),
        provenance_engine=ProvenanceEngine.from_path(_pack_path()),
        bridge=None,
    )


def capabilities() -> dict[str, Any]:
    return {
        "product": "ScamShield",
        "version": SURFACE_VERSION,
        "purpose": (
            "Privacy-conscious triage for suspicious messages, money-mule ads, "
            "phishing, impersonation, advance-fee scams, and illicit-market patterns."
        ),
        "interfaces": {
            "telegram": {
                "handle": "@Scamshield_2_bot",
                "mode": "private-message Shield mode",
            },
            "rest": {
                "transport": "loopback HTTP by default",
                "resources": ["capabilities", "typologies", "assess", "health"],
            },
            "mcp": {
                "transport": "stdio",
                "tools": [
                    "list_capabilities",
                    "assess_message",
                    "list_typologies",
                    "get_reporting_steps",
                ],
            },
        },
        "privacy": {
            "assessment_storage": "none",
            "bridge_side_effects": False,
            "raw_text_returned": False,
            "ioc_values_returned": False,
            "max_text_characters": MAX_TEXT_CHARS,
            "max_text_bytes": MAX_TEXT_BYTES,
        },
        "limitations": list(LIMITATIONS),
    }


def typology_catalog() -> dict[str, Any]:
    pack = load_intelligence_pack(_pack_path())
    return {
        "schema_version": pack.schema,
        "version": pack.version,
        "generated_at": pack.generated_at,
        "publisher": {
            "name": pack.publisher_name,
            "url": pack.publisher_url,
        },
        "digest_sha256": pack.digest_sha256,
        "source_count": len(pack.sources),
        "typologies": [
            {
                "id": item.id,
                "dimension": item.dimension,
                "label": item.label,
                "description": item.description,
                "indicator_count": len(item.indicators),
                "source_count": len(item.source_refs),
                "limitations": list(item.limitations),
            }
            for item in pack.typologies
        ],
        "principles": list(pack.principles),
    }


def reporting_steps() -> dict[str, Any]:
    return {
        "steps": list(REPORTING_STEPS),
        "preserve": [
            "message link or screenshot",
            "transaction reference and timestamp",
            "recipient account or wallet details",
        ],
        "do_not": [
            "pay a release, recovery, verification, or prepaid-deposit fee",
            "share OTPs, PINs, passwords, seed phrases, or remote-screen access",
            "rent or lend a UPI or bank account",
        ],
    }


def _validated_text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("text must be a string")
    text = value.strip()
    if not text:
        raise ValueError("text must not be empty")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"text exceeds {MAX_TEXT_CHARS} characters")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError(f"text exceeds {MAX_TEXT_BYTES} UTF-8 bytes")
    return text


def assess_message(
    text: Any,
    *,
    service: AnalysisService | None = None,
) -> dict[str, Any]:
    """Classify one message without retaining or re-emitting its contents."""
    submitted = _validated_text(text)
    analyzer = service or create_public_service()
    result = analyzer.analyze(
        submitted,
        collection=ObservationContext.create(
            submitted,
            surface="offline_import",
            authorization="user_submitted",
        ),
    )

    ioc_counts = {
        kind: len(values)
        for kind, values in result.iocs.items()
        if values
    }
    hypotheses = [
        {
            "typology_id": item.typology_id,
            "dimension": item.dimension,
            "label": item.label,
            "support_level": item.support_level,
            "evidence_classes": list(item.evidence_classes),
            "matched_indicators": [
                {
                    "id": indicator.id,
                    "label": indicator.label,
                    "specificity": indicator.specificity,
                }
                for indicator in item.matched_indicators
            ],
            "limitations": list(item.limitations),
        }
        for item in result.provenance.hypotheses
    ]
    return {
        "schema_version": ASSESSMENT_SCHEMA,
        "result": {
            "tier": result.overall_tier,
            "score": result.overall_score,
            "money_flow_signals": [
                {
                    "name": signal.name,
                    "family": signal.family,
                    "weight": signal.weight,
                }
                for signal in result.detector.signals
                if signal.weight > 0
            ][:12],
            "threat_findings": [
                {
                    "rule_id": finding.rule_id,
                    "family": finding.family,
                    "label": finding.label,
                    "tier": finding.tier,
                    "score": finding.score,
                    "evidence_classes": list(finding.evidence_classes),
                    "limitations": list(finding.limitations),
                }
                for finding in result.threats.findings
            ][:8],
            "provenance_hypotheses": hypotheses[:8],
            "ioc_summary": ioc_counts,
            "market_rate": {
                "status": result.rate.status,
                "observed_at": result.rate.observed_at,
                "source_count": len(result.rate.sources),
                "warnings": list(result.rate.warnings),
            },
        },
        "privacy": {
            "stored": False,
            "bridged": False,
            "raw_text_returned": False,
            "ioc_values_returned": False,
        },
        "limitations": list(LIMITATIONS),
        "reporting": reporting_steps(),
    }


__all__ = [
    "ASSESSMENT_SCHEMA",
    "MAX_TEXT_BYTES",
    "MAX_TEXT_CHARS",
    "assess_message",
    "capabilities",
    "create_public_service",
    "reporting_steps",
    "typology_catalog",
]
