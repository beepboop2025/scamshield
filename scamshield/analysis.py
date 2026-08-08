"""One orchestration surface for every ScamShield ingestion path."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .detector import Verdict, classify, extract_iocs
from .palimpsest import BridgeReceipt, PalimpsestBridge
from .provenance import ExternalObservation, ProvenanceAssessment, ProvenanceEngine
from .rates import MarketRateOracle, RateQuote
from .threats import TIER_RANK, ThreatAssessment, ThreatEngine

COLLECTION_SCHEMA = "scamshield-collection/v1"
SURFACES = {
    "private_submission", "guardian_group", "public_channel",
    "authorized_private_channel", "offline_import",
}
AUTHORIZATIONS = {
    "user_submitted", "public", "administrator_authorized", "operator_authorized",
}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _script_hints(text: str) -> tuple[str, ...]:
    hints: list[str] = []
    if any("A" <= character <= "Z" or "a" <= character <= "z" for character in text):
        hints.append("latin")
    if any("\u0900" <= character <= "\u097f" for character in text):
        hints.append("devanagari")
    if any("\u3400" <= character <= "\u9fff" for character in text):
        hints.append("han")
    if any("\u0600" <= character <= "\u06ff" for character in text):
        hints.append("arabic")
    if any("\u0400" <= character <= "\u04ff" for character in text):
        hints.append("cyrillic")
    return tuple(hints or ("undetermined",))


def _source_pseudonym(source: str, secret: str) -> str:
    if not source or not secret:
        return ""
    return hmac.new(
        secret.encode("utf-8"), source.encode("utf-8"), hashlib.sha256,
    ).hexdigest()[:24]


@dataclass(frozen=True)
class ObservationContext:
    surface: str
    authorization: str
    source_pseudonym: str = ""
    script_hints: tuple[str, ...] = ()
    observed_at: str = ""

    @classmethod
    def create(
        cls,
        text: str,
        *,
        surface: str,
        authorization: str,
        raw_source: str = "",
        pseudonym_key: str | None = None,
        observed_at: str = "",
    ) -> "ObservationContext":
        if surface not in SURFACES:
            raise ValueError(f"unknown collection surface {surface!r}")
        if authorization not in AUTHORIZATIONS:
            raise ValueError(f"unknown collection authorization {authorization!r}")
        secret = (
            os.environ.get("SCAMSHIELD_PSEUDONYM_KEY", "")
            if pseudonym_key is None else pseudonym_key
        )
        return cls(
            surface=surface,
            authorization=authorization,
            source_pseudonym=_source_pseudonym(raw_source, secret),
            script_hints=_script_hints(text),
            observed_at=observed_at or _utc_iso(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": COLLECTION_SCHEMA,
            "surface": self.surface,
            "authorization": self.authorization,
            "source_pseudonym": self.source_pseudonym,
            "script_hints": list(self.script_hints),
            "observed_at": self.observed_at,
            "scope_note": (
                "ScamShield observes only submitted, public, or explicitly authorized "
                "Telegram surfaces; this record does not imply Telegram-wide visibility."
            ),
        }


@dataclass(frozen=True)
class AnalysisResult:
    detector: Verdict
    threats: ThreatAssessment
    rate: RateQuote
    provenance: ProvenanceAssessment
    collection: ObservationContext
    bridge: BridgeReceipt
    overall_tier: str
    overall_score: int

    @property
    def iocs(self) -> Mapping[str, list[str]]:
        raw = self.provenance.detector.get("iocs", {})
        return raw if isinstance(raw, Mapping) else {}


class AnalysisService:
    """Fuse all local classifiers and optionally hand evidence to Palimpsest."""

    def __init__(
        self,
        *,
        rate_oracle: MarketRateOracle,
        provenance_engine: ProvenanceEngine,
        threat_engine: ThreatEngine | None = None,
        bridge: PalimpsestBridge | None = None,
        share_min_tier: str = "WATCH",
    ):
        self.rate_oracle = rate_oracle
        self.provenance_engine = provenance_engine
        self.threat_engine = threat_engine or ThreatEngine()
        self.bridge = bridge
        if share_min_tier not in TIER_RANK:
            raise ValueError("share_min_tier is unknown")
        self.share_min_tier = share_min_tier

    @classmethod
    def from_environment(cls) -> "AnalysisService":
        palimpsest_root_raw = os.environ.get("SCAMSHIELD_PALIMPSEST_ROOT", "").strip()
        palimpsest_root = Path(palimpsest_root_raw).expanduser() if palimpsest_root_raw else None
        pack_override = os.environ.get("SCAMSHIELD_INTELLIGENCE_PACK", "").strip()
        if pack_override:
            pack_path = Path(pack_override).expanduser()
        elif palimpsest_root and (
            palimpsest_root / "integrations" / "scamshield" / "intelligence-pack-v1.json"
        ).is_file():
            pack_path = (
                palimpsest_root / "integrations" / "scamshield" /
                "intelligence-pack-v1.json"
            )
        else:
            pack_path = Path(__file__).with_name("data") / "intelligence-pack-v1.json"
        bridge = None
        if palimpsest_root:
            bridge = PalimpsestBridge(
                palimpsest_root,
                outbox=os.environ.get(
                    "SCAMSHIELD_PALIMPSEST_OUTBOX", "var/scamshield-inbox"
                ),
            )
        return cls(
            rate_oracle=MarketRateOracle(),
            provenance_engine=ProvenanceEngine.from_path(pack_path),
            bridge=bridge,
            share_min_tier=os.environ.get("SCAMSHIELD_SHARE_MIN_TIER", "WATCH"),
        )

    def analyze(
        self,
        text: str,
        *,
        collection: ObservationContext | None = None,
        external_observations: Iterable[ExternalObservation] = (),
    ) -> AnalysisResult:
        context = collection or ObservationContext.create(
            text, surface="private_submission", authorization="user_submitted",
        )
        quote = self.rate_oracle.quote()
        detector = classify(
            text,
            market_rate=quote.rate,
            allow_rate=quote.numeric_detection_allowed,
        )
        threats = self.threat_engine.assess(text, detector)
        threat_rank = TIER_RANK[threats.tier]
        detector_rank = TIER_RANK[detector.tier]
        if threat_rank > detector_rank:
            overall_tier = threats.tier
            overall_score = threats.score
        elif detector_rank > threat_rank:
            overall_tier = detector.tier
            overall_score = detector.score
        else:
            overall_tier = detector.tier
            overall_score = max(detector.score, threats.score)
        observed_iocs = (
            extract_iocs(text) if TIER_RANK[overall_tier] >= TIER_RANK["WATCH"]
            else detector.iocs
        )
        evidence_verdict = Verdict(
            score=detector.score,
            tier=detector.tier,
            signals=list(detector.signals),
            iocs=observed_iocs,
            families=set(detector.families),
            notes=list(detector.notes),
            car_score=detector.car_score,
        )
        provenance = self.provenance_engine.assess(
            text,
            evidence_verdict,
            market_rate=quote.to_dict(),
            threat_assessment=threats.to_dict(),
            collection=context.to_dict(),
            additional_signals=threats.signal_names,
            external_observations=external_observations,
        )
        assessment_dict = provenance.to_dict()
        if self.bridge is None:
            bridge = BridgeReceipt(status="DISABLED")
        elif TIER_RANK[overall_tier] < TIER_RANK[self.share_min_tier]:
            bridge = BridgeReceipt(status="SKIPPED")
        else:
            bridge = self.bridge.publish(assessment_dict)
        return AnalysisResult(
            detector=detector,
            threats=threats,
            rate=quote,
            provenance=provenance,
            collection=context,
            bridge=bridge,
            overall_tier=overall_tier,
            overall_score=overall_score,
        )


__all__ = [
    "AnalysisResult", "AnalysisService", "ObservationContext",
]
