"""Safe HTML rendering for composite ScamShield analysis results."""

from __future__ import annotations

import html

from .analysis import AnalysisResult
from .disclosure_policy import should_render_hypothesis

REPORT_FOOTER = (
    "\n\n<b>What to do:</b>\n"
    "• Do not pay, click, share credentials, buy, or confront the sender.\n"
    "• Preserve the message link/screenshot and report it inside Telegram.\n"
    "• For online financial fraud in India: 1930 / cybercrime.gov.in. "
    "For immediate danger, contact local emergency services."
)

_BADGE = {
    "CONFIRMED_PATTERN": "🔴 High-confidence prohibited/scam pattern",
    "LIKELY_SCAM": "🟠 Likely high-risk pattern",
    "WATCH": "🟡 Suspicious — human review needed",
    "CLEAN": "🟢 No supported high-risk pattern found",
}


def render_analysis(result: AnalysisResult, *, surface: str) -> str:
    out = [
        f"<b>{_BADGE[result.overall_tier]}</b> "
        f"(risk score {result.overall_score})"
    ]

    positive = [
        signal for signal in result.detector.signals
        if signal.weight > 0 and signal.family not in {"WEAK"}
    ][:6]
    if positive:
        out.append("\n<b>Money-flow signals:</b>")
        out.extend(
            f"• {html.escape(signal.detail)}"
            for signal in positive
        )

    if result.threats.findings:
        out.append("\n<b>Threat-family matches:</b>")
        for finding in result.threats.findings[:5]:
            evidence = ", ".join(finding.evidence_classes)
            out.append(
                f"• {html.escape(finding.label)} — "
                f"{html.escape(finding.tier)}; evidence: {html.escape(evidence)}"
            )

    rate_names = {
        "above_market_rate", "tiered_price_menu", "above_market_admission",
        "tiered_fund_menu", "account_type_price_sheet",
    }
    if "RATE" in result.detector.families or result.detector.names() & rate_names:
        source_text = ", ".join(result.rate.sources)
        out.append(
            "\n<b>USDT/INR reference:</b> "
            f"₹{result.rate.rate:.2f} ({html.escape(result.rate.status)}; "
            f"{html.escape(source_text)})"
        )
        if result.rate.warnings:
            out.append(f"• {html.escape(result.rate.warnings[0])}")

    visible = [
        hypothesis for hypothesis in result.provenance.hypotheses
        if should_render_hypothesis(hypothesis.support_level, surface)
    ]
    if visible:
        out.append("\n<b>Possible provenance:</b>")
        for hypothesis in visible[:4]:
            out.append(
                f"• [{html.escape(hypothesis.support_level)}] "
                f"{html.escape(hypothesis.label)} "
                f"({html.escape(hypothesis.dimension)})"
            )
        if surface in {"private_submission", "offline_import"}:
            out.append(html.escape(result.provenance.origin_answer))
        else:
            out.append(
                "Only independently corroborated or direct-link hypotheses are "
                "shown on shared surfaces."
            )
    elif result.overall_tier != "CLEAN" and surface in {
        "private_submission", "offline_import",
    }:
        out.append("\n<b>Possible provenance:</b>")
        out.append(html.escape(result.provenance.origin_answer))

    if result.overall_tier in {"LIKELY_SCAM", "CONFIRMED_PATTERN"}:
        out.append(REPORT_FOOTER)
    elif result.overall_tier == "CLEAN":
        out.append(
            "\nThis is not a guarantee of safety. ScamShield only reports the "
            "patterns supported by its current rules and evidence pack."
        )
    return "\n".join(out)


__all__ = ["render_analysis"]
