"""Pure parsing and rendering helpers for the owner liquidity commands."""

from __future__ import annotations

import html
import re
from datetime import date, datetime, timezone
from typing import Iterable, Mapping

from .liquidity import MonetaryObservation

REVIEWABLE_MEASURES = {
    "amount_mentioned",
    "payment_requested",
    "victim_reported_loss",
    "verified_transfer",
}

_MEASURE_LABELS = {
    "amount_mentioned": "Amount mentioned",
    "estimated_proceeds": "Estimated proceeds",
    "payment_requested": "Payment requested",
    "suspicious_activity": "Suspicious activity",
    "verified_transfer": "Verified transfer",
    "victim_reported_loss": "Victim-reported loss",
}

_STATUS_LABELS = {
    "COUNT_ONLY": "count only",
    "INSUFFICIENT_DATA": "insufficient coverage",
    "PUBLISHED_OBSERVED_SUM": "observed sum",
    "WITHHELD_INCOMPLETE_NORMALIZATION": "sum withheld: incomplete FX normalization",
    "WITHHELD_INCOMPLETE_SOURCE": "sum withheld: incomplete source coverage",
    "WITHHELD_MIN_EVENTS": "sum withheld: too few reviewed events",
    "WITHHELD_SOURCE_DIVERSITY": "sum withheld: insufficient source diversity",
    "WITHHELD_SOURCE_DOMINANCE": "sum withheld: one source dominates events",
    "WITHHELD_VALUE_DOMINANCE": "sum withheld: one source dominates value",
}

_REVIEW_ID = re.compile(r"(?:Review ID|review-id):\s*([0-9a-f]{24})", re.IGNORECASE)


def review_usage() -> str:
    return (
        "Reply to a previously scanned suspicious message with:\n"
        "<code>/review_amount &lt;measure&gt; &lt;currency&gt; &lt;amount&gt; "
        "&lt;rail&gt; &lt;verification&gt; &lt;confidence&gt; "
        "[usd=&lt;amount&gt;] [fx=&lt;https-url-or-urn&gt;]</code>\n\n"
        "Measures: amount_mentioned, payment_requested, "
        "victim_reported_loss, verified_transfer. Values are accepted only "
        "as an explicit owner review; message text is never auto-summed. "
        "You may also reply to a configured-channel alert containing a Review ID."
    )


def review_id_from_alert(text: str) -> str:
    match = _REVIEW_ID.search(text or "")
    return match.group(1).lower() if match else ""


def parse_review_observation(
    args: Iterable[str],
    review_context: Mapping[str, str],
) -> MonetaryObservation:
    """Turn owner-supplied fields into one validated reviewed observation."""
    positional: list[str] = []
    options: dict[str, str] = {}
    for token in args:
        if "=" not in token:
            positional.append(token)
            continue
        key, value = token.split("=", 1)
        if key not in {"usd", "fx"} or not value or key in options:
            raise ValueError(f"unknown or duplicate option {key!r}")
        options[key] = value
    if len(positional) != 6:
        raise ValueError("review command requires exactly six positional fields")
    measure_type, currency, amount, rail, verification, confidence = positional
    if measure_type not in REVIEWABLE_MEASURES:
        raise ValueError(f"measure {measure_type!r} is not reviewable in Telegram")

    assessment_id = review_context.get("assessment_id", "")
    event_at = review_context.get("event_at", "")
    source_pseudonym = review_context.get("source_pseudonym", "")
    return MonetaryObservation(
        observation_id=f"review:{assessment_id}:{measure_type}",
        event_key=f"assessment:{assessment_id}",
        measure_type=measure_type,
        event_at=event_at,
        source_pseudonym=source_pseudonym,
        currency=currency.upper(),
        amount_low=amount,
        usd_low=options.get("usd"),
        rail=rail,
        verification=verification,
        attribution_confidence=confidence,
        evidence_refs=(assessment_id,),
        fx_rate_ref=options.get("fx", ""),
    )


def parse_pulse_day(args: Iterable[str], *, today: date | None = None) -> date:
    values = list(args)
    if len(values) > 1:
        raise ValueError("use /liquidity or /liquidity YYYY-MM-DD")
    if not values:
        return today or datetime.now(timezone.utc).date()
    try:
        selected = date.fromisoformat(values[0])
    except ValueError as exc:
        raise ValueError("liquidity date must be YYYY-MM-DD") from exc
    current = today or datetime.now(timezone.utc).date()
    if selected > current:
        raise ValueError("liquidity date cannot be in the future")
    return selected


def render_review_confirmation(observation: MonetaryObservation) -> str:
    normalization = ""
    if observation.currency != "USD":
        if observation.usd_low is None:
            normalization = " USD sum will remain withheld until reviewed FX is supplied."
        else:
            normalization = f" Reviewed USD value: {html.escape(observation.usd_low)}."
    return (
        "✅ <b>Reviewed monetary observation saved</b>\n"
        f"{html.escape(_MEASURE_LABELS[observation.measure_type])}: "
        f"{html.escape(observation.currency)} {html.escape(observation.amount_low)}\n"
        f"Rail: {html.escape(observation.rail)} · "
        f"verification: {html.escape(observation.verification)}."
        f"{normalization}\n\n"
        "This records an observed/reported event; it does not estimate criminal proceeds."
    )


def render_liquidity_pulse(pulse: Mapping) -> str:
    """Render the privacy-minimized pulse within Telegram's message limit."""
    window = pulse["window"]["start"][:10]
    coverage = pulse["coverage"]
    status = pulse["publication_status"]
    lines = [
        f"<b>Illicit-liquidity pulse · {html.escape(window)} UTC</b>",
        f"Status: <b>{html.escape(status.replace('_', ' ').title())}</b>",
        (
            "Coverage: "
            f"{coverage['messages_observed']} messages · "
            f"{coverage['messages_flagged']} flagged · "
            f"{coverage['active_source_pseudonyms']} pseudonymized sources · "
            f"{coverage['collection_errors']} errors"
        ),
        "",
    ]
    visible = []
    for measure, bucket in pulse["monetary_observations"].items():
        if not bucket["event_count"]:
            continue
        label = _MEASURE_LABELS.get(measure, measure.replace("_", " ").title())
        detail = _STATUS_LABELS.get(bucket["value_status"], bucket["value_status"])
        if bucket["usd_sum"] is not None:
            detail = f"observed USD sum ${bucket['usd_sum']}"
        visible.append(
            f"• <b>{html.escape(label)}</b>: {bucket['event_count']} events / "
            f"{bucket['source_count']} sources · {html.escape(detail)}"
        )
    if visible:
        lines.extend(visible)
    else:
        lines.append("No operator-reviewed monetary observations in this window.")
    if pulse["rails"]:
        rails = ", ".join(
            f"{item['rail']} ×{item['event_count']}" for item in pulse["rails"]
        )
        lines.extend(("", f"Rails: {html.escape(rails)}"))
    lines.extend((
        "",
        "No population extrapolation. Mentions, requests, modeled estimates, "
        "and suspicious-activity values are never counted as realized proceeds.",
    ))
    return "\n".join(lines)


__all__ = [
    "parse_pulse_day",
    "parse_review_observation",
    "render_liquidity_pulse",
    "render_review_confirmation",
    "review_id_from_alert",
    "review_usage",
]
