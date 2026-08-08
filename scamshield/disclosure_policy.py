"""Operator-owned policy for displaying unverified provenance hypotheses."""

from __future__ import annotations


def should_render_hypothesis(support_level: str, surface: str) -> bool:
    """Return whether a hypothesis may be shown on the requested surface.

    TODO(owner): This is the deliberate policy seam. Private users currently
    see clearly labelled typology matches; public surfaces require independent
    corroboration. Adjust these 5-10 lines if your publication posture differs.
    """
    if support_level not in {"TYPOLOGY_MATCH", "CORROBORATED_LEAD", "DIRECT_LINK"}:
        return False
    if surface in {"public_channel", "guardian_group"}:
        return support_level in {"CORROBORATED_LEAD", "DIRECT_LINK"}
    return True


__all__ = ["should_render_hypothesis"]
