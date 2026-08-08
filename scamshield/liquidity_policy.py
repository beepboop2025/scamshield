"""Operator-owned publication policy for monetary observations.

This module is intentionally tiny.  Measurement validity lives in
``liquidity.py``; this policy seam answers the narrower product question of
which already validated measurement classes may expose a value after privacy,
coverage, and dominance gates pass.
"""

from __future__ import annotations


def may_publish_value(measure_type: str, verification: str) -> bool:
    """Return whether an observation class is eligible for a public sum.

    TODO(owner): Decide whether victim-reported losses belong in the public
    aggregate or only independently verified transfers do.  The conservative
    default permits both, but never amount mentions, payment requests, modeled
    estimates, or suspicious-activity values.
    """
    if measure_type == "victim_reported_loss":
        return verification in {"victim_report", "official_source"}
    if measure_type == "verified_transfer":
        return verification in {
            "official_attribution", "independent_label_agreement",
        }
    return False


__all__ = ["may_publish_value"]
