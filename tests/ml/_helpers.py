"""Shared fixtures for the sentry.ml tests.

Provides a deterministic, hand-crafted ModelWeights / AdvisoryScorer so the
advisory tests exercise scoring mechanics without depending on a trained
artifact. ``build_dataset``-style trained models are tested separately in
``test_train``.
"""

from __future__ import annotations

from sentry.ml.advisory import FEATURE_ORDER, AdvisoryScorer
from sentry.ml.weights import ModelWeights


def build_test_weights() -> ModelWeights:
    """A crafted 2-class model with a known linear separator.

    Uses a single decisive axis per feature set:
      - pps_rx   (index 0)  means 500, weight +2 for attack
      - flow_count (index 10) means 50,  weight +2 for attack
      - arp_entropy (index 13) means 0.5, weight -2 for attack
    High pps/flow with low arp entropy drives the attack class; small
    values drive benign.
    """
    zero = [0.0] * len(FEATURE_ORDER)
    attack = list(zero)
    attack[0] = 2.0
    attack[10] = 2.0
    attack[13] = -2.0
    benign = [-x for x in attack]

    means = [0.0] * len(FEATURE_ORDER)
    means[0] = 500.0
    means[10] = 50.0
    means[13] = 0.5
    stds = [1.0] * len(FEATURE_ORDER)

    return ModelWeights(
        features=list(FEATURE_ORDER),
        classes=["attack", "benign"],
        coefficients={"attack": attack, "benign": benign},
        intercepts={"attack": 0.0, "benign": 0.0},
        means=means,
        stds=stds,
        trained_at=0,
    )


def build_test_scorer() -> AdvisoryScorer:
    """An AdvisoryScorer wrapping the crafted test weights."""
    return AdvisoryScorer(weights=build_test_weights())


def attack_metrics() -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    """Metrics describing a clear syn-flood-like attack."""
    port_metrics = {"p1": {"pps_rx": 5000.0, "pps_tx": 200.0}}
    flow_metrics = {"flow_count": 100.0, "arp_entropy": 0.1}
    return port_metrics, flow_metrics


def benign_metrics() -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    """Metrics describing a quiet, healthy window."""
    port_metrics = {"p1": {"pps_rx": 50.0, "pps_tx": 48.0}}
    flow_metrics = {"flow_count": 3.0, "arp_entropy": 0.9}
    return port_metrics, flow_metrics
