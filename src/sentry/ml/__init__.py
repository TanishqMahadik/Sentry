"""ML advisory scorer — pure-Python logistic regression (stdlib-only).

Consumes the same per-window telemetry metrics as the rule detectors and
produces an *advisory* attack probability with a recommendation band.
Advisory output annotates the API threat feed and CLI; it never gates or
triggers the mitigation engine (which remains rule-driven per FR-1/NFR).
"""

from __future__ import annotations

from sentry.ml.advisory import (
    DEFAULT_WEIGHTS_PATH,
    FEATURE_ORDER,
    AdvisoryScorer,
    AdvisoryVerdict,
    vector_from_metrics,
)
from sentry.ml.logistic import LogisticRegression, sigmoid
from sentry.ml.weights import ModelWeights

__all__ = [
    "AdvisoryScorer",
    "AdvisoryVerdict",
    "DEFAULT_WEIGHTS_PATH",
    "FEATURE_ORDER",
    "LogisticRegression",
    "ModelWeights",
    "sigmoid",
    "vector_from_metrics",
]
