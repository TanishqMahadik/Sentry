"""ML advisory scoring facade.

Consumes the same per-window metrics that the rule detectors use
(``detect/rules.py``) and produces an ADVISORY probability of attack plus
a recommendation band. The results are informational: they annotate the
API threat feed and the CLI but never gate or trigger mitigation
(``mitigate/``) — that path is exclusively rule-driven.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sentry.core.models import ThreatVerdict
from sentry.ml.logistic import LogisticRegression
from sentry.ml.weights import ModelWeights

logger = logging.getLogger(__name__)

# Default path to the committed weights artifact (also written by `sentry train`).
DEFAULT_WEIGHTS_PATH = "models/advisory_weights.json"

# Fixed ordered vector consumed by the model. Mirror of the union of rule
# inputs (port_metrics + flow_metrics). Order must never change between
# training and inference, hence it is frozen here.
FEATURE_ORDER: list[str] = [
    "pps_rx",
    "pps_tx",
    "bps_rx",
    "bps_tx",
    "drops_rx_rate",
    "drops_tx_rate",
    "errors_rx_rate",
    "errors_tx_rate",
    "packet_size_ratio",
    "tx_rx_ratio",
    "flow_count",
    "unique_dst_ports",
    "avg_packets_per_flow",
    "arp_entropy",
    "duplicate_macs",
    "cpu_utilization",
    "link_flap_count",
    "src_ip_entropy",
    "dst_ip_entropy",
    "flow_table_utilization",
]

# Flow-level keys read by vector_from_metrics with their benign defaults.
_FLOW_DEFAULTS: dict[str, float] = {
    "flow_count": 0.0,
    "unique_dst_ports": 0.0,
    "avg_packets_per_flow": 0.0,
    "arp_entropy": 1.0,
    "duplicate_macs": 0.0,
    "cpu_utilization": 0.0,
    "link_flap_count": 0.0,
    "src_ip_entropy": 0.0,
    "dst_ip_entropy": 0.0,
    "flow_table_utilization": 0.0,
}

_PORT_METRICS = (
    "pps_rx",
    "pps_tx",
    "bps_rx",
    "bps_tx",
    "drops_rx_rate",
    "drops_tx_rate",
    "errors_rx_rate",
    "errors_tx_rate",
)

# Advisory bands mirror the severity mapping in detect/rules.py
# (>0.85 critical, >0.6 high, >0.4 medium, else low).
_BANDS: list[tuple[float, str]] = [
    (0.85, "CRITICAL"),
    (0.60, "HIGH"),
    (0.40, "MEDIUM"),
    (0.0, "LOW"),
]


@dataclass
class AdvisoryVerdict:
    """Advisory scoring result for one evaluation window.

    Attributes:
        score: Attack probability in (0, 1)
        predicted: Predicted class label (e.g., "SYN_FLOOD" or "benign")
        band: LOW / MEDIUM / HIGH / CRITICAL
        top_features: Top contributing (feature, weight) pairs
        recommendation: Advisory-only human guidance
        weights_path: Source weights artifact, if loaded from disk
    """

    score: float
    predicted: str
    band: str
    top_features: list[tuple[str, float]]
    recommendation: str
    weights_path: str | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for the API threat feed."""
        return {
            "score": round(self.score, 4),
            "predicted": self.predicted,
            "band": self.band,
            "top_features": [[name, round(value, 4)] for name, value in self.top_features],
            "recommendation": self.recommendation,
            "weights_path": self.weights_path,
        }


def _pack_port_metrics(port_metrics: dict[str, dict[str, float]]) -> dict[str, float]:
    """Aggregate per-port rates by taking the max value per metric.

    A window-wide advisory should be raised if any subject is under
    attack, so the strongest observation across ports is used.
    """
    packed: dict[str, float] = {}
    for metrics in port_metrics.values():
        for name in _PORT_METRICS:
            value = float(metrics.get(name, 0.0))
            if value > packed.get(name, 0.0):
                packed[name] = value
    return packed


def vector_from_metrics(
    port_metrics: dict[str, dict[str, float]],
    flow_metrics: dict[str, Any],
) -> list[float]:
    """Build the fixed-order ML feature vector from window metrics.

    Matches the input contract of :mod:`sentry.detect.rules` so the rule
    detectors and the ML scorer see the same observations.

    Args:
        port_metrics: Per-port normalized rates
        flow_metrics: Flow-level statistics

    Returns:
        A 20-element feature vector aligned to FEATURE_ORDER
    """
    rates = _pack_port_metrics(port_metrics)
    pps_total = rates.get("pps_rx", 0.0) + rates.get("pps_tx", 0.0)
    bps_total = rates.get("bps_rx", 0.0) + rates.get("bps_tx", 0.0)
    pps_rx = rates.get("pps_rx", 0.0)

    packet_size_ratio = bps_total / pps_total if pps_total > 0 else 0.0
    tx_rx_ratio = rates.get("pps_tx", 0.0) / pps_rx if pps_rx > 0 else 0.0

    values: dict[str, float] = {}
    for name in _PORT_METRICS:
        values[name] = rates.get(name, 0.0)
    values["packet_size_ratio"] = packet_size_ratio
    values["tx_rx_ratio"] = tx_rx_ratio

    for name, default in _FLOW_DEFAULTS.items():
        raw = flow_metrics.get(name)
        values[name] = float(raw) if raw is not None else default

    return [values[name] for name in FEATURE_ORDER]


def _band_for(score: float) -> str:
    """Map an advisory probability to a severity band."""
    for threshold, band in _BANDS:
        if score >= threshold:
            return band
    return "LOW"


def _recommendation_for(band: str, predicted: str) -> str:
    """Advisory-only guidance text per band."""
    if band == "LOW":
        return "Continue monitoring — no action indicated."
    if band == "MEDIUM":
        return "Review subject; no automated action indicated. Advisory only."
    if band == "HIGH":
        return (
            f"Consider a Stage 1-2 countermeasure for {predicted}. "
            "Advisory only — rule verdict remains authoritative."
        )
    return (
        f"Consider escalation for {predicted}. Advisory only — this never triggers "
        "automated mitigation; rely on the rule-based decision path."
    )


@dataclass
class AdvisoryScorer:
    """Scores windows with a fitted logistic regression.

    ``available`` is False when no weights are loaded; scoring then
    returns None (the API and CLI degrade gracefully).
    """

    weights_path: str | None = None
    weights: ModelWeights | None = None
    _model: LogisticRegression | None = None

    def __post_init__(self) -> None:
        """Load model from weights (either supplied or from path)."""
        loaded: ModelWeights | None = self.weights
        if loaded is None and self.weights_path:
            try:
                loaded = ModelWeights.load(self.weights_path)
            except (OSError, ValueError):
                logger.warning(
                    "ML advisory weights unavailable; scorer disabled",
                    extra={"weights_path": str(self.weights_path)},
                )
                return
        if loaded is not None:
            self._model = LogisticRegression.restore(loaded.to_dict())

    @property
    def available(self) -> bool:
        """Whether the scorer has a loaded model."""
        return self._model is not None

    def score(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
    ) -> AdvisoryVerdict | None:
        """Score one evaluation window.

        Args:
            port_metrics: Per-port normalized rates
            flow_metrics: Flow-level statistics

        Returns:
            An AdvisoryVerdict, or None when no model is loaded
        """
        if self._model is None:
            return None

        vector = vector_from_metrics(port_metrics, flow_metrics)
        prob = self._model.predict_proba(vector)
        predicted = self._model.predict(vector)
        band = _band_for(prob)
        top = self._model.top_features(vector, k=3)

        return AdvisoryVerdict(
            score=prob,
            predicted=predicted,
            band=band,
            top_features=top,
            recommendation=_recommendation_for(band, predicted),
            weights_path=self.weights_path,
        )

    def attach_to_threats(
        self,
        threats: list[ThreatVerdict],
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Serialize threats, appending an ``advisory`` field per threat.

        When the scorer is unavailable, threats serialize without the
        advisory key (backward-compatible with the existing feed shape).

        Args:
            threats: Confirmed ThreatVerdicts to serialize
            port_metrics: Per-port normalized rates for the window
            flow_metrics: Flow-level statistics for the window

        Returns:
            List of threat dicts, each optionally carrying ``advisory``
        """
        advisory = self.score(port_metrics, flow_metrics)
        entries: list[dict[str, Any]] = []
        for threat in threats:
            entry: dict[str, Any] = {
                "threat_type": threat.threat_type,
                "subject_id": threat.subject_id,
                "severity": threat.severity,
                "confidence": threat.confidence,
                "timestamp": threat.timestamp,
                "evidence": threat.evidence,
                "message": threat.message,
            }
            if advisory is not None:
                entry["advisory"] = advisory.to_dict()
            entries.append(entry)
        return entries
