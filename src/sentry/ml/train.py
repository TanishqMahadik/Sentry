"""Synthetic training pipeline for the ML advisory scorer.

Generates labeled feature vectors for benign traffic and the 8 attack
types (signal ranges derived from `detect/rules.py` thresholds and
`sim/scenarios.py` patterns), fits the stdlib-only logistic regression,
evaluates on a held-out validation split, and persists `ModelWeights`.

Exposes a CLI entry (`sentry train`) and a scenario-scoring demo
(`sentry score --scenario <name>`).

All advisory — output never influences rule-based mitigation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from sentry.collect.normalizer import TelemetryNormalizer
from sentry.core.models import TelemetrySnapshot
from sentry.ml.advisory import (
    DEFAULT_WEIGHTS_PATH,
    FEATURE_ORDER,
    AdvisoryScorer,
    AdvisoryVerdict,
    vector_from_metrics,
)
from sentry.ml.logistic import LogisticRegression
from sentry.ml.weights import weights_from_model
from sentry.sim.scenarios import SCENARIOS

# Class labels in canonical order. "benign" must be one of them.
CLASSES: list[str] = [
    "benign",
    "syn_flood",
    "udp_flood",
    "icmp_flood",
    "port_scan",
    "flow_table_exhaustion",
    "arp_spoofing",
    "cp_saturation",
    "topology_poisoning",
]

# Defaults bound the CLI when invoked without flags.
DEFAULT_SAMPLES_PER_CLASS = 60
VALIDATION_FRACTION = 0.30


@dataclass
class Sample:
    """One labeled training example."""

    port_metrics: dict[str, dict[str, float]]
    flow_metrics: dict[str, float]
    label: str


class RandomMetricSource:
    """Per-class synthetic metric generators.

    Ranges are chosen so the distinctive signal of each attack family
    (e.g., flow_count for exhaustion, arp_entropy for spoofing, cpu for
    saturation) cleanly separates classes while leaving noise on the
    non-discriminative metrics.
    """

    def __init__(self, rng: random.Random) -> None:
        """Store the shared PRNG."""
        self.rng = rng

    def _port(
        self, pps_rx: float, pps_tx: float, bps_rx: float, bps_tx: float
    ) -> dict[str, dict[str, float]]:
        """Build a single-port metrics dict with small noise."""
        return {
            "of:1:1": {
                "pps_rx": pps_rx + self.rng.uniform(-10, 10),
                "pps_tx": pps_tx + self.rng.uniform(-10, 10),
                "bps_rx": bps_rx + self.rng.uniform(-500, 500),
                "bps_tx": bps_tx + self.rng.uniform(-500, 500),
                "drops_rx_rate": self.rng.uniform(0.0, 20.0),
                "drops_tx_rate": self.rng.uniform(0.0, 10.0),
                "errors_rx_rate": self.rng.uniform(0.0, 5.0),
                "errors_tx_rate": self.rng.uniform(0.0, 3.0),
            }
        }

    def _bps(self, pps: float, packet_size: float) -> float:
        """Bits per second roughly matching a packet rate and avg size."""
        return pps * packet_size * 8.0

    def gen(self, label: str) -> Sample:
        """Generate one sample for a class label.

        Args:
            label: One of CLASSES

        Returns:
            A Sample with labeled port/flow metrics
        """
        rng = self.rng
        if label == "benign":
            pps_rx = rng.uniform(50, 400)
            pps_tx = rng.uniform(40, pps_rx * 1.2)
            flow = {
                "flow_count": rng.uniform(1, 15),
                "unique_dst_ports": rng.uniform(1, 8),
                "avg_packets_per_flow": rng.uniform(60, 1500),
                "arp_entropy": rng.uniform(0.7, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.1, 0.35),
                "link_flap_count": rng.uniform(0, 1),
                "src_ip_entropy": rng.uniform(0.4, 0.8),
                "dst_ip_entropy": rng.uniform(0.4, 0.8),
                "flow_table_utilization": rng.uniform(0.01, 0.08),
            }
        elif label == "syn_flood":
            pps_rx = rng.uniform(1500, 6000)
            pps_tx = pps_rx * rng.uniform(0.03, 0.15)
            flow = {
                "flow_count": rng.uniform(25, 80),
                "unique_dst_ports": rng.uniform(5, 20),
                "avg_packets_per_flow": rng.uniform(1, 6),
                "arp_entropy": rng.uniform(0.8, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.3, 0.6),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.5, 0.9),
                "dst_ip_entropy": rng.uniform(0.5, 0.9),
                "flow_table_utilization": rng.uniform(0.15, 0.5),
            }
        elif label == "udp_flood":
            pps_rx = rng.uniform(2500, 10000)
            pps_tx = pps_rx * rng.uniform(0.2, 0.5)
            flow = {
                "flow_count": rng.uniform(30, 90),
                "unique_dst_ports": rng.uniform(5, 25),
                "avg_packets_per_flow": rng.uniform(10, 60),
                "arp_entropy": rng.uniform(0.8, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.3, 0.7),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.4, 0.8),
                "dst_ip_entropy": rng.uniform(0.6, 0.95),
                "flow_table_utilization": rng.uniform(0.2, 0.6),
            }
        elif label == "icmp_flood":
            pps_rx = rng.uniform(800, 4000)
            pps_tx = pps_rx * rng.uniform(0.8, 1.2)
            flow = {
                "flow_count": rng.uniform(10, 40),
                "unique_dst_ports": rng.uniform(1, 6),
                "avg_packets_per_flow": rng.uniform(5, 20),
                "arp_entropy": rng.uniform(0.85, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.2, 0.5),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.3, 0.6),
                "dst_ip_entropy": rng.uniform(0.3, 0.6),
                "flow_table_utilization": rng.uniform(0.1, 0.3),
            }
        elif label == "port_scan":
            pps_rx = rng.uniform(500, 2500)
            pps_tx = pps_rx * rng.uniform(0.1, 0.3)
            flow = {
                "flow_count": rng.uniform(60, 320),
                "unique_dst_ports": rng.uniform(25, 120),
                "avg_packets_per_flow": rng.uniform(1, 8),
                "arp_entropy": rng.uniform(0.8, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.2, 0.5),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.5, 0.9),
                "dst_ip_entropy": rng.uniform(0.7, 1.0),
                "flow_table_utilization": rng.uniform(0.2, 0.5),
            }
        elif label == "flow_table_exhaustion":
            pps_rx = rng.uniform(500, 2500)
            pps_tx = pps_rx * rng.uniform(0.4, 0.9)
            flow = {
                "flow_count": rng.uniform(700, 980),
                "unique_dst_ports": rng.uniform(200, 700),
                "avg_packets_per_flow": rng.uniform(8, 40),
                "arp_entropy": rng.uniform(0.7, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.5, 0.8),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.3, 0.7),
                "dst_ip_entropy": rng.uniform(0.3, 0.7),
                "flow_table_utilization": rng.uniform(0.7, 0.99),
            }
        elif label == "arp_spoofing":
            pps_rx = rng.uniform(100, 800)
            pps_tx = pps_rx * rng.uniform(0.5, 1.0)
            flow = {
                "flow_count": rng.uniform(5, 30),
                "unique_dst_ports": rng.uniform(1, 6),
                "avg_packets_per_flow": rng.uniform(20, 200),
                "arp_entropy": rng.uniform(0.0, 0.3),
                "duplicate_macs": rng.uniform(2, 60),
                "cpu_utilization": rng.uniform(0.2, 0.5),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.5, 0.9),
                "dst_ip_entropy": rng.uniform(0.2, 0.5),
                "flow_table_utilization": rng.uniform(0.05, 0.2),
            }
        elif label == "cp_saturation":
            pps_rx = rng.uniform(1000, 5000)
            pps_tx = pps_rx * rng.uniform(0.5, 1.0)
            flow = {
                "flow_count": rng.uniform(300, 700),
                "unique_dst_ports": rng.uniform(50, 300),
                "avg_packets_per_flow": rng.uniform(5, 30),
                "arp_entropy": rng.uniform(0.6, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.85, 0.99),
                "link_flap_count": 0.0,
                "src_ip_entropy": rng.uniform(0.4, 0.8),
                "dst_ip_entropy": rng.uniform(0.4, 0.8),
                "flow_table_utilization": rng.uniform(0.4, 0.9),
            }
        elif label == "topology_poisoning":
            pps_rx = rng.uniform(100, 500)
            pps_tx = pps_rx * rng.uniform(0.5, 1.0)
            flow = {
                "flow_count": rng.uniform(2, 20),
                "unique_dst_ports": rng.uniform(1, 6),
                "avg_packets_per_flow": rng.uniform(50, 400),
                "arp_entropy": rng.uniform(0.7, 1.0),
                "duplicate_macs": 0.0,
                "cpu_utilization": rng.uniform(0.2, 0.4),
                "link_flap_count": rng.uniform(3, 20),
                "src_ip_entropy": rng.uniform(0.4, 0.8),
                "dst_ip_entropy": rng.uniform(0.4, 0.8),
                "flow_table_utilization": rng.uniform(0.05, 0.15),
            }
        else:  # pragma: no cover - guarded by callers
            raise ValueError(f"Unknown label: {label}")

        pps_tx = max(pps_tx, 0.0)
        return Sample(
            port_metrics=self._port(pps_rx, pps_tx, self._bps(pps_rx, 64), self._bps(pps_tx, 64)),
            flow_metrics=flow,
            label=label,
        )


def _flow_metrics_from_snapshot(snapshot: TelemetrySnapshot) -> dict[str, float]:
    """Derive flow-level metrics from a telemetry snapshot.

    Mirror of the flow metrics the replay harness feeds the detectors:
    flow_count comes from installed flows, with the remaining fields kept
    at benign defaults (the scenario generators do not emit them).

    Args:
        snapshot: One telemetry snapshot

    Returns:
        Flow-level metric dict
    """
    flows = list(snapshot.flows)
    flow_count = float(len(flows))
    return {
        "flow_count": flow_count,
        "unique_dst_ports": min(flow_count, 200.0),
        "avg_packets_per_flow": (
            sum(f.packets for f in flows) / flow_count if flow_count else 0.0
        ),
    }


def _scenario_samples(seed: int, max_ticks: int = 8) -> list[Sample]:
    """Derive labeled samples from the scenario generators.

    The scenarios represent the *real operating points* the demo feeds the
    scorer (sim/scenarios.py). Pre-attack ticks (tick < 3, the hardcoded
    onset in those generators) are labeled benign; from tick 3 the attack
    label applies. This grounds the model in live-trace behavior so the
    `score --scenario` demo classifies correctly.

    Args:
        seed: Seed for the scenario generators
        max_ticks: Ticks per scenario (first tick has no rate delta)

    Returns:
        Labeled Samples derived from scenario traces
    """
    samples: list[Sample] = []
    for scenario_name, generator_cls in SCENARIOS.items():
        normalizer = TelemetryNormalizer()
        generator = generator_cls(seed=seed)
        for tick in range(max_ticks):
            snapshot = generator.generate_snapshot()
            rates = normalizer.normalize_snapshot(snapshot)
            generator.advance_tick()
            if not rates:
                continue  # first snapshot: no delta yet
            if scenario_name == "benign" or tick >= 3:  # attack onset at tick 3
                label = scenario_name
            else:
                label = "benign"
            samples.append(
                Sample(
                    port_metrics=rates,
                    flow_metrics=_flow_metrics_from_snapshot(snapshot),
                    label=label,
                )
            )
    return samples


def build_dataset(
    samples_per_class: int = DEFAULT_SAMPLES_PER_CLASS,
    seed: int = 7,
) -> tuple[list[list[float]], list[str], list[Sample]]:
    """Synthesize labeled feature vectors for all classes.

    Combines hand-tuned synthetic ranges (covering all 9 classes,
    including the three not present in sim/scenarios) with
    scenario-derived traces (the demo operating points).

    Args:
        samples_per_class: Rows to generate per class label
        seed: PRNG seed for reproducibility

    Returns:
        (vectors, labels, samples) where vectors align to FEATURE_ORDER
    """
    rng = random.Random(seed)
    source = RandomMetricSource(rng)

    vectors: list[list[float]] = []
    labels: list[str] = []
    samples: list[Sample] = []

    # Synthetic ranges first (all 9 classes)
    for label in CLASSES:
        for _ in range(samples_per_class):
            sample = source.gen(label)
            vector = vector_from_metrics(sample.port_metrics, sample.flow_metrics)
            vectors.append(vector)
            labels.append(label)
            samples.append(sample)

    # Scenario-derived operating points (benign + the 5 registered attacks)
    for sample in _scenario_samples(seed=seed):
        vector = vector_from_metrics(sample.port_metrics, sample.flow_metrics)
        vectors.append(vector)
        labels.append(sample.label)
        samples.append(sample)

    return vectors, labels, samples


def _train_validation_split(
    vectors: list[list[float]],
    labels: list[str],
    samples: list[Sample],
    seed: int = 7,
) -> tuple[list[list[float]], list[str], list[list[float]], list[str]]:
    """Deterministic 70/30 train/validation split (stratified by label)."""
    rng = random.Random(seed)
    by_label: dict[str, list[int]] = {}
    for idx, label in enumerate(labels):
        by_label.setdefault(label, []).append(idx)

    train_idx: list[int] = []
    val_idx: list[int] = []
    for indexes in by_label.values():
        rng.shuffle(indexes)
        cut = max(1, int(len(indexes) * (1.0 - VALIDATION_FRACTION)))
        train_idx.extend(indexes[:cut])
        val_idx.extend(indexes[cut:])
    rng.shuffle(train_idx)
    rng.shuffle(val_idx)

    train_x = [vectors[i] for i in train_idx]
    train_y = [labels[i] for i in train_idx]
    val_x = [vectors[i] for i in val_idx]
    val_y = [labels[i] for i in val_idx]
    # `samples` is retained in the signature for symmetric callers but is
    # not needed downstream; keep the mapping implicit.
    _ = samples
    return train_x, train_y, val_x, val_y


def _classify_attack(predicted: str, actual: str) -> tuple[bool, bool]:
    """Map predicted/actual labels to an attack-vs-benign (pred, actual) pair."""
    pred = predicted != "benign"
    actual_attack = actual != "benign"
    return pred, actual_attack


def evaluate(samples: list[tuple[str, str]]) -> dict[str, float]:
    """Compute accuracy / precision / recall / F1 over (actual, predicted) pairs.

    Args:
        samples: Sequence of (predicted, actual) tuples

    Returns:
        Metrics dict with keys accuracy, precision, recall, f1
    """
    tp = fp = fn = tn = 0
    correct = 0
    total = len(samples)
    for predicted, actual in samples:
        pred, act = _classify_attack(predicted, actual)
        if pred == act:
            correct += 1
        if act and pred:
            tp += 1
        elif act and not pred:
            fn += 1
        elif pred and not act:
            fp += 1
        else:
            tn += 1

    accuracy = correct / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def train(
    samples_per_class: int = DEFAULT_SAMPLES_PER_CLASS,
    seed: int = 7,
    epochs: int = 800,
) -> tuple[LogisticRegression, dict[str, float]]:
    """Fit the advisory logistic regression on synthetic data.

    Args:
        samples_per_class: Rows per class label
        seed: PRNG seed
        epochs: Gradient descent iterations

    Returns:
        (trained_model, validation_metrics)
    """
    vectors, labels, samples = build_dataset(samples_per_class, seed=seed)
    train_x, train_y, val_x, val_y = _train_validation_split(vectors, labels, samples, seed=seed)

    model = LogisticRegression()
    model.set_feature_names(FEATURE_ORDER)
    model.fit(train_x, train_y, epochs=epochs)

    val_metrics = evaluate(
        [(model.predict(x), y) for x, y in zip(val_x, val_y)]
    )
    return model, val_metrics


def main(
    samples: int = DEFAULT_SAMPLES_PER_CLASS,
    out: str = DEFAULT_WEIGHTS_PATH,
    epochs: int = 800,
    verbose: bool = True,
) -> int:
    """Full train-and-persist pipeline (CLI entry ``sentry train``).

    Args:
        samples: Rows per class label
        out: Destination weights path
        epochs: Gradient descent iterations
        verbose: Print a summary table

    Returns:
        Process exit code (0 = success)
    """
    model, val_metrics = train(samples_per_class=samples, epochs=epochs)
    weights = weights_from_model(model, features=FEATURE_ORDER, metrics=val_metrics)
    weights.save(out)

    if verbose:
        print("\n=== Sentry ML Advisory Scorer — Training ===")
        print(f"  Samples per class: {samples}  ({len(CLASSES)} classes)")
        print(
            f"  Validation: accuracy={val_metrics['accuracy']:.3f} "
            f"precision={val_metrics['precision']:.3f} "
            f"recall={val_metrics['recall']:.3f} "
            f"f1={val_metrics['f1']:.3f}"
        )
        print(f"  Weights written to: {out}\n")
    return 0


def score_scenario(
    scenario: str,
    weights_path: str = DEFAULT_WEIGHTS_PATH,
    max_ticks: int = 12,
) -> list[tuple[int, AdvisoryVerdict | None]]:
    """Replay a scenario and print per-tick advisory verdicts.

    Uses the same ScenarioGenerator the replay harness drives; port rates
    are computed via TelemetryNormalizer, flow metrics from the snapshot.

    Args:
        scenario: Scenario name from SCENARIOS (benign + the 5 attack classes)
        weights_path: Weights artifact path
        max_ticks: Ticks to simulate (rates are available from tick 1+)

    Returns:
        List of (tick, verdict) pairs; verdict None only if scorer disabled
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario} — choose from {sorted(SCENARIOS)}")

    from sentry.sim.scenarios import ScenarioGenerator

    scorer = AdvisoryScorer(weights_path=weights_path)
    generator: ScenarioGenerator = SCENARIOS[scenario](seed=42)
    normalizer = TelemetryNormalizer()

    results: list[tuple[int, AdvisoryVerdict | None]] = []
    print(f"\n=== Advisory replay: {scenario} ===\n")
    print(f"{'tick':>4} {'pps_rx':>8} {'flows':>6} {'score':>6}  {'band':<8} predicted")
    print("-" * 58)

    for tick in range(max_ticks):
        pps_rx = 0.0
        snapshot = generator.generate_snapshot()
        rates = normalizer.normalize_snapshot(snapshot)
        generator.advance_tick()

        flows = len(snapshot.flows)
        if not rates:
            # First snapshot establishes the baseline; no delta yet.
            print(f"{tick:>4} {'--':>8} {flows:>6} {'--':>6}  {'--':<8} (baselining)")
            results.append((tick, None))
            continue

        for metrics in rates.values():
            pps_rx = max(pps_rx, metrics.get("pps_rx", 0.0))

        flow_metrics = _flow_metrics_from_snapshot(snapshot)
        verdict = scorer.score(rates, flow_metrics)
        results.append((tick, verdict))

        if verdict is not None:
            print(
                f"{tick:>4} {pps_rx:>8.0f} {flows:>6} {verdict.score:>6.3f}  "
                f"{verdict.band:<8} {verdict.predicted}"
            )
        else:
            print(
                f"{tick:>4} {pps_rx:>8.0f} {flows:>6} {'n/a':>6}  {'n/a':<8} "
                "(scorer unavailable)"
            )

    print()
    return results
