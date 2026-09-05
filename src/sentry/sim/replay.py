"""Offline replay harness for testing detection without live ONOS.

Feeds synthetic scenarios through the telemetry pipeline using FakeTransport,
validates detection logic without requiring Docker, ONOS, or root permissions.
"""

from __future__ import annotations

import logging
from typing import Any

from sentry.collect.normalizer import TelemetryNormalizer
from sentry.collect.window import WindowManager
from sentry.features.extractor import FeatureExtractor
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport
from sentry.sim.scenarios import SCENARIOS, ScenarioGenerator

logger = logging.getLogger(__name__)


class ReplayResult:
    """Result of a replay run."""

    def __init__(self, scenario_name: str) -> None:
        """Initialize replay result.

        Args:
            scenario_name: Name of the scenario
        """
        self.scenario_name = scenario_name
        self.ticks_processed = 0
        self.anomalies_detected: list[dict[str, Any]] = []
        self.false_positives = 0
        self.false_negatives = 0
        self.detection_tick: int | None = None

    def add_anomaly(self, tick: int, subject: str, metric: str, mad_score: float) -> None:
        """Record an anomaly detection.

        Args:
            tick: Tick number when detected
            subject: Subject identifier
            metric: Metric name
            mad_score: MAD deviation score
        """
        self.anomalies_detected.append({
            "tick": tick,
            "subject": subject,
            "metric": metric,
            "mad_score": mad_score,
        })
        if self.detection_tick is None:
            self.detection_tick = tick


class ReplayEngine:
    """Offline replay engine for scenario testing."""

    def __init__(self) -> None:
        """Initialize replay engine."""
        self.transport = FakeTransport()
        self.client = OnosClient(self.transport)
        self.normalizer = TelemetryNormalizer()
        self.window_manager = WindowManager(window_seconds=1, warmup_windows=3, ewma_alpha=0.3)
        self.feature_extractor = FeatureExtractor()

    def replay_scenario(
        self,
        scenario_name: str,
        max_ticks: int = 10,
        mad_threshold: float = 3.0,
    ) -> ReplayResult:
        """Replay a scenario and detect anomalies.

        Args:
            scenario_name: Name of scenario from SCENARIOS registry
            max_ticks: Maximum ticks to simulate
            mad_threshold: MAD threshold for anomaly detection

        Returns:
            ReplayResult with detection outcomes
        """
        if scenario_name not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario_name}")

        logger.info(f"Starting replay: {scenario_name}")
        result = ReplayResult(scenario_name)

        # Reset state
        self.normalizer.reset()
        self.window_manager.reset()

        # Create scenario generator
        generator: ScenarioGenerator = SCENARIOS[scenario_name](seed=42)

        for tick in range(max_ticks):
            # Generate synthetic snapshot
            snapshot = generator.generate_snapshot()

            # Feed through normalizer
            rate_metrics = self.normalizer.normalize_snapshot(snapshot)

            # Process each port's metrics through window manager
            for port_key, metrics in rate_metrics.items():
                # Update baselines
                for metric_name, value in metrics.items():
                    self.window_manager.update_baseline(
                        port_key, metric_name, value, snapshot.timestamp
                    )

                    # Check for anomalies (only after warmup)
                    if self.window_manager.is_warmup_complete(port_key):
                        is_anom, mad_score = self.window_manager.is_anomalous(
                            port_key, metric_name, value, mad_threshold=mad_threshold
                        )

                        if is_anom:
                            logger.info(
                                f"Anomaly detected at tick {tick}",
                                extra={
                                    "port": port_key,
                                    "metric": metric_name,
                                    "value": value,
                                    "mad_score": mad_score,
                                },
                            )
                            result.add_anomaly(tick, port_key, metric_name, mad_score)

            # Also track flow_count per device (flow-based attack detection)
            for device in snapshot.devices:
                flow_count = len([
                    f for f in snapshot.flows if f.device_id == device.device_id
                ])
                metric_key = f"{device.device_id}:flows"
                self.window_manager.update_baseline(
                    metric_key, "flow_count", float(flow_count), snapshot.timestamp
                )
                if self.window_manager.is_warmup_complete(metric_key):
                    is_anom, mad_score = self.window_manager.is_anomalous(
                        metric_key, "flow_count", float(flow_count),
                        mad_threshold=mad_threshold,
                    )
                    if is_anom:
                        logger.info(
                            f"Flow anomaly detected at tick {tick}",
                            extra={
                                "device": device.device_id,
                                "flow_count": flow_count,
                                "mad_score": mad_score,
                            },
                        )
                        result.add_anomaly(tick, metric_key, "flow_count", mad_score)

            result.ticks_processed = tick + 1
            generator.advance_tick()

        logger.info(
            f"Replay complete: {scenario_name}",
            extra={
                "ticks": result.ticks_processed,
                "anomalies": len(result.anomalies_detected),
                "detection_tick": result.detection_tick,
            },
        )

        return result

    def run_all_scenarios(self, max_ticks: int = 10) -> dict[str, ReplayResult]:
        """Run all registered scenarios.

        Args:
            max_ticks: Maximum ticks per scenario

        Returns:
            Dictionary mapping scenario name to ReplayResult
        """
        results = {}
        for scenario_name in SCENARIOS.keys():
            results[scenario_name] = self.replay_scenario(scenario_name, max_ticks)
        return results

    def validate_benign_scenario(self, max_ticks: int = 10) -> bool:
        """Validate that benign traffic triggers zero alerts.

        Args:
            max_ticks: Ticks to run

        Returns:
            True if zero anomalies detected, False otherwise
        """
        result = self.replay_scenario("benign", max_ticks=max_ticks, mad_threshold=3.0)
        return len(result.anomalies_detected) == 0

    def validate_attack_detection(
        self,
        scenario_name: str,
        max_ticks: int = 10,
        latency_bound: int = 10,
        mad_threshold: float = 2.0,
    ) -> bool:
        """Validate that an attack is detected within latency bound.

        Args:
            scenario_name: Attack scenario name
            max_ticks: Ticks to run
            latency_bound: Maximum ticks allowed for detection
            mad_threshold: MAD threshold for detection sensitivity

        Returns:
            True if attack detected within bound, False otherwise
        """
        result = self.replay_scenario(
            scenario_name, max_ticks=max_ticks, mad_threshold=mad_threshold
        )
        if result.detection_tick is None:
            logger.warning(f"Attack NOT detected: {scenario_name}")
            return False

        if result.detection_tick > latency_bound:
            logger.warning(
                f"Detection too slow: {scenario_name} detected at tick {result.detection_tick}"
            )
            return False

        logger.info(
            f"Attack detected within bounds: {scenario_name} at tick {result.detection_tick}"
        )
        return True
