"""Sentry CLI entrypoint.

Provides subcommands:
  - run: Start Sentry core engine (live or dry-run)
  - replay: Replay synthetic attack scenarios offline (Phase 3)
  - selftest: Run full test suite offline without external deps (Phase 3)
  - train: Fit the ML advisory scorer on synthetic data (Phase 8)
  - score: Score a scenario or feature set with the advisory scorer (Phase 8)
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from sentry.collect.normalizer import TelemetryNormalizer
from sentry.collect.poller import TelemetryPoller
from sentry.core.config import load_config, setup_logging
from sentry.core.models import TelemetrySnapshot
from sentry.ml.advisory import DEFAULT_WEIGHTS_PATH
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport, UrllibTransport
from sentry.sim.scenarios import SCENARIOS

logger = logging.getLogger("sentry")

SCENARIOS_KEYS = sorted(SCENARIOS)


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentry",
        description="Closed-loop SDN attack detection and mitigation system",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Start Sentry monitoring engine")
    run_parser.add_argument(
        "--once",
        action="store_true",
        help="Poll telemetry once, normalize, print output and exit",
    )
    run_parser.add_argument(
        "--config",
        type=str,
        default="config/sentry.yaml",
        help="Path to sentry.yaml configuration file",
    )
    run_parser.add_argument(
        "--policy",
        type=str,
        default="config/policy.yaml",
        help="Path to policy.yaml configuration file",
    )
    run_parser.add_argument(
        "--mock",
        action="store_true",
        help="Use FakeTransport with mock fixtures instead of real ONOS",
    )

    # Command: replay (Phase 3)
    replay_parser = subparsers.add_parser(
        "replay", help="Replay synthetic threat scenarios offline"
    )
    replay_parser.add_argument(
        "--scenario",
        type=str,
        choices=[
            "all",
            "syn_flood",
            "udp_flood",
            "icmp_flood",
            "port_scan",
            "arp_spoofing",
            "cp_saturation",
            "flow_table_exhaustion",
            "topology_poisoning",
        ],
        default="all",
        help="Specific scenario to replay",
    )
    replay_parser.add_argument(
        "--serve",
        action="store_true",
        help="Start HTTP server for offline browser demo (Phase 7)",
    )
    replay_parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind when using --serve (default: 0.0.0.0)",
    )
    replay_parser.add_argument(
        "--port",
        type=int,
        default=9090,
        help="Port to bind when using --serve (default: 9090)",
    )

    # Command: serve (Phase 7) — run the API server
    serve_parser = subparsers.add_parser(
        "serve", help="Start Sentry API server with dashboard"
    )
    serve_parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=9090,
        help="Port to bind (default: 9090)",
    )
    serve_parser.add_argument(
        "--mock",
        action="store_true",
        help="Use FakeTransport with mock fixtures",
    )

    # Command: selftest (Phase 3 exit gate)
    subparsers.add_parser(
        "selftest", help="Run offline self-test suite across all 8 attack vectors"
    )

    # Command: train (Phase 8) — fit the ML advisory scorer
    train_parser = subparsers.add_parser(
        "train", help="Fit the ML advisory scorer on synthetic data"
    )
    train_parser.add_argument(
        "--samples",
        type=int,
        default=60,
        help="Synthetic samples per class (default: 60)",
    )
    train_parser.add_argument(
        "--epochs",
        type=int,
        default=800,
        help="Gradient descent iterations (default: 800)",
    )
    train_parser.add_argument(
        "--out",
        type=str,
        default=DEFAULT_WEIGHTS_PATH,
        help=f"Destination weights file (default: {DEFAULT_WEIGHTS_PATH})",
    )

    # Command: score (Phase 8) — run the advisory scorer
    score_parser = subparsers.add_parser(
        "score", help="Score a scenario or feature set with the advisory scorer"
    )
    score_parser.add_argument(
        "--scenario",
        type=str,
        choices=list(SCENARIOS_KEYS),
        help="Replay a scenario and show per-tick advisory scores",
    )
    score_parser.add_argument(
        "--features",
        type=str,
        help="Score one window from 'name=value' pairs (e.g., pps_rx=5000,flow_count=300)",
    )
    score_parser.add_argument(
        "--weights",
        type=str,
        default=DEFAULT_WEIGHTS_PATH,
        help=f"Path to weights file (default: {DEFAULT_WEIGHTS_PATH})",
    )

    return parser


def run_command(args: argparse.Namespace) -> int:
    """Execute the 'run' subcommand."""
    config = load_config(args.config, args.policy)
    setup_logging(config.service.log_level)

    logger.info(
        "Starting Sentry",
        extra={
            "mode": config.service.mode,
            "poll_interval": config.service.poll_interval,
            "mock": args.mock,
        },
    )

    # Initialize transport
    transport: FakeTransport | UrllibTransport
    if args.mock:
        logger.info("Using FakeTransport with mock fixtures")
        transport = FakeTransport()
        # Seed basic mock topology fixtures
        transport.register_fixture(
            "/devices",
            {
                "devices": [
                    {
                        "id": "of:0000000000000001",
                        "type": "SWITCH",
                        "available": True,
                        "role": "MASTER",
                    }
                ]
            },
        )
        transport.register_fixture(
            "/hosts",
            {
                "hosts": [
                    {
                        "id": "00:00:00:00:00:01/-1",
                        "mac": "00:00:00:00:00:01",
                        "ipAddresses": ["10.0.0.1"],
                    }
                ]
            },
        )
        transport.register_fixture(
            "/statistics/ports",
            {
                "statistics": [
                    {
                        "deviceId": "of:0000000000000001",
                        "port": "1",
                        "packetsReceived": 1000,
                        "packetsSent": 800,
                        "bytesReceived": 150000,
                        "bytesSent": 120000,
                    }
                ]
            },
        )
    else:
        onos_url = f"http://{config.onos.host}:{config.onos.port}/onos/v1"
        transport = UrllibTransport(
            base_url=onos_url,
            username=config.onos.username,
            password=config.onos.password,
            timeout=config.onos.timeout,
            backoff_initial=config.onos.backoff_initial,
            backoff_multiplier=config.onos.backoff_multiplier,
            backoff_max=config.onos.backoff_max_seconds,
        )

    client = OnosClient(transport)
    poller = TelemetryPoller(
        client=client,
        poll_interval=config.service.poll_interval,
        backoff_initial=config.onos.backoff_initial,
        backoff_multiplier=config.onos.backoff_multiplier,
        backoff_max=config.onos.backoff_max_seconds,
    )
    normalizer = TelemetryNormalizer()

    def handle_snapshot(snapshot: TelemetrySnapshot) -> None:
        rates = normalizer.normalize_snapshot(snapshot)
        logger.info(
            "Telemetry processed",
            extra={
                "timestamp": snapshot.timestamp,
                "devices": len(snapshot.devices),
                "hosts": len(snapshot.hosts),
                "rates": rates,
            },
        )

    if args.once:
        logger.info("Running single telemetry poll (--once)")
        if args.mock:
            assert isinstance(transport, FakeTransport)  # register_fixture is mock-only
            # For mock --once, feed two snapshots to verify rate computation
            snap1 = client.get_telemetry_snapshot()
            normalizer.normalize_snapshot(snap1)

            # Simulate second tick with incremented counters
            transport.register_fixture(
                "/statistics/ports",
                {
                    "statistics": [
                        {
                            "deviceId": "of:0000000000000001",
                            "port": "1",
                            "packetsReceived": 1200,  # +200 packets
                            "packetsSent": 900,  # +100 packets
                            "bytesReceived": 180000,
                            "bytesSent": 135000,
                        }
                    ]
                },
            )
            # Wait 1s for delta calculation
            time.sleep(1)
            snap2 = client.get_telemetry_snapshot()
            rates = normalizer.normalize_snapshot(snap2)
            print("\n=== Phase 1 Exit Gate: Normalized Telemetry Output ===")
            print(f"Timestamp: {snap2.timestamp}")
            print(f"Devices detected: {len(snap2.devices)}")
            print(f"Hosts detected: {len(snap2.hosts)}")
            print(f"Port Rates: {rates}")
            print("=====================================================\n")
            return 0
        else:
            poller.start(handle_snapshot, run_once=True)
            return 0

    # Continuous polling loop
    try:
        poller.start(handle_snapshot)
    except KeyboardInterrupt:
        logger.info("Shutdown requested via KeyboardInterrupt")
        poller.stop()

    return 0


def replay_command(args: argparse.Namespace) -> int:
    """Execute the 'replay' subcommand."""
    # If --serve flag, start HTTP server for browser demo
    if getattr(args, "serve", False):
        return _start_server(args.host, args.port, replay_mode=True)

    from sentry.sim.replay import ReplayEngine
    from sentry.sim.scenarios import SCENARIOS

    engine = ReplayEngine()

    if args.scenario == "all":
        scenarios_to_run = list(SCENARIOS.keys())
    else:
        scenarios_to_run = [args.scenario]

    print("\n=== Sentry Replay Harness ===\n")
    all_ok = True

    for scenario_name in scenarios_to_run:
        result = engine.replay_scenario(scenario_name, max_ticks=15, mad_threshold=2.0)
        status = "OK" if result.anomalies_detected or scenario_name == "benign" else "FAIL"
        if scenario_name == "benign" and len(result.anomalies_detected) > 2:
            status = "WARN"

        detection_str = f"tick {result.detection_tick}" if result.detection_tick else "none"
        print(
            f"  [{status}] {scenario_name:<25s} "
            f"ticks={result.ticks_processed}  "
            f"anomalies={len(result.anomalies_detected)}  "
            f"detection={detection_str}"
        )

        if status == "FAIL":
            all_ok = False

    print()
    if all_ok:
        print("Replay complete: all scenarios passed.")
    else:
        print("Replay complete: some scenarios failed.")
    print()
    return 0 if all_ok else 1


def serve_command(args: argparse.Namespace) -> int:
    """Execute the 'serve' subcommand — start API server."""
    return _start_server(args.host, args.port, replay_mode=False, mock=args.mock)


def _start_server(
    host: str = "0.0.0.0",
    port: int = 9090,
    replay_mode: bool = False,
    mock: bool = False,
) -> int:
    """Start the Sentry API server."""
    import signal

    from sentry.api.auth import Authenticator
    from sentry.api.server import create_server
    from sentry.core.config import ApiConfig

    cfg = ApiConfig()
    authenticator = Authenticator(
        valid_token=cfg.auth_token,
        session_ttl_seconds=cfg.session_ttl_seconds,
        max_attempts=cfg.rate_limit_max_attempts,
        lockout_seconds=cfg.rate_limit_lockout_seconds,
    )

    from sentry.ml.advisory import AdvisoryScorer

    scorer = AdvisoryScorer(weights_path=DEFAULT_WEIGHTS_PATH)
    server = create_server(
        host=host,
        port=port,
        authenticator=authenticator,
        executor=None,
        advisory_scorer=scorer,
    )

    def shutdown_handler(signum: int, frame: object) -> None:
        logger.info("Shutdown signal received")
        server.shutdown()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    mode = "replay" if replay_mode else "live"
    print(f"\n=== Sentry API Server ({mode} mode) ===")
    print(f"  Listening on http://{host}:{port}")
    print(f"  Dashboard: http://{host}:{port}/dashboard.html")
    print(f"  Token: {cfg.auth_token}")
    print("  Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("\nServer stopped.")

    return 0


def selftest_command(args: argparse.Namespace) -> int:
    """Execute the 'selftest' subcommand — Phase 3 exit gate."""
    from sentry.sim.replay import ReplayEngine

    engine = ReplayEngine()

    print("\n=== Sentry Phase 3 Self-Test ===\n")

    # 1. Validate benign produces zero/few alerts
    benign_ok = engine.validate_benign_scenario(max_ticks=10)
    print(f"  [{'OK' if benign_ok else 'FAIL'}] Benign traffic: zero/few alerts")

    # 2. Validate each attack scenario is detected within latency bound
    attack_scenarios = [
        "syn_flood",
        "udp_flood",
        "icmp_flood",
        "port_scan",
        "flow_table_exhaustion",
    ]
    all_ok = benign_ok

    for scenario in attack_scenarios:
        detected = engine.validate_attack_detection(
            scenario, max_ticks=15, latency_bound=15, mad_threshold=2.0
        )
        print(f"  [{'OK' if detected else 'FAIL'}] {scenario}: detected within latency bound")
        if not detected:
            all_ok = False

    # 3. Run full suite for summary
    results = engine.run_all_scenarios(max_ticks=15)
    total_anomalies = sum(len(r.anomalies_detected) for r in results.values())

    print(f"\n  Scenarios run: {len(results)}")
    print(f"  Total anomalies detected: {total_anomalies}")
    print()

    if all_ok:
        print("Self-test PASSED — Phase 3 exit gate satisfied.")
    else:
        print("Self-test FAILED — see above for details.")
    print()
    return 0 if all_ok else 1


def train_command(args: argparse.Namespace) -> int:
    """Execute the 'train' subcommand — fit the ML advisory scorer (Phase 8)."""
    from sentry.ml.train import main as train_main

    return train_main(samples=args.samples, out=args.out, epochs=args.epochs, verbose=True)


def _parse_feature_spec(spec: str) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    """Split 'name=value,...' into (port_metrics, flow_metrics).

    Port-rate keys are grouped under a synthetic subject; everything else
    is treated as flow-level metrics.
    """
    port_keys = {
        "pps_rx",
        "pps_tx",
        "bps_rx",
        "bps_tx",
        "drops_rx_rate",
        "drops_tx_rate",
        "errors_rx_rate",
        "errors_tx_rate",
    }
    port_metrics: dict[str, dict[str, float]] = {}
    flow_metrics: dict[str, float] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, raw = part.partition("=")
        name = name.strip()
        try:
            value = float(raw.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid numeric feature value: {part!r}") from exc
        if name in port_keys:
            port_metrics.setdefault("window-summary", {})[name] = value
        else:
            flow_metrics[name] = value
    return port_metrics, flow_metrics


def score_command(args: argparse.Namespace) -> int:
    """Execute the 'score' subcommand — run the ML advisory scorer (Phase 8)."""
    from sentry.ml.advisory import AdvisoryScorer
    from sentry.ml.train import score_scenario

    if args.scenario:
        score_scenario(args.scenario, weights_path=args.weights)
        return 0

    if args.features:
        scorer = AdvisoryScorer(weights_path=args.weights)
        if not scorer.available:
            print(f"Advisory scorer unavailable (weights missing: {args.weights}).")
            print("Run `sentry train` to generate weights.")
            return 1
        try:
            port_metrics, flow_metrics = _parse_feature_spec(args.features)
        except ValueError as exc:
            print(f"  error: {exc}")
            return 2
        verdict = scorer.score(port_metrics, flow_metrics)
        if verdict is None:
            print("Advisory scorer unavailable.")
            return 1
        print()
        print(f"  advisory score      : {verdict.score:.4f}")
        print(f"  predicted class     : {verdict.predicted}")
        print(f"  band                : {verdict.band}")
        print(f"  recommendation      : {verdict.recommendation}")
        for name, contribution in verdict.top_features:
            print(f"  top feature {name:<22s}: {contribution:+.4f}")
        print()
        return 0

    print("Use --scenario <name> or --features 'k=v,k=v'.")
    return 2


def main() -> None:
    """Main CLI entrypoint."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "run":
        sys.exit(run_command(args))
    elif args.command == "replay":
        sys.exit(replay_command(args))
    elif args.command == "serve":
        sys.exit(serve_command(args))
    elif args.command == "train":
        sys.exit(train_command(args))
    elif args.command == "score":
        sys.exit(score_command(args))
    elif args.command == "selftest":
        sys.exit(selftest_command(args))


if __name__ == "__main__":
    main()
