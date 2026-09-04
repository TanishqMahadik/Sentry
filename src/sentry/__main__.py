"""Sentry CLI entrypoint.

Provides subcommands:
  - run: Start Sentry core engine (live or dry-run)
  - replay: Replay synthetic attack scenarios offline (Phase 3)
  - selftest: Run full test suite offline without external deps (Phase 3)
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
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport, UrllibTransport

logger = logging.getLogger("sentry")


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

    # Command: selftest (Phase 3 exit gate)
    subparsers.add_parser(
        "selftest", help="Run offline self-test suite across all 8 attack vectors"
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
        print("Replay harness will be implemented in Phase 3")
        sys.exit(0)
    elif args.command == "selftest":
        print("Self-test suite will be implemented in Phase 3")
        sys.exit(0)


if __name__ == "__main__":
    main()
