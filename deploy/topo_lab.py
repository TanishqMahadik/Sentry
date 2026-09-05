#!/usr/bin/env python3
"""Mininet topology lab for Sentry integration testing.

Creates a fat-tree-like topology with:
  - 3 OpenFlow switches (OVS) connected in a triangle
  - 6 end hosts (2 per switch)
  - OpenFlow 1.3 controller pointing to ONOS

Requires: Mininet 2.3+, Open vSwitch, root privileges.

Usage:
    sudo python topo_lab.py           # Start interactive topology
    sudo python topo_lab.py --test    # Run connectivity tests
    sudo python topo_lab.py --attack  # Start attack + detection demo
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    from mininet.cli import CLI
    from mininet.link import TCLink
    from mininet.log import info, setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.util import dumpNodeConnections
except ImportError:
    print("ERROR: Mininet is required. Install with:")
    print("  sudo apt install mininet")
    sys.exit(1)


# ─── Configuration ──────────────────────────────────────────────────────────

CONTROLLER_IP = "10.0.0.100"  # ONOS container (from docker-compose.yml)
CONTROLLER_PORT = 6653
SWITCH_PROTOCOL = "OpenFlow13"


class SentrySwitch(OVSSwitch):
    """OVS switch configured for OpenFlow 1.3."""

    def __init__(self, *args, **kwargs):
        kwargs["protocols"] = SWITCH_PROTOCOL
        super().__init__(*args, **kwargs)


def build_topology() -> Mininet:
    """Build the 3-switch, 6-host test topology.

    Topology layout:

        s1 (10.0.0.100)
       / \\
      s2---s3
     /|   |\\
    h1 h2 h3 h4 h5 h6

    Returns:
        Configured Mininet instance
    """
    net = Mininet(
        controller=lambda name: RemoteController(
            name, ip=CONTROLLER_IP, port=CONTROLLER_PORT
        ),
        switch=SentrySwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    info("*** Adding controller\n")
    net.addController("c0")

    info("*** Adding switches\n")
    s1 = net.addSwitch("s1", dpid="0000000000000001")
    s2 = net.addSwitch("s2", dpid="0000000000000002")
    s3 = net.addSwitch("s3", dpid="0000000000000003")

    info("*** Adding hosts\n")
    # Hosts on s1 (subnet 10.0.1.0/24)
    h1 = net.addHost("h1", ip="10.0.1.1/24", mac="00:00:00:00:01:01")
    h2 = net.addHost("h2", ip="10.0.1.2/24", mac="00:00:00:00:01:02")

    # Hosts on s2 (subnet 10.0.2.0/24)
    h3 = net.addHost("h3", ip="10.0.2.1/24", mac="00:00:00:00:02:01")
    h4 = net.addHost("h4", ip="10.0.2.2/24", mac="00:00:00:00:02:02")

    # Hosts on s3 (subnet 10.0.3.0/24)
    h5 = net.addHost("h5", ip="10.0.3.1/24", mac="00:00:00:00:03:01")
    h6 = net.addHost("h6", ip="10.0.3.2/24", mac="00:00:00:00:03:02")

    info("*** Adding links\n")
    # Host-to-switch links (10 Mbps, 2ms delay)
    net.addLink(h1, s1, cls=TCLink, bw=10, delay="2ms")
    net.addLink(h2, s1, cls=TCLink, bw=10, delay="2ms")
    net.addLink(h3, s2, cls=TCLink, bw=10, delay="2ms")
    net.addLink(h4, s2, cls=TCLink, bw=10, delay="2ms")
    net.addLink(h5, s3, cls=TCLink, bw=10, delay="2ms")
    net.addLink(h6, s3, cls=TCLink, bw=10, delay="2ms")

    # Switch-to-switch links (100 Mbps, 1ms delay)
    net.addLink(s1, s2, cls=TCLink, bw=100, delay="1ms")
    net.addLink(s2, s3, cls=TCLink, bw=100, delay="1ms")
    net.addLink(s1, s3, cls=TCLink, bw=100, delay="1ms")

    return net


def run_connectivity_test(net: Mininet) -> bool:
    """Run ping-all connectivity test.

    Returns:
        True if all pings succeed
    """
    info("\n*** Running connectivity test\n")
    result = net.pingAll()
    return result == 0


def wait_for_controller(net: Mininet, timeout: int = 30) -> bool:
    """Wait for ONOS controller to be reachable.

    Returns:
        True if controller connected within timeout
    """
    info(f"*** Waiting for controller at {CONTROLLER_IP}:{CONTROLLER_PORT}\n")
    start = time.time()
    while time.time() - start < timeout:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((CONTROLLER_IP, CONTROLLER_PORT))
            sock.close()
            info("*** Controller is reachable\n")
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(1)
    info("*** WARNING: Controller not reachable, proceeding anyway\n")
    return False


def run_attack_demo(net: Mininet) -> None:
    """Run a basic attack demo using hping3/nping.

    Launches SYN flood from h1 targeting h3, then waits for
    Sentry to detect and mitigate.
    """
    info("\n*** Starting attack demo\n")
    info("    Attacker: h1 (10.0.1.1)")
    info("    Target:   h3 (10.0.2.1)")
    info("    Duration: 30 seconds\n")

    h1 = net.get("h1")
    h3 = net.get("h3")

    # Ensure h3 is listening
    h3.cmd("python3 -c 'import socket; s=socket.socket(); s.bind((\"0.0.0.0\",80)); s.listen(1)' &")

    info("*** Launching SYN flood from h1 -> h3\n")
    # Use hping3 if available, fallback to nping
    h1.cmd("which hping3 > /dev/null 2>&1")
    h1.popen(
        "hping3 -S -p 80 --flood 10.0.2.1",
        shell=True,
    )

    info("*** Flood running for 30s — watch Sentry dashboard for detection\n")
    time.sleep(30)

    h1.cmd("kill $(pgrep hping3) 2>/dev/null")
    info("*** Attack stopped\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentry SDN Lab Topology")
    parser.add_argument("--test", action="store_true", help="Run connectivity tests")
    parser.add_argument("--attack", action="store_true", help="Run attack demo")
    parser.add_argument("--cli", action="store_true", help="Open Mininet CLI")
    args = parser.parse_args()

    setLogLevel("info")

    info("\n" + "=" * 60)
    info("  Sentry SDN Lab — Building Topology")
    info("=" * 60 + "\n")

    net = build_topology()

    try:
        info("*** Starting network\n")
        net.start()

        wait_for_controller(net)

        info("\n*** Topology started\n")
        dumpNodeConnections(net.hosts)

        if args.test or args.attack:
            # Let STP converge and ONOS install rules
            info("*** Waiting 10s for ONOS to install forwarding rules\n")
            time.sleep(10)

        if args.test:
            success = run_connectivity_test(net)
            if success:
                info("\n*** All connectivity tests PASSED\n")
            else:
                info("\n*** Some pings FAILED — check ONOS is running\n")

        if args.attack:
            run_attack_demo(net)

        if args.cli or (not args.test and not args.attack):
            info("\n*** Starting Mininet CLI (type 'exit' to quit)\n")
            CLI(net)

    finally:
        info("\n*** Stopping network\n")
        net.stop()


if __name__ == "__main__":
    main()
