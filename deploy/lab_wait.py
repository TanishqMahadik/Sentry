#!/usr/bin/env python3
"""Persistent Mininet lab test with extended topology-convergence wait.

Curves the 10s --test wait in topo_lab.py, which is too short for ONOS
LLDP link discovery. Launches the same topology, waits for ONOS to
learn links, then runs ping-all.
"""

from topo_lab import build_topology, setLogLevel

import time


def main() -> None:
    setLogLevel("info")
    print("\n=== Sentry Lab — extended convergence test ===\n")
    net = build_topology()
    try:
        net.start()
        # Wait for ONOS to discover inter-switch links via LLDP/NETCONF.
        # LINK_UP takes ~10s per hop in practice; give it a generous window.
        for i in range(1, 7):
            time.sleep(5)
            print(f"  ...converging {i*5}s", flush=True)
        print("\n*** Running ping-all after convergence\n")
        result = net.pingAll()
        ok = result == 0
        print("\n" + ("*** All connectivity tests PASSED" if ok else "*** Some pings FAILED"))
    finally:
        net.stop()
        print("\n*** Done")


if __name__ == "__main__":
    main()
