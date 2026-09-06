#!/usr/bin/env python3
"""Long-running Mininet+ONOS monitor.

Keeps the 3-switch topology up for 90 s, polls ONOS every 5 s
for devices/links/hosts, and pings continuously so the log shows
when forwarding actually comes up.

Usage in WSL2:
    sudo python3 /mnt/c/Users/tanis/Desktop/Sentry/deploy/lab_monitor.py
"""

from topo_lab import build_topology, setLogLevel
import time
import json
import urllib.request
import urllib.error


def fetch(path: str):
    url = f"http://127.0.0.1:8181{path}"
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, "karaf", "karaf")
    handler = urllib.request.HTTPBasicAuthHandler(mgr)
    opener = urllib.request.build_opener(handler)
    opener.open(url, timeout=5)
    req = opener.open(url, timeout=5)


def get_json(path: str) -> dict:
    url = f"http://127.0.0.1:8181{path}"
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, "karaf", "karaf")
    handler = urllib.request.HTTPBasicAuthHandler(mgr)
    opener = urllib.request.build_opener(handler)
    with opener.open(url, timeout=5) as r:
        return json.loads(r.read().decode())


def main() -> None:
    setLogLevel("info")
    print("\n=== Sentry Lab Monitor — 90 s live poll ===\n")
    net = build_topology()
    try:
        net.start()
        # Poll loop: every 5 s query ONOS and ping
        for i in range(1, 19):
            time.sleep(5)
            ts = f"t={i*5:3d}s"
            try:
                dev = get_json("/onos/v1/devices")
                links = get_json("/onos/v1/links")
                hosts = get_json("/onos/v1/hosts")
                stats = get_json("/onos/v1/statistics/ports")
                nd = sum(1 for d in dev.get("devices", []) if d.get("available"))
                total = len(dev.get("devices", []))
                nl = len(links.get("links", []))
                nh = len(hosts.get("hosts", []))
                ps = len(stats.get("statistics", []))
                print(
                    f"  [{ts}] devices {nd}/{total}  links {nl}  hosts {nh}  portStats {ps}",
                    flush=True,
                )
                if i % 3 == 0 and nd > 0:
                    # pingall probe every 15 s
                    r = net.pingAll(timeout="1")
                    print(f"         pingAll drops={r} (0=full reach)", flush=True)
            except Exception as e:
                print(f"  [{ts}] poll error: {e}", flush=True)

        print("\nMonitor window done — shutting down\n")
    finally:
        # Use setLogLevel to suppress mininet's stop banner if any
        net.stop()
        print("*** Done ***")


if __name__ == "__main__":
    main()
