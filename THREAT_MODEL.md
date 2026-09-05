# Sentry — Threat Model

Reference for the 8 attack vectors Sentry detects (FR-1). For each threat: what it is, the subject it is scoped to, the primary signals and features, the detection rule and thresholds, the expected ML advisory signature, and the escalation guidance.

Two detection paths coexist:

- **Rule path** (authoritative) — `detect/rules.py` + `correlator.py`, thresholds from `config/policy.yaml`. This path alone decides mitigation.
- **ML advisory path** (read-only) — `ml/advisory.py` consumes the same per-window metrics and produces a probability + band. It never gates or triggers mitigation; treat it as a second, independent opinion surfaced in the API feed and CLI.

Severity bands for the advisory score mirror the rule confidence mapping:

| Band | Advisory score |
|---|---|
| LOW | < 0.40 |
| MEDIUM | 0.40 – 0.60 |
| HIGH | 0.60 – 0.85 |
| CRITICAL | ≥ 0.85 |

---

## 1. SYN Flood

| | |
|---|---|
| **Class label** | `syn_flood` (rule `threat_type` `SYN_FLOOD`) |
| **Subject** | Port/destination host (server) |
| **What it is** | Volumetric TCP SYN burst; many new handshakes, few completing. |
| **Primary signals** | High `pps_rx` with a very low `tx_rx_ratio` (client→server dominant). |
| **Rule** | `SynFloodRule` — `pps_rx_threshold=1000`, `tx_rx_ratio_max=0.3`; `policy.yaml`: `threshold_pps=500`, `baseline_mad_factor=3.0`, `min_confidence=0.85`. |
| **ML signature** | Very high `pps_rx`/`bps_rx`; `tx_rx_ratio` ≪ 0.3; `flow_count` modest for the rate. |
| **Escalation** | HIGH+ → Stage 2 Selective Drop (default TTL 60 s). |

## 2. UDP Flood

| | |
|---|---|
| **Class label** | `udp_flood` (rule `threat_type` `UDP_FLOOD`) |
| **Subject** | Port/destination host |
| **What it is** | Saturating UDP packet burst. |
| **Primary signals** | Very high `pps_rx` regardless of `tx` symmetry. |
| **Rule** | `UdpFloodRule` — `pps_rx_threshold=2000`; `policy.yaml`: `threshold_pps=1000`, `min_confidence=0.85`. |
| **ML signature** | Extreme `pps_rx`/`bps_rx`; `tx_rx_ratio` may be moderate-to-high (echo replies absent in UDP → often low, but burst dominates). |
| **Escalation** | HIGH+ → Stage 2 Selective Drop (60 s). |

## 3. ICMP Flood

| | |
|---|---|
| **Class label** | `icmp_flood` (rule `threat_type` `ICMP_FLOOD`) |
| **Subject** | Port/destination host |
| **What it is** | Ping-style echo flood. |
| **Primary signals** | High `pps_rx` **with** symmetric `pps_tx` (echo replies keep up) — distinguishes it from SYN/UDP floods. |
| **Rule** | `IcmpFloodRule` — `pps_rx_threshold=500`; `policy.yaml`: `threshold_pps=300`, `min_confidence=0.85`. |
| **ML signature** | High `pps_rx` and elevated `tx_rx_ratio` (approaching 1.0); steady `bps_rx`. |
| **Escalation** | MEDIUM+ → Stage 1 Throttle (30 s). |

## 4. Port Scan

| | |
|---|---|
| **Class label** | `port_scan` (rule `threat_type` `PORT_SCAN`) |
| **Subject** | Source host (scanner) |
| **What it is** | Attacker enumerating many destination ports, one-to-few packets each. |
| **Primary signals** | Many unique destination ports; high `flow_count`; low `avg_packets_per_flow`. |
| **Rule** | `PortScanRule` — `flow_count_threshold=20`, `unique_ports_threshold=20`; `policy.yaml`: `min_confidence=0.90`, `window_seconds=5`. |
| **ML signature** | High `unique_dst_ports`, high `flow_count`, **low** `avg_packets_per_flow`; moderate `pps_rx`. |
| **Escalation** | MEDIUM+ → Stage 1 Throttle (30 s). |

## 5. Flow-Table Exhaustion

| | |
|---|---|
| **Class label** | `flow_table_exhaustion` (rule `threat_type` `FLOW_TABLE_EXHAUSTION`) |
| **Subject** | Device (switch) |
| **What it is** | Anomalous flow installation filling the switch's flow table. |
| **Primary signals** | Explosive growth of installed flows; high `flow_table_utilization`. |
| **Rule** | `FlowTableExhaustionRule` — `flow_count_threshold=500`; `policy.yaml`: `table_utilization_pct=85.0`, `min_confidence=0.90`. |
| **ML signature** | High `flow_count`, high `flow_table_utilization`; note packet rates may not be elevated — the flow-plane signal dominates. |
| **Escalation** | HIGH+ → Stage 2 Selective Drop (60 s) toward the offending subject. |

## 6. ARP Spoofing

| | |
|---|---|
| **Class label** | `arp_spoofing` (rule `threat_type` `ARP_SPOOFING`) |
| **Subject** | Host (IP with conflicting MACs) |
| **What it is** | An attacker claims a victim's IP with a different MAC, poisoning the ARP cache. |
| **Primary signals** | Drop in ARP entropy; duplicate (conflicting) MAC claims for one IP. |
| **Rule** | `ArpSpoofRule` — `entropy_threshold=0.3`, `duplicate_mac_threshold=2`; `policy.yaml`: `mac_conflict_threshold=2`, `min_confidence=0.95`. |
| **ML signature** | Low `arp_entropy`, elevated `duplicate_macs`; rate metrics may look normal. |
| **Escalation** | CRITICAL → Stage 3 Host Quarantine (120 s). |

## 7. Control-Plane Saturation

| | |
|---|---|
| **Class label** | `cp_saturation` (rule `threat_type` `CP_SATURATION`) |
| **Subject** | Controller (device) |
| **What it is** | Packet-In/unknown-flow flood overloading the controller's control plane. |
| **Primary signals** | High CPU/control-plane utilization; elevated Packet-In rate. |
| **Rule** | `CpSaturationRule` — `cpu_threshold=0.85`; `policy.yaml`: `packet_in_pps=2000`, `min_confidence=0.90`. |
| **ML signature** | High `cpu_utilization`, high `link_flap_count` if flooding causes reconnects; broad rate elevation. |
| **Escalation** | CRITICAL → Stage 3 Host Quarantine (120 s) on the flooding source. |

## 8. Topology Poisoning

| | |
|---|---|
| **Class label** | `topology_poisoning` (rule `threat_type` `TOPOLOGY_POISONING`) |
| **Subject** | Device / link pair |
| **What it is** | Fabricated or replay-injected topology updates (host/LLDP messages) trick the controller into routing traffic into a dead end or attacker switch. |
| **Primary signals** | Anomalous link state churn; unexpected host/link registrations. |
| **Rule** | `TopologyPoisoningRule` — `link_flap_threshold=3`; `policy.yaml`: `link_flap_threshold=5`, `min_confidence=0.90`, **`alert_only: true`**. |
| **ML signature** | High `link_flap_count`, elevated `src_ip_entropy`/`dst_ip_entropy` (fabricated endpoint diversity). |
| **Escalation** | **Alert-only (FR-1).** Never reaches the planner/executor. The correlator can raise severity for display, but no mitigation is ever issued. |

---

## Advisory vs. Rule Path — when to trust which

- The **rule path** is authoritative and is the *only* path that triggers mitigation. It reasons from a small, explainable set of thresholded features with configured baselines (MAD logit), has hysteresis to prevent flapping, and every decision is audited.
- The **ML advisory path** is a global, learned opinion over a fixed 20-feature vector. It catches *combinations* of subtly-elevated features that individually stay under a rule threshold. Because it is trained on synthetic data, its absolute probability is not a calibrated threat probability — it is a *similarity score* to learned attack operating points. Use it as a second opinion during triage, not as a stand-alone truth source.
- When the two agree, confidence in the verdict is high. When they disagree, the rule path wins by design (advisory can flag but never block).

## Detection latency budget (NFR-2)

Target: detection → mitigation in **under 10 seconds** regardless of path. The correlator confirms on the 2nd consecutive positive window; the poll interval (default 5 s at L4) bounds window cadence. All 8 scenarios pass the offline latency gate in CI (`selftest`).