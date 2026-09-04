# Sentry — Product Requirements Document (PRD)

## 1. Executive Summary
Sentry is a closed-loop, automated SDN attack detection and mitigation system operating on top of the ONOS (Open Network Operating System) controller. It continuously monitors network telemetry via the ONOS REST API, identifies malicious traffic patterns, and applies graduated, self-expiring countermeasures directly to the data plane.

## 2. Target Users & Audience
* **Network Operations Center (NOC) / Security Operators:** Need real-time visibility into incoming network threats, evidence-backed verdicts, and one-click manual override/revocation capabilities.
* **Security Analysts:** Require transparent forensic evidence behind every automated decision, including raw feature vectors, triggered rules, and ledger audit logs[cite: 1, 2].
* **Academic Reviewers / Technical Evaluators:** Require an easily reproducible, zero-external-dependency project that can be verified and demonstrated offline without a complex physical lab[cite: 1, 2].

## 3. Core Functional Requirements
* **FR-1 Multi-Threat Detection:** Detect 8 distinct attack vectors: SYN Flood, UDP Flood, ICMP Flood, Port Scan, ARP Spoofing, Control-Plane Saturation, Flow-Table Exhaustion, and Topology Poisoning (alert-only)[cite: 1, 2].
* **FR-2 Adaptive Telemetry Ingestion:** Poll ONOS REST API every 1–5 seconds with adaptive backoff, normalizing monotonic counters into per-interval delta metrics and handling switch reconnects gracefully[cite: 1, 2].
* **FR-3 Dynamic Baseline Engine:** Maintain EWMA and MAD baselines per subject across rolling time windows[cite: 1, 2]. Freeze baseline updates during active mitigations to prevent oscillation loops[cite: 1, 2].
* **FR-4 Graduated Mitigation Ladder:** Escalate through 5 stages: Stage 0 (Observe), Stage 1 (Throttle/Meter), Stage 2 (Selective Drop Rule), Stage 3 (Host Quarantine), and Stage 4 (Port Isolation via Operator Ack)[cite: 1, 2].
* **FR-5 Tamper-Evident Ledger:** Write every verdict, action, refusal, and revocation to an append-only, SHA-256 hash-chained audit ledger[cite: 1, 2].
* **FR-6 Standalone Operator Dashboard:** Single-file, air-gapped web console rendering real-time topology graphs, threat feeds, canvas charts, and token-guarded write actions[cite: 1, 2].
* **FR-7 Authenticated Operator Login:** Dedicated login interface (`/login`) authenticating operators using `SENTRY_API_TOKEN` via session cookies or HTTP Bearer tokens before granting access to protected routes.

## 4. Non-Functional Requirements
* **NFR-1 Fail-Open Safety:** Every installed OpenFlow rule or meter must carry a hard OpenFlow timeout (`isPermanent=false`)[cite: 1, 2].
* **NFR-2 Execution Speed:** Detection to mitigation latency must complete in under 10 seconds[cite: 1, 2].
* **NFR-3 Zero Third-Party Core Dependencies:** Core runtime must rely strictly on the Python standard library[cite: 1, 2].
* **NFR-4 Auditability:** Every verdict, action, refusal, and revocation must be independently reconstructable from the ledger alone (see FR-5), without relying on external logs.
* **NFR-5 Observability:** Core engine and API must emit structured JSON logs sufficient to reconstruct a full detection-to-mitigation timeline for post-incident review.
* **NFR-6 Credential Hygiene:** `SENTRY_API_TOKEN` and any ONOS Basic Auth credentials must be rotatable without a code change or service rebuild, and must never be logged in plaintext.

## 5. Glossary
* **Subject:** The entity a baseline, detector, or mitigation action is scoped to (e.g. a host, switch port, or flow, depending on the detector). Referenced throughout FR-3, FR-4, and the Phases/Architecture docs — each detector rule should state explicitly which subject granularity it operates on.
* **Dry-Run Mode:** Operating mode in which the Planner and Executor generate and log valid mitigation payloads but do not apply them to the data plane.
* **Enforce Mode:** Operating mode in which generated mitigation payloads are actually applied via the ONOS REST API.

## 6. Out of Scope
* Multi-controller or high-availability ONOS deployments (single ONOS instance only).
* Encrypted-traffic deep packet inspection or payload-level analysis.
* Multi-site or WAN-scale topologies; project targets a single-site Mininet lab.
* Attack vectors outside the 8 listed in FR-1 (e.g. DNS amplification, application-layer/L7 attacks).
* Automated response actions beyond the 5-stage mitigation ladder (e.g. upstream ISP coordination, automatic firewall rule propagation outside the SDN fabric).