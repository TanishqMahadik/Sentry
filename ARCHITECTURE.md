# Sentry — System Architecture

Sentry is a closed-loop, automated SDN attack detection and mitigation system built on ONOS. This document is the authoritative architecture reference: five-plane topology, module map, and the end-to-end data flow (including the Phase 8 ML advisory side-channel).

Companion documents: [`THREAT_MODEL.md`](THREAT_MODEL.md), [`DEMO.md`](DEMO.md), [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. Five-Plane Topology

Sentry spans five planes, each with a clear boundary and a protocol to the next:

```
┌────────────────────────────────────────────────────────────────────┐
│ L5  OPERATOR PLANE   Web Dashboard · Login Screen · REST API ·      │
│                      Audit Ledger · ML Advisory Feed                │
└────────────────────────────────────────────────────────────────────┘
        ▲ status, threats, advisory        │ set mode, revoke, ack
        │                                  ▼
┌────────────────────────────────────────────────────────────────────┐
│ L4  DECISION PLANE   Sentry Core Engine                             │
│     Poller → Normalizer → Window → Feature Extractor →              │
│     Detectors → Correlator → Policy Planner → Executor              │
│     └── ML Advisory Scorer (side-channel, read-only)                │
└────────────────────────────────────────────────────────────────────┘
        ▲ GET statistics/flows/hosts       │ POST flows/meters/portstate
        │ (ONOS Basic Auth —               ▼  distinct from operator
        │  SENTRY_API_TOKEN at L5)             token at L5
┌────────────────────────────────────────────────────────────────────┐
│ L3  CONTROL PLANE    ONOS Controller 2.7.0                          │
└────────────────────────────────────────────────────────────────────┘
        ▲ port/flow statistics replies      │ OpenFlow 1.3 Mod messages
        │                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│ L2  DATA PLANE       Open vSwitch (OVS) under Mininet               │
└────────────────────────────────────────────────────────────────────┘
        ▲ Ethernet Frames                   │ Ethernet Frames
        │                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│ L1  ENDPOINT PLANE   Benign Clients · Victim Server · Attacker Host │
└────────────────────────────────────────────────────────────────────┘
```

## 2. Module Map

All runtime modules live under `src/sentry/`. The runtime is **stdlib-only** (NFR-3) — `ml/` includes a pure-Python logistic regression so no numpy/sklearn dependency is introduced.

| Plane | Module | Responsibility |
|---|---|---|
| L4 | `core/` | Dataclasses (`TelemetrySnapshot`, `ThreatVerdict`, `MitigationAction`, `BaselineWindow`, …), `minyaml` config parser, clock, logging |
| L4 | `onos/` | ONOS REST client, HTTP transport (real + fake), OpenFlow payload builders |
| L4 | `collect/` | Adaptive telemetry poller, counter normalization, sliding window, EWMA/MAD baseline engine |
| L4 | `features/` | Shannon entropy + feature-vector extraction feeding the detectors |
| L4 | `detect/` | Detector engine, per-threat rules (`SynFloodRule`, `PortScanRule`, …), correlator with hysteresis |
| L4 | `mitigate/` | Policy planner, safety rails, executor, TTL reaper, startup reconciler |
| L4 | `audit/` | Append-only SHA-256 hash-chained ledger |
| L4 | `ml/` | **Advisory-only** scorer: `logistic.py` (model), `weights.py` (persistence), `advisory.py` (facade), `train.py` (synthetic training + CLI logic) |
| L4 | `sim/` | Synthetic telemetry scenarios + offline replay harness (demo/CI path) |
| L5 | `api/` | HTTP server, auth (token + session cookie, rate-limited), route handlers, static dashboard/login |
| L4/L5 | `__main__.py` | CLI entrypoint: `run`, `replay`, `serve`, `selftest`, `train`, `score`, `verify-ledger` |

Deployment helpers (not part of the runtime) live under `deploy/`: `docker-compose.yml`, `Dockerfile.sentry`, `Dockerfile.mininet`, Mininet `mininet/topo_lab.py` (topology), `topo_lab.py`/`attacks.py` (host attack scripts), `onos-config/`.

## 3. Data Flow — Detection Path (authoritative)

This is the rule-driven path that actually makes decisions. Mitigation is only ever triggered here.

```
ONOS REST ──► collect/ (poller ─► normalizer ─► window)   forward metrics
                       │
                       ├──► features/ (extractor, entropy)  per-window vectors
                       │          │
                       │          ▼
                       ├──► detect/ (rules ─► correlator ─► ThreatVerdict)
                       │          │
                       │          ▼              confirmed → reads policy.yaml
                       └──► mitigate/ (planner ─► safety rails ─► executor ─► ONOS)
                                  │
                                  ├──► audit/ (every verdict & action, hash-chained)
                                  └──► api/ (mitigations feed -> dashboard)
```

1. **Poll** — `TelemetryPoller` queries ONOS REST at the configured interval (1–5 s) with adaptive backoff on failure.
2. **Normalize** — `TelemetryNormalizer` converts monotonic counters into per-interval delta *rates* (`pps_rx`, `bps_tx`, drops, errors) and handles switch reconnects.
3. **Window & baseline** — pieces the normalized rates into a rolling window and maintains per-subject EWMA/MAD baselines. Baselines **freeze** while a mitigation is active on a subject (Invariant I9) so the system never learns an attack as normal.
4. **Extract features** — `features/` builds entropy metrics and the detection feature set consumed by the rules.
5. **Detect** — each `DetectionRule` evaluates its subject(s); the correlator fuses rule verdicts and applies hysteresis (2 positive windows to confirm, 5 clean windows to clear).
6. **Plan & mitigate** — confirmed `ThreatVerdict`s go to the planner, which selects a stage on the 5-stage ladder. The executor checks 8 sequential safety rails before issuing any ONOS payload (`isPermanent=false` on every rule — fail-open).
7. **Audit** — every verdict, planned action, refusal, application, expiry, and revocation is appended to the ledger.
8. **Surface** — the API exposes threats and mitigations to the dashboard; operators can revoke Stage 3/4 actions.

## 4. Data Flow — ML Advisory Side-Channel (read-only)

Phase 8 adds **advisory** scoring. The ML scorer consumes the *same* per-window metrics as the rule detectors and produces a probabilistic estimate of attack plus a recommendation band. It is deliberately a **side-channel**: it annotates the API threat feed and the CLI output but **never** gates, triggers, or overrides mitigation.

```
   same per-window metrics (port_metrics + flow_metrics)
   ────────────────────────────────►  ml/advisory.py  ─► AdvisoryVerdict
                                            (score, predicted, band,
                                             top_features, recommendation)
                                                │
                                                ├──► api/routes.py → threats feed
                                                │     (adds "advisory" key)
                                                └──► CLI: sentry score --features/--scenario
```

- **Model**: pure-Python logistic regression (`ml/logistic.py`) — binary + one-vs-rest multiclass, gradient descent with L2 and feature standardization. No third-party deps.
- **Weights**: trained parameters persist to `models/advisory_weights.json` via `ml/weights.py`; the scorer loads them offline at startup. Missing weights ⇒ scorer reports *unavailable* and the API/CLI degrade gracefully (no `advisory` key).
- **Training data**: `ml/train.py` synthesizes labeled per-window vectors for `benign` + the 8 attack classes, with ranges derived from `detect/rules.py` thresholds and `sim/scenarios.py` signal patterns. Synthetic **and** scenario-derived traces are used so the offline demo classifies correctly.
- **Bands** (`ml/advisory.py`): `<0.40` LOW · `<0.60` MEDIUM · `<0.85` HIGH · `≥0.85` CRITICAL. These mirror the severity mapping in `detect/rules.py`.
- **Trust boundary**: the executor and planner have no reference to `ml/`. The advisory result is informational only. See [`THREAT_MODEL.md`](THREAT_MODEL.md) for per-threat feature signatures.

## 5. Mitigation Ladder & Safety

| Stage | Name | Action | Default TTL |
|---|---|---|---|
| 0 | Observe | Flag + track subject | — |
| 1 | Throttle | Rate-limiting OpenFlow meter | 30 s |
| 2 | Selective Drop | Low-priority DROP flow rule | 60 s |
| 3 | Host Quarantine | Subject isolated from topology | 120 s |
| 4 | Port Isolation | Full port shutdown — **operator ack required** | 300 s |

Escalation uses 2 positive windows; de-escalation uses 5 clean windows (hysteresis). All rules are `isPermanent=false`; the reaper and startup reconciler enforce TTL expiry even if Sentry is killed mid-attack.

## 6. Requirement Traceability

| Requirement | Plane | Module(s) |
|---|---|---|
| FR-1 Multi-Threat Detection (8 vectors; topology poisoning alert-only) | L4 | `detect/` |
| FR-2 Adaptive Telemetry Ingestion | L4 | `collect/`, `onos/` |
| FR-3 Dynamic Baseline Engine | L4 | `collect/` (Window), `features/` |
| FR-4 Graduated Mitigation Ladder | L4 | `mitigate/` |
| FR-5 Tamper-Evident Ledger | L4/L5 | `audit/` |
| FR-6 Standalone Operator Dashboard | L5 | `api/static/dashboard.html` |
| FR-7 Authenticated Operator Login | L5 | `api/auth.py`, `api/static/login.html` |
| NFR-1 Fail-Open Safety | L4 | `onos/payloads.py`, `mitigate/` |
| NFR-2 Execution Speed (<10 s detection→mitigation) | L4 | `collect/`, `detect/`, `mitigate/` |
| NFR-3 Zero Third-Party Core Dependencies | L4 | core runtime incl. `ml/` |
| NFR-4 Auditability | L4/L5 | `audit/` |
| NFR-5 Observability | L4/L5 | `core/` (logging), `api/` |
| NFR-6 Credential Hygiene | L5 | `api/auth.py`, `config/sentry.yaml` |

## 7. Config & Policy

- `config/sentry.yaml` — service mode (dry-run/enforce), poll interval, ONOS connectivity + credentials.
- `config/policy.yaml` — per-threat thresholds (`threats:`), mitigation ladder + TTLs, and the safety rails (`mitigation:`).