# Sentry

**A closed-loop, automated SDN attack detection and mitigation system built on ONOS.**

Sentry continuously monitors network telemetry via the ONOS REST API, identifies malicious traffic patterns using statistical baselining and rule-based detectors, and applies graduated, self-expiring countermeasures directly to the data plane — with every verdict, action, and revocation written to a tamper-evident audit ledger.

---

## Table of Contents

- [Why Sentry](#why-sentry)
- [Core Features](#core-features)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Directory Structure](#directory-structure)
- [Getting Started](#getting-started)
- [Operator Dashboard & Login](#operator-dashboard--login)
- [Mitigation Ladder](#mitigation-ladder)
- [Safety Guarantees](#safety-guarantees)
- [Project Status / Phases](#project-status--phases)
- [Out of Scope](#out-of-scope)
- [Glossary](#glossary)

---

## Why Sentry

Most SDN security demos either require a live attack lab to show anything, or skip the safety rails that make automated mitigation trustworthy enough to run unattended. Sentry is built to satisfy three audiences at once:

- **NOC / Security Operators** — real-time visibility into threats, evidence-backed verdicts, one-click manual override and revocation.
- **Security Analysts** — full forensic transparency behind every automated decision: raw feature vectors, triggered rules, and a hash-chained ledger.
- **Reviewers / Evaluators** — a zero-external-dependency core that can be verified and demonstrated **entirely offline**, without a physical lab, Docker, or root access.

## Core Features

| Requirement | Description |
|---|---|
| **Multi-Threat Detection** | Detects 8 distinct attack vectors: SYN Flood, UDP Flood, ICMP Flood, Port Scan, ARP Spoofing, Control-Plane Saturation, Flow-Table Exhaustion, and Topology Poisoning (alert-only). |
| **Adaptive Telemetry Ingestion** | Polls the ONOS REST API every 1–5s with adaptive backoff; normalizes monotonic counters into per-interval deltas and handles switch reconnects gracefully. |
| **Dynamic Baseline Engine** | Maintains EWMA and MAD (Median Absolute Deviation) baselines per subject over rolling windows; freezes baseline updates during active mitigations to prevent oscillation loops. |
| **Graduated Mitigation Ladder** | Escalates through 5 stages, from passive observation to operator-acknowledged port isolation. See [Mitigation Ladder](#mitigation-ladder). |
| **Tamper-Evident Ledger** | Every verdict, action, refusal, and revocation is written to an append-only, SHA-256 hash-chained audit ledger. |
| **Standalone Operator Dashboard** | Single-file, air-gapped web console — topology graph, live threat feed, canvas baseline chart, token-guarded write actions. |
| **Authenticated Operator Login** | Dedicated `/login` interface authenticating operators via `SENTRY_API_TOKEN`, session cookies, or HTTP Bearer tokens. |
| **ML Advisory Scorer** | Pure-Python logistic regression (stdlib-only, no numpy/sklearn) that scores the same per-window metrics as the rule detectors, producing an advisory probability, class guess, and band (`LOW→CRITICAL`). It annotates the API threat feed and CLI, never the mitigation path. See `THREAT_MODEL.md`. |

## System Architecture

Sentry is organized into five planes, each with a clear boundary and protocol to the next:

```
┌───────────────────────────────────────────────────────────────────┐
│ L5  OPERATOR PLANE   Web Dashboard · Login Screen · REST API ·      │
│                      Ledger                                        │
└───────────────────────────────────────────────────────────────────┘
        ▲ status, threats, metrics     │ set mode, revoke, ack
        │                              ▼
┌───────────────────────────────────────────────────────────────────┐
│ L4  DECISION PLANE   Sentry Core Engine                             │
│     Poller → Normalizer → Window → Feature Extractor →              │
│     Detectors → Correlator → Policy Planner → Executor              │
└───────────────────────────────────────────────────────────────────┘
        ▲ GET statistics/flows/hosts   │ POST flows/meters/portstate
        │ (ONOS Basic Auth —           ▼  distinct from operator
        │  SENTRY_API_TOKEN at L5)
┌───────────────────────────────────────────────────────────────────┐
│ L3  CONTROL PLANE    ONOS Controller 2.7.0                          │
└───────────────────────────────────────────────────────────────────┘
        ▲ port/flow statistics replies │ OpenFlow 1.3 Mod messages
        │                              ▼
┌───────────────────────────────────────────────────────────────────┐
│ L2  DATA PLANE       Open vSwitch (OVS) under Mininet                │
└───────────────────────────────────────────────────────────────────┘
        ▲ Ethernet Frames              │ Ethernet Frames
        │                              ▼
┌───────────────────────────────────────────────────────────────────┐
│ L1  ENDPOINT PLANE   Benign Clients · Victim Server · Attacker Host │
└───────────────────────────────────────────────────────────────────┘
```

### Requirement Traceability

| Requirement | Plane | Module(s) |
|---|---|---|
| FR-1 Multi-Threat Detection | L4 | `detect/` |
| FR-2 Adaptive Telemetry Ingestion | L4 | `collect/`, `onos/` |
| FR-3 Dynamic Baseline Engine | L4 | `collect/` (Window), `features/` |
| FR-4 Graduated Mitigation Ladder | L4 | `mitigate/` |
| FR-5 Tamper-Evident Ledger | L4/L5 | `audit/` |
| FR-6 Standalone Operator Dashboard | L5 | `api/static/dashboard.html` |
| FR-7 Authenticated Operator Login | L5 | `api/auth.py`, `api/static/login.html` |
| NFR-1 Fail-Open Safety | L4 | `onos/payloads.py`, `mitigate/` |
| NFR-2 Execution Speed (<10s detection→mitigation) | L4 | `collect/`, `detect/`, `mitigate/` |
| NFR-3 Zero Third-Party Core Dependencies | L4 | core runtime |
| NFR-4 Auditability | L4/L5 | `audit/` |
| NFR-5 Observability | L4/L5 | `core/` (logging), `api/` |
| NFR-6 Credential Hygiene | L5 | `api/auth.py`, `config/sentry.yaml` |

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 runtime, written in 3.9-compatible syntax for broader deployability |
| Control Plane | ONOS 2.7.0 (Dockerized) |
| Data Plane / Emulator | Mininet 2.3.1b4, Open vSwitch 2.17+, OpenFlow 1.3 |
| Frontend | Vanilla ES2020 JavaScript, HTML5 Canvas, inline SVG — zero npm/CDN dependencies |
| Core runtime dependencies | Python standard library only (NFR-3) |

## Directory Structure

```
Sentry/
├── .github/workflows/ci.yml   # Linting, typing & test CI (Phase 8 exit gate)
├── config/
│   ├── sentry.yaml             # Service & ONOS connectivity config
│   └── policy.yaml             # Threat thresholds & safety rails
├── deploy/
│   ├── docker-compose.yml      # Multi-container orchestration
│   ├── Dockerfile.sentry       # Non-root Python runtime container
│   ├── onos-config/            # ONOS runtime customization
│   ├── topo_lab.py             # Mininet lab topology (requires root)
│   ├── attacks.py              # Per-attack traffic generator scripts
│   └── mininet/                # Mininet lab container helpers
├── models/
│   └── advisory_weights.json   # Committed ML advisor weights (offline scoring)
├── src/sentry/
│   ├── __init__.py
│   ├── __main__.py             # CLI entrypoint (run, replay, serve, selftest, train, score)
│   ├── api/                    # Server, auth, routes, static login + dashboard
│   │   └── static/
│   │       ├── login.html
│   │       └── dashboard.html
│   ├── audit/                  # Append-only hash-chained ledger
│   ├── collect/                # Telemetry poller, normalizer, sliding window, baselines
│   ├── core/                   # Models, minyaml parser, clock, logging
│   ├── detect/                 # Detector engine, rules, correlator
│   ├── features/               # Shannon entropy & feature-vector extractor
│   ├── mitigate/               # Policy planner, safety rails, executor, reaper
│   ├── ml/                     # Advisory-only ML scorer (Phase 8): logistic, weights, advisory, train
│   ├── onos/                   # REST client, HTTP transport, payload builders
│   └── sim/                    # Synthetic telemetry scenarios & replay harness
├── tests/                      # Test modules mirroring src structure (incl. tests/ml/)
├── pyproject.toml              # Python package configuration (ruff/mypy/pytest)
├── ARCHITECTURE.md             # Five-plane architecture & data flows
├── THREAT_MODEL.md             # Per-threat detection & advisory signatures
├── DEMO.md                     # Step-by-step offline demo walkthrough
├── RUNBOOK.md                  # Live-lab deployment & operations
└── README.md
```

## Getting Started

Sentry is designed to be fully verifiable **offline**, with no ONOS instance, Docker, or root privileges required.

```bash
# Run the full offline self-test suite (all 8 threat scenarios, no external deps)
python -m sentry selftest

# Run a single telemetry pass against mock fixtures
python -m sentry run --once

# Replay a specific attack scenario and serve the dashboard locally for a demo
python -m sentry replay --scenario syn_flood --serve

# ML advisory scorer (Phase 8): retrain the pure-Python model, then score an attack
python -m sentry train
python -m sentry score --scenario syn_flood
```

The ML scorer is advisory-only — it annotates the API threat feed and CLI output but never gates or triggers mitigation. For the full walkthrough see `DEMO.md`; for a live lab run against a real ONOS + Mininet topology see `deploy/docker-compose.yml` and `RUNBOOK.md`.

## Operator Dashboard & Login

`src/sentry/api/static/login.html` and `dashboard.html` are single-file, dependency-free consoles styled as a dark SOC/NOC theme (see the Design System doc for the full spec).

- **Login** — token-based authentication (`SENTRY_API_TOKEN`), HttpOnly + SameSite=Strict session cookie, per-IP rate limiting with lockout on repeated failures.
- **Dashboard** — mode badge (DRY-RUN / ENFORCE), kill-switch, stat tiles, an SVG topology graph (color *and* shape encode node state), a live threat feed with an evidence drawer (raw feature vectors + matched triggers), a Canvas chart of EWMA/MAD baselines with hatched active-mitigation regions, and a mitigation registry with live TTL countdowns and one-click Revoke.

Unauthenticated requests redirect to `/login`; invalid tokens return HTTP 401.

## Mitigation Ladder

Sentry escalates through five stages rather than jumping straight to a block — each stage is logged to the ledger regardless of outcome:

| Stage | Name | Action |
|---|---|---|
| 0 | Observe | No action; subject flagged and tracked |
| 1 | Throttle / Meter | Rate-limiting meter applied toward the subject |
| 2 | Selective Drop Rule | Low-priority DROP OpenFlow rule installed |
| 3 | Host Quarantine | Subject isolated from the rest of the topology |
| 4 | Port Isolation (Operator Ack) | Full port shutdown, requires explicit operator acknowledgment |

Escalation and de-escalation use hysteresis (2 positive windows to escalate, 5 clean windows to de-escalate) to avoid flapping.

## Safety Guarantees

- **Fail-open by default** — every installed OpenFlow rule or meter carries a hard timeout (`isPermanent=false`); nothing persists indefinitely without operator action.
- **Sub-10-second response** — detection-to-mitigation latency is bounded and tested in CI.
- **8 sequential safety rail checks** run before any mitigation payload is issued.
- **Baseline freeze** — EWMA/MAD baselines stop updating while a mitigation is active on a subject, preventing the detector from "learning" the attack as normal.
- **Tamper-evident ledger** — a deliberately corrupted ledger fails verification as part of the CI exit gate for Phase 5.
- **Manual rollback** — any Stage 3/4 mitigation can be reverted via the dashboard's Revoke action independently of TTL auto-expiry; documented in `RUNBOOK.md`.

## Project Status / Phases

| Phase | Focus | Exit Gate |
|---|---|---|
| 1 | Core foundation & telemetry pipeline | `python -m sentry run --once` outputs normalized telemetry against mock fixtures |
| 2 | Feature pipeline & baselines | Entropy verified against hand-computed cases; warmup gating suppresses false alerts |
| 3 | Offline simulation & replay harness | `python -m sentry selftest` passes all 8 scenarios offline |
| 4 | Threat detectors & correlator | All scenarios detected within 10s; zero false positives on benign traffic |
| 5 | Mitigation engine & safety rails (dry-run) | Valid ONOS payloads generated and logged; tampered ledger fails verification |
| 6 | Live lab enforcement | >90% attack drop rate; TTL auto-expiry survives mid-attack container kill |
| 7 | API, auth, login & dashboard | Unauthenticated requests redirect to `/login`; invalid tokens return 401 |
| 8 | ML advisory scorer & documentation | CI (`ruff`, `mypy`, `pytest`) passes cleanly on GitHub Actions |

See `Phases.md` for the full breakdown.

## Out of Scope

- Multi-controller or high-availability ONOS deployments (single ONOS instance only)
- Encrypted-traffic deep packet inspection or payload-level analysis
- Multi-site or WAN-scale topologies (single-site Mininet lab only)
- Attack vectors beyond the 8 listed above (e.g. DNS amplification, L7/application-layer attacks)
- Response actions beyond the 5-stage mitigation ladder (e.g. upstream ISP coordination)

## Glossary

- **Subject** — the entity a baseline, detector, or mitigation action is scoped to (a host, switch port, or flow, depending on the detector).
- **Dry-Run Mode** — the Planner/Executor generate and log valid mitigation payloads without applying them to the data plane.
- **Enforce Mode** — generated mitigation payloads are actually applied via the ONOS REST API.

---

*For deeper detail see `ARCHITECTURE.md`, `THREAT_MODEL.md`, `RUNBOOK.md`, and `DEMO.md` (Phase 8 deliverables).*
