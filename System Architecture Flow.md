# Sentry — System Architecture & Flow

## 1. Five-Plane System Topology

+---------------------------------------------------------------------+
| L5  OPERATOR PLANE  -- Web Dashboard, Login Screen, REST API, Ledger|
+---------------------------------------------------------------------+
^ status, threats, metrics     | set mode, revoke, ack
|                              v
+---------------------------------------------------------------------+
| L4  DECISION PLANE  -- Sentry Core Engine                     |
|     Poller -> Normalizer -> Window -> Feature Extractor ->           |
|     Detectors -> Correlator -> Policy Planner -> Executor           |
+---------------------------------------------------------------------+
^ GET statistics/flows/hosts   | POST flows/meters/portstate
| (REST API + Basic Auth --    v
|  ONOS credentials, distinct from
|  operator SENTRY_API_TOKEN at L5)
+---------------------------------------------------------------------+
| L3  CONTROL PLANE   -- ONOS Controller 2.7.0                        |
+---------------------------------------------------------------------+
^ port/flow statistics replies | OpenFlow 1.3 Mod messages
|                              v
+---------------------------------------------------------------------+
| L2  DATA PLANE      -- Open vSwitch (OVS) under Mininet              |
+---------------------------------------------------------------------+
^ Ethernet Frames              | Ethernet Frames
|                              v
+---------------------------------------------------------------------+
| L1  ENDPOINT PLANE  -- Benign Clients, Victim Server, Attacker Host |
+---------------------------------------------------------------------+

## 2. Directory & Repository Structure

Sentry/
├── .github/workflows/ci.yml   # Linting and replay CI tests
├── config/
│   ├── sentry.yaml      # Service & ONOS connectivity config
│   └── policy.yaml            # Threat thresholds & safety rails
├── deploy/
│   ├── docker-compose.yml     # Multi-container orchestration
│   ├── Dockerfile.sentry # Non-root Python runtime container
│   ├── Dockerfile.mininet     # Mininet + OVS lab container
│   └── mininet/topo_lab.py    # Multi-switch lab topology
├── src/sentry/
│   ├── __init__.py
│   ├── __main__.py            # CLI entrypoint (run, replay, selftest)
│   ├── app.py                 # Core orchestrator
│   ├── api/                   # Server, auth, topology projection, login, dashboard
│   │   ├── static/
│   │   │   ├── login.html
│   │   │   └── dashboard.html
│   ├── audit/                 # Append-only hash-chained ledger
│   ├── collect/               # Telemetry poller, normalizer, sliding window
│   ├── core/                  # Models, minyaml parser, clock, logging
│   ├── detect/                # Detector engine, rules, correlator, ML scorer
│   ├── features/              # Shannon entropy & 16-feature vector extractor
│   ├── mitigate/              # Policy planner, safety rails, executor, reaper
│   ├── onos/                  # REST client, HTTP transport, payload builders
│   └── sim/                   # Synthetic telemetry scenarios & replay harness
├── tests/                     # Test modules mirroring src structure
├── Makefile                   # Quickstart build commands
├── pyproject.toml             # Python package configuration
└── README.md

## 3. Requirement Traceability

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
| NFR-2 Execution Speed | L4 | `collect/`, `detect/`, `mitigate/` |
| NFR-3 Zero Third-Party Core Dependencies | L4 | core runtime (all `src/sentry/` excl. optional tooling) |
| NFR-4 Auditability | L4/L5 | `audit/` |
| NFR-5 Observability | L4/L5 | `core/` (logging), `api/` |
| NFR-6 Credential Hygiene | L5 | `api/auth.py`, `config/sentry.yaml` |