# Sentry — Phased Execution Plan

## Phase 1: Core Foundation & Telemetry Pipeline
* Implement `pyproject.toml`, `core/minyaml.py` (tested first), `models.py`, `config.py`, and JSON logging[cite: 2].
* Build `urllib` HTTP transport layer with `FakeTransport` for offline mocking[cite: 2].
* Construct `OnosClient` for endpoints (`devices`, `flows`, `hosts`, `links`, `statistics`)[cite: 2].
* Build telemetry `Poller` and `Normalizer` handling counter resets and switch reconnects[cite: 2].
* **Exit Gate:** `python -m sentry run --once` outputs normalized telemetry against mock fixtures[cite: 2].

## Phase 2: Feature Pipeline & Baselines
* Build `Window` manager maintaining EWMA mean and MAD deviation baselines[cite: 2].
* Implement Invariant I9 baseline freeze hook when active mitigations exist[cite: 2].
* Implement normalized Shannon Entropy calculation module[cite: 2].
* Build `Extractor` generating 16 statistical features per subject window[cite: 2].
* **Exit Gate:** Entropy verified against hand-computed test cases; warmup gating suppresses false alerts[cite: 2].

## Phase 3: Offline Simulation & Replay Harness
* Create `sim/scenarios.py` generating synthetic telemetry for benign traffic and 8 threat profiles[cite: 2].
* Build `sim/replay.py` offline test engine running against `FakeTransport`[cite: 2].
* **Exit Gate:** `python -m sentry selftest` passes all 8 scenarios offline without ONOS, Docker, or root[cite: 2].

## Phase 4: Threat Detectors & Correlator
* Implement all 8 detector rules per PRD FR-1: SYN Flood, UDP Flood, ICMP Flood, Port Scan, ARP Spoofing, Control-Plane Saturation, Flow-Table Exhaustion, and Topology Poisoning[cite: 2].
* Note: Topology Poisoning is **alert-only** per FR-1 — it must feed the Correlator and Threat Feed but must never reach the Planner/Executor for automated mitigation.
* Build `Correlator` tracking threat state, hysteresis (2 positive windows / 5 clean windows), and subject escalation stages[cite: 2].
* **Exit Gate:** All scenarios detected within 10-second latency bounds; benign traffic triggers zero alerts in the offline replay suite (see `sim/scenarios.py`, Phase 3).

## Phase 5: Mitigation Engine & Safety Rails (Dry-Run)
* Build OpenFlow payload construction methods in `onos/payloads.py`[cite: 2].
* Build `Planner` with 5-stage escalation ladder and 8 sequential safety rail checks[cite: 2].
* Implement `Executor` in dry-run mode and hash-chained audit `Ledger`[cite: 2].
* **Exit Gate:** Valid ONOS payloads generated and logged; tampered ledger correctly fails verification test[cite: 2].

## Phase 6: Live Lab Enforcement
* Wire real `Executor`, `Verifier` read-back, `Reaper` thread, and startup reconciliation[cite: 2].
* Create `deploy/docker-compose.yml`, Dockerfiles, `topo_lab.py`, and attack scripts[cite: 2].
* Document manual rollback procedure for a misfired Stage 3/4 mitigation (operator-triggered Revoke via dashboard/API, independent of Reaper TTL auto-expiry) as part of `RUNBOOK.md`.
* **Exit Gate:** Live lab tests achieve >90% attack drop rate; mid-attack container kill results in complete TTL auto-expiry; manual revoke of a Stage 3/4 rule is verified to restore prior flow state within one polling interval.

## Phase 7: API, Authentication, Login Screen & Dashboard
* Implement `ThreadingHTTPServer` API with bearer-token and session-cookie authorization (`api/auth.py`)[cite: 2].
* Create `src/sentry/api/static/login.html` (Vanilla JS / CSS)[cite: 2].
* Create single-file `src/sentry/api/static/dashboard.html` with vanilla JS, SVG topology graph, and Canvas metrics chart[cite: 2].
* Implement `replay --scenario syn_flood --serve` CLI flag for offline browser demonstrations[cite: 2].
* **Exit Gate:** Unauthenticated requests redirect to `/login`; dashboard renders attack cycles offline; invalid tokens return HTTP 401[cite: 2].

## Phase 8: ML Advisory Scorer & Documentation
* Build pure-Python logistic regression scorer and synthetic training script (`train.py`)[cite: 2].
* Finalize `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `RUNBOOK.md`, and `DEMO.md`[cite: 2].
* **Exit Gate:** CI workflow (`ruff`, `mypy`, `pytest`) passes cleanly on GitHub Actions[cite: 2].