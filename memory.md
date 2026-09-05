---
name: sentry-project
description: Sentry SDN attack detection & mitigation system — project overview, location, tech stack, and current status
metadata:
  type: project
---

## Sentry Project

**Location:** `C:\Users\tanis\Desktop\Sentry`

**What it is:** A closed-loop, automated SDN attack detection and mitigation system built on top of the ONOS controller. It monitors network telemetry, detects 8 attack types (SYN Flood, UDP Flood, ICMP Flood, Port Scan, ARP Spoofing, Control-Plane Saturation, Flow-Table Exhaustion, Topology Poisoning), and applies graduated 5-stage countermeasures.

**Tech Stack:**
- Backend: Python 3.11/3.14 (3.9-compatible syntax), zero third-party dependencies (stdlib only)
- Control Plane: ONOS 2.7.0 (Dockerized)
- Data Plane: Mininet 2.3.1 + Open vSwitch + OpenFlow 1.3
- Frontend: Vanilla JS (ES2020), HTML5 Canvas, Inline SVG — no npm/CDN

**Current Status (as of 2026-09-04):**
- ✅ **Phase 1 COMPLETE** (22/22 tests)
- ✅ **Phase 2 COMPLETE** (44/44 tests total):
  - Shannon Entropy module `features/entropy.py` (11 tests, hand-computed)
  - Window Manager `collect/window.py` with EWMA/MAD baselines (7 tests)
  - Invariant I9 baseline freeze during active mitigations
  - 16-feature vector extractor `features/extractor.py` (4 tests)
  - Warmup gating to suppress false alerts during initialization
- ✅ **Phase 3 COMPLETE** (53/53 tests, selftest passes):
  - `sim/scenarios.py` — synthetic telemetry for 6 attack profiles + benign (ARP spoofing, CP saturation, topology poisoning deferred to Phase 4)
  - `sim/replay.py` — offline test engine with FakeTransport, flow-count tracking for flow-based attacks
  - Exit gate `python -m sentry selftest` passes all scenarios offline
  - `__main__.py` — wired `replay` and `selftest` CLI commands
- ✅ **Phase 4 COMPLETE** (90/90 tests):
  - `detect/rules.py` — 8 detection rules (SYN/UDP/ICMP flood, port scan, flow table exhaustion, ARP spoofing, CP saturation, topology poisoning)
  - `detect/correlator.py` — hysteresis state machine (SUSPECTED → CONFIRMED → ESCALATING → MITIGATING), 2 positive / 5 clean windows
  - Topology Poisoning capped at SUSPECTED (alert-only per FR-1)
  - Severity auto-mapped from confidence (low/medium/high/critical)
- ✅ **Phase 5 COMPLETE** (120/120 tests):
  - `mitigate/payloads.py` — OpenFlow rule construction (all 5 stages, all rules carry `isPermanent=false`)
  - `mitigate/planner.py` — 5-stage escalation ladder with 8 sequential safety rails
  - `mitigate/executor.py` — Dry-run executor with TTL expiry and revocation
  - `mitigate/ledger.py` — Tamper-evident SHA-256 hash-chained audit log (FR-5)
  - Topology Poisoning blocked from automated mitigation at planner level
- ✅ **Phase 6 COMPLETE** (142/142 tests):
  - `mitigate/reaper.py` — Background TTL expiry thread, unfreezes baselines on expiry
  - `mitigate/verifier.py` — Read-back validation of installed OpenFlow rules
  - `mitigate/reconciler.py` — Startup reconciliation (verifies/revokes stale rules, re-freezes baselines)
  - `deploy/docker-compose.yml` — ONOS + Sentry containers with healthcheck
  - `deploy/Dockerfile.sentry` — Python 3.11 slim image, stdlib-only
  - `deploy/topo_lab.py` — 3-switch, 6-host Mininet fat-tree topology
  - `deploy/attacks.py` — 8 attack scripts (syn_flood, udp_flood, icmp_flood, port_scan, flow_exhaustion, arp_spoof, cp_saturation, topo_poison)
  - `RUNBOOK.md` — Operations runbook with manual rollback procedure for Stage 3/4 rules
  - Exit gate requires live Docker/ONOS/Mininet infrastructure (cannot fully test offline)
- ✅ **Phase 7 COMPLETE** (206/206 tests):
  - `api/auth.py` — SessionStore, RateLimiter, Authenticator (bearer-token + session-cookie)
  - `api/routes.py` — Route handlers (login, logout, status, threats, mitigations, revoke, topology, replay)
  - `api/server.py` — ThreadingHTTPServer with route dispatch, static file serving, auth middleware
  - `api/static/login.html` — Dark NOC theme login page, wired to real POST /api/v1/login
  - `api/static/dashboard.html` — Dashboard with SVG topology, Canvas chart, threat feed, mitigation registry
  - `__main__.py` — Added `serve` command and `replay --serve` flag for offline browser demo
  - Exit gate: Unauthenticated → redirect to /login; dashboard renders offline; invalid tokens → 401

**Why:** Context preservation to save token usage across sessions.

**How to apply:** Resume with Phase 3 implementation.
