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
- Backend: Python 3.11 (3.9-compatible syntax), zero third-party dependencies
- Control Plane: ONOS 2.7.0 (Dockerized)
- Data Plane: Mininet 2.3.1 + Open vSwitch + OpenFlow 1.3
- Frontend: Vanilla JS (ES2020), HTML5 Canvas, Inline SVG — no npm/CDN

**Project Files:**
- `CLAUDE.md` — Project instructions for AI assistant
- `PRD.md` — Product Requirements Document (8 FRs, 6 NFRs)
- `Phases.md` — 8-phase development plan
- `Design System UI Specs.md` — Dark NOC/SOC theme, color palette, component specs
- `System Architecture Flow.md` — 5-plane architecture (L1-L5), directory structure
- `Teck stack.md` — Technology choices
- `login.html` — Operator authentication page (built, demo auth only)
- `dashboard.html` — SOC/NOC dark-mode console (built)

**Current Status (as of 2026-09-04):**
- Phase 7 frontend files (login.html, dashboard.html) exist as standalone HTML
- Python backend (`src/sentry/...`) has NOT been scaffolded yet
- login.html uses a demo setTimeout stub instead of real fetch('/api/v1/login')
- No git repo initialized yet

**Planned login.html improvements (discussed, not yet applied):**
1. Replace demo auth with real fetch('/api/v1/login')
2. Wire up "Stay signed in" checkbox
3. Implement actual lockout after 5 failed attempts
4. Add loading spinner
5. Add aria-live for screen reader support
6. Clear token field on failed attempts

**Why:** User is building this project and needs context preserved across terminal sessions to save tokens.

**How to apply:** When working in this directory, use this file and CLAUDE.md for context instead of re-reading all spec files.
