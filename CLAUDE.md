# Sentry — Project Instructions

## Project Overview
Sentry is a closed-loop, automated SDN attack detection and mitigation system built on ONOS (Open Network Operating System). It monitors network telemetry, detects 8 attack vectors, and applies graduated countermeasures.

## Project Location
`C:\Users\tanis\Desktop\Sentry`

## Tech Stack
- **Backend:** Python 3.11 (3.9-compatible syntax), zero third-party dependencies (stdlib only)
- **Control Plane:** ONOS 2.7.0 (Dockerized)
- **Data Plane:** Mininet 2.3.1 + Open vSwitch + OpenFlow 1.3
- **Frontend:** Vanilla JS (ES2020), HTML5 Canvas, Inline SVG — no npm/CDN

## Coding Conventions
- Python: stdlib only for core runtime (NFR-3)
- Frontend: single-file HTML pages, no build tools, no external dependencies
- CSS: use the design system variables defined in `Design System UI Specs.md`
- Follow the color palette in `:root` CSS variables (dark NOC/SOC theme)
- All OpenFlow rules must have `isPermanent=false` (fail-open safety)

## Key Spec Files (read these before major changes)
- `PRD.md` — Requirements (8 FRs, 6 NFRs)
- `Phases.md` — 8-phase execution plan
- `Design System UI Specs.md` — UI theme, colors, component specs
- `System Architecture Flow.md` — 5-plane architecture, directory structure
- `Teck stack.md` — Technology choices

## Current Status
- Phase 7 frontend files exist: `login.html`, `dashboard.html`
- Python backend (`src/sentry/...`) not yet scaffolded
- No git repo initialized

## Workflow Preferences
- Always explain proposed changes before applying them
- User reviews and approves before edits are made
- Save token usage — use memory files, don't re-read specs unnecessarily
