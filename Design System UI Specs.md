# Sentry — Design System & UI Specs

## 1. Visual Theme & Color Palette
Dark-mode SOC/NOC console theme designed for contrast and legibility:

```css
:root {
  --bg-primary: #0f172a;      /* Deep Slate Blue */
  --bg-secondary: #1e293b;    /* Card Surface Slate */
  --bg-tertiary: #334155;     /* Border / Divider Slate */
  --text-main: #f8fafc;       /* High Contrast White */
  --text-muted: #94a3b8;      /* Muted Slate Text */
  
  --status-dryrun: #f59e0b;   /* Amber (Dry-Run Mode) */
  --status-enforce: #ef4444;  /* Red (Enforce Mode) */
  --status-normal: #10b981;   /* Emerald Green (Healthy) */
  --status-suspect: #f97316;  /* Orange (Anomalous Traffic) */
  --status-mitigated: #a855f7;/* Purple (Active Mitigation Rule) */
}

2. Typography & Fonts
Font Family: System Monospace / UI Sans Fallbacks (Consolas, Fira Code, Monaco, system-ui).

Scale: Headers 1.25rem, Metrics 1.75rem, Body 0.875rem, Logs/Hashes 0.75rem.

3. Login Screen Specification 
(src/sentry/api/static/login.html)
Layout: Centered Slate card (bg-secondary), clear typography, minimal brand header.

Controls: Password/Token field (type="password"), "Authenticate Session" primary button (bg-status-enforce).

Behavior: Submits via fetch('/api/v1/login'). Upon HTTP 200, sets an HttpOnly, SameSite=Strict cookie and redirects to /.

Session Expiry: Session cookie carries a fixed TTL (default configurable via `sentry.yaml`); on expiry mid-session, the dashboard's next API call receives HTTP 401 and the client redirects back to `/login` with the in-progress view state discarded.

Rate Limiting: `/api/v1/login` enforces a per-source-IP attempt cap with exponential backoff (e.g. lockout after 5 failed attempts within 60s) to reduce brute-force exposure, even though the deployment target is a lab environment.

4. Operator Dashboard Layout
(src/sentry/api/static/dashboard.html)
Header Bar: Displays loud mode badge (DRY-RUN / ENFORCE), kill-switch toggle, controller status, warmup counter, and session status.

Stat Tiles: High-level metrics for Total PPS, Active Threats, Active Mitigations, and Refusal Counts.

Topology Graph (SVG): Fixed-layout network map. Node states are indicated using both color and geometric shapes (Circle = Normal, Triangle = Suspect, Square = Mitigated).

Threat Feed (aria-live): Scrollable alert log. Clicking any row opens an Evidence Drawer showing raw 16-feature vectors and matched trigger thresholds.

Baseline & Entropy Canvas Chart: Real-time dual-trace chart rendering metric observations against EWMA ± MAD baseline bands with hatched active-mitigation regions.

Mitigation Registry & Ledger Tail: Draining TTL progress bars with live countdown timers, direct Revoke action buttons, and hash-chain verification status.

## 5. Accessibility Notes
* Status colors (amber/red/emerald/orange/purple) must always be paired with a non-color cue — the Topology Graph already does this via shape (Circle/Triangle/Square); extend the same pairing to Stat Tiles (icon or text label per state) and Threat Feed rows (severity text badge, not color alone).
* Maintain a minimum 4.5:1 contrast ratio between status colors and `--bg-secondary` for any text or icon rendered on a card surface; verify `--status-dryrun` (#f59e0b) and `--status-suspect` (#f97316) in particular, since amber/orange pairs are easy to under-contrast against dark slate.