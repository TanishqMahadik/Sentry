# Sentry — Offline Demo Guide

This is the complete, repeatable demo of Sentry — **no ONOS, no Docker, no root needed**. Everything runs from the repo root with the Python standard library + the committed ML weights. The core runtime is dependency-free (NFR-3).

Two demo tracks:

1. **Detection & mitigation** (Phases 3–7) — offline replay of all 8 attacks + dashboard.
2. **ML advisory scorer** (Phase 8) — train the pure-Python model and watch advisory scores rise as an attack unfolds.

---

## 0. Prerequisites

```bash
# From the repo root (repo already has the ML weights committed):
python -m sentry selftest     # fast smoke: all 8 attacks detectable offline
```

Sentry is a normal Python package; use the interpreter that has it importable
(`pip install -e .` into a venv, or rely on `PYTHONPATH=src`).

---

## 1. Self-Test — all 8 attack vectors (Phase 3 exit gate)

```bash
python -m sentry selftest
```

**Expected output (abridged):**

```
=== Sentry Phase 3 Self-Test ===

  [OK] Benign traffic: zero/few alerts
  [OK] syn_flood: detected within latency bound
  [OK] udp_flood: detected within latency bound
  [OK] icmp_flood: detected within latency bound
  [OK] port_scan: detected within latency bound
  [OK] flow_table_exhaustion: detected within latency bound
  [OK] arp_spoofing: detected within latency bound
  [OK] cp_saturation: detected within latency bound
  [OK] topology_poisoning: detected within latency bound

  Scenarios run: 9
  Self-test PASSED — Phase 3 exit gate satisfied.
```

This validates both detection *and* the offline replay harness. Full suite: `python -m pytest -q`.

## 2. Replay a single scenario

```bash
# Pick any attack:
python -m sentry replay --scenario syn_flood
python -m sentry replay --scenario topology_poisoning
```

**Expected output:**

```
=== Sentry Replay Harness ===

  [OK] syn_flood                ticks=15  anomalies=4  detection=tick 3
```

An anomaly count > 0 for an attack means detection fired; `benign` should be near zero.

## 3. Browser walkthrough — dashboard (Phases 6/7)

```bash
# Serve the live dashboard backed by offline replay telemetry:
python -m sentry replay --scenario syn_flood --serve
```

or, for the API server alone:

```bash
python -m sentry serve --mock
```

Open `http://localhost:9090`.

1. You land on **/login.html** — unauthenticated requests are redirected here.
2. Log in with the token printed at server start (`SENTRY_API_TOKEN`).
3. **Dashboard** shows: mode badge (DRY-RUN / ENFORCE), stat tiles, the SVG topology graph (color *and* shape encode node state), a live **threat feed** (each entry has an evidence drawer with raw feature vectors + matched triggers), the EWMA/MAD baseline chart with hatched active-mitigation regions, and the **mitigation registry** with TTL countdowns and one-click Revoke.
4. Watch the threat feed populate as the attack progresses, then the mitigation ladder escalate (Observe → Throttle → Drop).

In `--serve` mode the dashboard is fed by the deterministic replay — a repeatable demo. Stop with `Ctrl+C`.

## 4. ML advisory — train the model (Phase 8)

```bash
# Providers the committed models/advisory_weights.json already; retrain for a live demo:
python -m sentry train --samples 60 --epochs 600
```

**Expected output:**

```
=== Sentry ML Advisory Scorer — Training ===

  Samples per class: 60  (9 classes)
  Validation: accuracy=0.983 precision=0.993 recall=0.987 f1=0.990
  Wrote models/advisory_weights.json
```

The model is a pure-Python logistic regression (`src/sentry/ml/logistic.py`) — no numpy/sklearn. Training synthesizes per-window feature vectors for `benign` + the 8 attacks from the `detect/rules.py` thresholds and `sim/scenarios.py` signal patterns.

## 5. ML advisory — score a live attack unfolding

```bash
# Replay syn_flood and watch the advisory band climb tick-by-tick:
python -m sentry score --scenario syn_flood
```

**Expected output (abridged):**

```
=== Sentry Advisory Scorer — syn_flood ===
  tick 0  --          (baselining)
  tick 1  MEDIUM  benign        score 0.432
  tick 2  HIGH    benign        score 0.611
  tick 3  HIGH    syn_flood     score 0.782
  tick 4  CRITICAL syn_flood    score 0.931
  ...
```

- Early ticks score **LOW/MEDIUM for `benign`** while the baseline is quiet.
- Once the flood hits, the score jumps toward **HIGH/CRITICAL and the predicted class becomes `syn_flood`** — matching (but not driving) the rule verdict.

### Or score a single feature window directly:

```bash
python -m sentry score --features "pps_rx=5000,flow_count=300,arp_entropy=0.1"
```

**Expected output:**

```
  advisory score      : 0.9714
  predicted class     : syn_flood
  band                : CRITICAL
  recommendation      : Consider escalation for syn_flood. Advisory only — ...
    top feature pps_rx            : +2.3512
    top feature flow_count       : +1.8840
    ...
```

`top_features` makes the model *explainable*: the highest-magnitude contributions to the verdict, named by feature.

## 6. ML advisory — verify it stays advisory

The scorer is a **side-channel**. Two quick checks:

```bash
# 1. Without weights, scoring degrades gracefully (exit code 1, no crash):
python -m sentry score --features "pps_rx=5000" --weights /nonexistent.json

# 2. The API threat feed carries an "advisory" key only when weights exist —
#    the rule path and mitigation engine never consult ml/.
```

The `mitigate/` planner and executor have zero references to `ml/`; advisory predictions can flag but never block.

---

## Failure cheatsheet

| Symptom | Fix |
|---|---|
| `Operation not permitted` / import errors | Ensure `sentry` is importable (`pip install -e .` in a venv or `PYTHONPATH=src`). |
| `Advisory scorer unavailable (weights missing: models/advisory_weights.json)` | Run `python -m sentry train` (writes the file) or commit exists already — check the file is present. |
| `score --scenario` shows only `baselining` rows | Short demo: attack fires at tick 3+; give it ≥ 6 ticks. |
| Em-dashes render as `�` in Windows Git Bash | Console encoding artifact — cosmetic only; use Windows Terminal or `chcp 65001`. |