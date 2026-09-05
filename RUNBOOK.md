# Sentry SDN Security — Operations Runbook

## Quick Reference

| Component | Container/Process | Port | Health Check |
|-----------|-------------------|------|--------------|
| ONOS | `sentry-onos` | 8181 (REST), 6653 (OF) | `curl http://localhost:8181/onos/v1/devices` |
| Sentry | `sentry-sentry` | — | `docker logs sentry-sentry` |
| Mininet | `topo_lab.py` (host) | — | `pingall` in Mininet CLI |

---

## 1. Deployment

### Start the Lab

```bash
# Terminal 1: Start ONOS
cd deploy/
docker compose up -d
# Wait for healthcheck to pass (~30s)

# Terminal 2: Start Mininet topology (requires root)
sudo python3 topo_lab.py --test

# Terminal 3: Start Sentry detection loop
python3 -m sentry run
```

### Verify ONOS

```bash
# REST API check
curl -s -u onos:onos http://localhost:8181/onos/v1/devices | python3 -m json.tool

# Should show 3 switches (of:0000000000000001, of:0000000000000002, of:0000000000000003)
```

### Verify Mininet Connectivity

```bash
# In Mininet CLI:
mininet> pingall
# All hosts should be able to ping each other after ONOS installs forwarding rules
```

---

## 2. Attack Testing

### Run Attack Scripts

```bash
# From a Mininet host:
mininet> h1 python3 /path/to/deploy/attacks.py syn_flood 10.0.2.1 30
mininet> h1 python3 /path/to/deploy/attacks.py port_scan 10.0.2.1 60
mininet> h1 python3 /path/to/deploy/attacks.py udp_flood 10.0.2.1 30
mininet> h1 python3 /path/to/deploy/attacks.py icmp_flood 10.0.2.1 30
mininet> h1 python3 /path/to/deploy/attacks.py flow_exhaustion 10.0.2.1 30
mininet> h1 python3 /path/to/deploy/attacks.py arp_spoof 10.0.2.1 30
mininet> h1 python3 /path/to/deploy/attacks.py cp_saturation 30
mininet> h1 python3 /path/to/deploy/attacks.py topo_poison 30
```

### Expected Detection Behavior

| Attack | Rule | Min Severity | Auto-Mitigated? |
|--------|------|-------------|-----------------|
| SYN Flood | `syn_flood` | high | ✅ Stage 2 (Drop) |
| UDP Flood | `udp_flood` | high | ✅ Stage 2 (Drop) |
| ICMP Flood | `icmp_flood` | medium | ✅ Stage 1 (Throttle) |
| Port Scan | `port_scan` | medium | ✅ Stage 1 (Throttle) |
| Flow Exhaustion | `flow_table_exhaustion` | high | ✅ Stage 2 (Drop) |
| ARP Spoof | `arp_spoofing` | critical | ✅ Stage 3 (Quarantine) |
| CP Saturation | `cp_saturation` | critical | ✅ Stage 3 (Quarantine) |
| Topo Poison | `topology_poisoning` | high | ❌ Alert-only (FR-1) |

---

## 3. Manual Rollback — Revoking a Mitigation

**When to use:** A misfired Stage 3/4 rule is blocking legitimate traffic, or you need to manually release a quarantined/isolated host.

### Step-by-Step Procedure

#### Option A: Via API (Recommended)

```bash
# 1. List active mitigations
curl -s -u onos:onos http://localhost:8181/onos/v1/sentry/actions \
  | python3 -m json.tool

# 2. Identify the action_id of the rule to revoke
#    Look for status="applied" and the subject_id (host IP)

# 3. Issue revoke command
curl -X POST -u onos:onos \
  http://localhost:8181/onos/v1/sentry/actions/<action_id>/revoke

# 4. Verify revocation within one polling interval (5s)
curl -s -u onos:onos http://localhost:8181/onos/v1/sentry/actions/<action_id> \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status'])"
# Should print: "revoked"
```

#### Option B: Via ONOS CLI (Karaf)

```bash
# Access ONOS shell
docker exec -it sentry-onos /root/onos/bin/onos

# List active flow rules for a device
onos> flows -s of:0000000000000001

# Remove a specific flow
onos> flow-remove -f of:0000000000000001 <flow-id>

# Verify removal
onos> flows -s of:0000000000000001
```

#### Option C: Via Mininet (Emergency)

```bash
# If Sentry is down, remove OVS flows directly
mininet> s1 ovs-ofctl del-flows s1 "ip,nw_src=10.0.1.50"

# Verify flow table is clear
mininet> s1 ovs-ofctl dump-flows s1
```

### Verification After Revocation

After revoking a Stage 3/4 rule, verify prior flow state is restored:

```bash
# 1. Check ONOS flow table — Sentry rule should be gone
curl -s -u onos:onos http://localhost:8181/onos/v1/flows/of:0000000000000001 \
  | python3 -c "
import sys, json
flows = json.load(sys.stdin).get('flows', [])
for f in flows:
    if f.get('appId') == 'org.sentry':
        print(f'STILL PRESENT: {f[\"id\"]}')
        sys.exit(1)
print('Sentry rules removed successfully')
"

# 2. Test connectivity from the previously blocked host
mininet> h1 ping 10.0.2.1
# Should succeed within one polling interval
```

---

## 4. TTL Auto-Expiry (Fail-Open Safety)

All OpenFlow rules carry `isPermanent=false` with hard timeouts. If Sentry crashes or is killed mid-attack:

- **Throttle (Stage 1):** Rules expire after 30 seconds
- **Selective Drop (Stage 2):** Rules expire after 60 seconds
- **Quarantine (Stage 3):** Rules expire after 120 seconds
- **Port Isolation (Stage 4):** Rules expire after 300 seconds (5 min)

After expiry, traffic flow is automatically restored — no manual intervention needed.

### Testing TTL Expiry

```bash
# 1. Start an attack to trigger mitigation
mininet> h1 python3 /path/to/attacks.py syn_flood 10.0.2.1 60

# 2. Kill Sentry mid-attack (simulate crash)
pkill -f "sentry"

# 3. Wait for TTL expiry (60s for Stage 2)
sleep 70

# 4. Verify flow table is clear (ONOS removed rules via hard timeout)
curl -s -u onos:onos http://localhost:8181/onos/v1/flows/of:0000000000000001 \
  | python3 -m json.tool
```

---

## 5. Startup Reconciliation

When Sentry restarts after a crash, the **Reconciler** automatically:

1. Reads the audit ledger for all "applied" actions
2. Verifies each against ONOS (read-back check)
3. Revokes stale rules that should have expired
4. Re-freezes baselines for active mitigations (Invariant I9)

```bash
# Reconciler runs automatically on startup. Check logs:
docker logs sentry-sentry 2>&1 | grep "Reconciling"
# Should see: "Reconciling N active mitigations from ledger"
```

---

## 6. Audit Ledger Verification

The tamper-evident audit ledger (SHA-256 hash chain) can be verified:

```bash
# Verify ledger integrity
python3 -m sentry verify-ledger

# Should print: "Ledger verification: PASSED (N entries)"
# If tampered: "Ledger verification: FAILED — hash chain broken at entry N"
```

---

## 7. Troubleshooting

### ONOS Not Receiving Flows

```bash
# Check ONOS apps are active
docker exec sentry-onos /root/onos/bin/onos apps -a -s
# Should show: org.onosproject.openflow

# Verify OpenFlow connection
docker exec sentry-onos /root/onos/bin/onos devices
# Switches should show "available=true"
```

### Mininet Hosts Can't Ping

```bash
# Check STP has converged (wait ~30s after topology start)
mininet> sh ovs-vsctl show

# Verify ONOS installed forwarding rules
mininet> s1 ovs-ofctl dump-flows s1 -O OpenFlow13
```

### Sentry Not Detecting Attacks

```bash
# Check warmup period (first 5 windows = 25s of normal traffic needed)
docker logs sentry-sentry 2>&1 | grep "warmup"

# Verify telemetry is flowing
docker logs sentry-sentry 2>&1 | grep "Normalized snapshot"
# Should see periodic snapshots with device stats
```

### False Positives

If legitimate traffic triggers detection:

1. Check the anomaly threshold (default: `mad_threshold=3.0`)
2. Verify the warmup period completed before traffic spike
3. Review the correlator's hysteresis (2 positive / 5 clean windows)
4. Adjust `min_confidence` in SafetyRails if needed

### ML Advisory Scorer Reports Unavailable

The Phase 8 advisory scorer (`sentry score`, `sentry serve`) loads `models/advisory_weights.json`:

```bash
# Verify the weights artifact exists
ls -l models/advisory_weights.json

# Missing? Regenerate it — pure-Python training, no external deps
python -m sentry train --samples 60 --epochs 600

# The scorer degrades gracefully when unavailable:
#   - `sentry score --features ...` prints "Advisory scorer unavailable" (exit 1)
#   - the API threat feed simply omits the "advisory" key
```

The advisory score is **informational only** — it annotates the threat feed and CLI output but never gates or triggers mitigation. If advisory predictions diverge from rule verdicts, trust the rule path; the model is trained on synthetic operating points, so its probability is a similarity score, not a calibrated threat probability (see `THREAT_MODEL.md`).

---

## 8. Backup & Recovery

### Audit Ledger Backup

```bash
# Copy ledger to backup location
cp audit/audit_ledger.jsonl /backup/sentry/audit_$(date +%Y%m%d_%H%M%S).jsonl
```

### State Recovery After Full Loss

If both Sentry state and ledger are lost:

1. Sentry starts fresh with no active mitigations
2. ONOS flow rules continue until their hard timeouts expire
3. No manual intervention needed — fail-open safety ensures traffic flows
4. Re-run `python -m sentry selftest` to verify system integrity
