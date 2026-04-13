#!/bin/bash
# ==============================================================================
# Script Name: health_check.sh
# Version: 2.8
# Description: Complete end-to-end verification of the eBPF capture pipeline:
#              Kernel → ringbuf → c2_loader → libbpf_collector → baseline.db
# ==============================================================================

echo "====================================================================="
echo " C2 Beacon Hunter v2.8 - PIPELINE HEALTH CHECK (Container Mode)"
echo "====================================================================="

INTERFACE=${TARGET_INTERFACE:-wlo1}

# Phase 0: Main Stack
echo ""
echo "[*] Main Stack Running?"
pgrep -f "run_full_stack.py" >/dev/null && echo " [OK] run_full_stack.py + learner + collector active" || echo " [WARN] Main process not found"

# Phase 1: eBPF Map + XDP
echo ""
echo "[*] eBPF Map & XDP"
[ -f /sys/fs/bpf/c2_blocklist ] && echo " [OK] Blocklist map pinned" || echo " [WARN] Blocklist map missing"
ip link show dev "$INTERFACE" 2>/dev/null | grep -q "xdp" && echo " [OK] XDP attached to $INTERFACE" || echo " [WARN] No XDP on $INTERFACE"

# Phase 2: Database Pipeline Health
echo ""
echo "[*] baseline.db Pipeline (Last Event)"
python3 -c '
import sqlite3, time
try:
    conn = sqlite3.connect("/app/data/baseline.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*), MAX(timestamp) FROM flows")
    count, max_ts = c.fetchone() or (0, 0)
    lag = time.time() - max_ts if max_ts else 9999
    print(f"   Total flows: {count}")
    if lag < 180:
        print(f"   [OK] Pipeline LIVE — last event {lag:.0f}s ago")
    else:
        print(f"   [WARN] Last event {lag:.0f}s ago")
except Exception as e:
    print(f"   [FAIL] DB error: {e}")
' 2>/dev/null

# Phase 3: Live End-to-End Test (exec + network)
echo ""
echo "[*] Live Capture Test"
BEFORE=$(sqlite3 /app/data/baseline.db "SELECT COUNT(*) FROM flows;" 2>/dev/null || echo 0)
echo "    Triggering exec + network event..."
ls >/dev/null 2>&1
curl -I -s -m 4 https://1.1.1.1 >/dev/null 2>&1 || true
sleep 3
AFTER=$(sqlite3 /app/data/baseline.db "SELECT COUNT(*) FROM flows;" 2>/dev/null || echo 0)
DELTA=$((AFTER - BEFORE))

if [[ $DELTA -gt 0 ]]; then
    echo " [OK] SUCCESS — $DELTA new flow(s) captured!"
    echo "      Full pipeline is WORKING"
else
    echo " [WARN] No new events from test (but ${BEFORE} total flows exist)"
fi

# Phase 4: Defense Readiness
echo ""
echo "[*] Defense Readiness"
[[ -f /app/output/anomalies.jsonl ]] && echo " [OK] anomalies.jsonl ready ($(wc -l < /app/output/anomalies.jsonl) lines)" || echo " [INFO] No anomalies yet"

curl -s -k -m 2 https://127.0.0.1:8443/api/v1/metrics 2>/dev/null | grep -q "total_flows" && echo " [OK] API responding" || echo " [WARN] API not responding"

echo ""
echo "====================================================================="
echo " HEALTH CHECK COMPLETE"
echo "====================================================================="