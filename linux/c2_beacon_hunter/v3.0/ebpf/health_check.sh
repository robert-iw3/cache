#!/usr/bin/env bash
# ==============================================================================
# Script Name: health_check.sh
# Version: 1.0
# Description: Rigorous validation script for C2 Beacon Hunter v3.0.
#              Validates interoperability across modes (host, promisc, cloud),
#              processes, eBPF/XDP, database connectivity and data flow,
#              detections, API dashboard, and performs a live traffic test.
#              Designed as a final validation test before deployment or merge.
# Usage: sudo ./health_check.sh [--config /path/to/config.ini]
# ==============================================================================

set -e  # Exit on error

# Constants
DEFAULT_CONFIG="config.ini"
DB_PATH="data/baseline.db"  # SQLite default
ANOMALIES_JSONL="output/anomalies.jsonl"
API_URL="https://127.0.0.1:8443/api/v1/metrics"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

CONFIG_FILE=${CONFIG_FILE:-$DEFAULT_CONFIG}

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

echo "====================================================================="
echo " C2 Beacon Hunter v3.0 - COMPREHENSIVE HEALTH CHECK & VALIDATION TEST"
echo "====================================================================="
echo "[INFO] Using config: $CONFIG_FILE"

# Helper functions
get_config_value() {
    local section=$1
    local key=$2
    local default=$3
    grep -E "^${key}\s*=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "$default"
}

check_process() {
    local proc_name=$1
    pgrep -f "$proc_name" > /dev/null && echo " [OK] Running: $proc_name" || echo " [FAIL] Not running: $proc_name"
}

# Step 1: Mode Detection
MODE=$(get_config_value "general" "mode" "host")
echo ""
echo "[*] Step 1: Mode Detection"
echo " [OK] Mode detected: ${MODE^^}"

# Step 2: Processes & Loader Validation
echo ""
echo "[*] Step 2: Processes & Loader Validation"
check_process "c2_beacon_hunter.py"

case $MODE in
    promisc)
        check_process "c2_promisc_loader"
        ;;
    host)
        check_process "c2_loader"
        ;;
    cloud)
        echo " [INFO] Cloud mode — no loader process (file ingestion)"
        ;;
    *)
        echo " [WARN] Unknown mode: $MODE — assuming host"
        check_process "c2_loader"
        ;;
esac

# Step 3: eBPF / XDP Objects Validation
echo ""
echo "[*] Step 3: eBPF / XDP Objects Validation"
INTERFACE=$(get_config_value "ebpf" "interface" "wlo1")
if [ "$MODE" = "promisc" ]; then
    ip link show dev "$INTERFACE" | grep -q "xdp" && echo " [OK] XDP promisc parser attached" || echo " [FAIL] No XDP program attached to $INTERFACE"
else
    echo " [INFO] $MODE mode — no XDP validation needed"
fi

# Step 4: Database Connectivity & Data Flow Validation
echo ""
echo "[*] Step 4: Database Connectivity & Data Flow Validation"
DB_TYPE=$(get_config_value "database" "type" "sqlite")

if [ "$DB_TYPE" = "postgres" ]; then
    PGPASSWORD=$(get_config_value "postgres" "password" "password")
    PGUSER=$(get_config_value "postgres" "user" "user")
    PGDB=$(get_config_value "postgres" "dbname" "c2_beacon_hunter")
    PGHOST=$(get_config_value "postgres" "host" "localhost")
    PGPORT=$(get_config_value "postgres" "port" "5432")

    # Test connection
    psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -c "\q" 2>/dev/null && echo " [OK] Postgres connection successful" || echo " [FAIL] Postgres connection failed"

    # Data flow check
    COUNT=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -t -c "SELECT COUNT(*) FROM flows;")
    LAST=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -t -c "SELECT MAX(timestamp) FROM flows;")
    if [ "$LAST" != "0" ]; then
        LAG=$(( $(date +%s) - $LAST ))
        echo " [OK] Flows: $COUNT | Last event: ${LAG}s ago"
    else
        echo " [WARN] Database exists but no flows yet"
    fi
else
    if [ -f "data/baseline.db" ]; then
        COUNT=$(sqlite3 data/baseline.db "SELECT COUNT(*) FROM flows;")
        LAST=$(sqlite3 data/baseline.db "SELECT MAX(timestamp) FROM flows;")
        if [ "$LAST" != "0" ]; then
            LAG=$(( $(date +%s) - $LAST ))
            echo " [OK] Flows: $COUNT | Last event: ${LAG}s ago"
        else
            echo " [WARN] Database exists but no flows yet"
        fi
    else
        echo " [FAIL] baseline.db not found"
    fi
fi

# Step 5: Detections Validation
echo ""
echo "[*] Step 5: Detections Validation"
if [ -f "$ANOMALY_JSONL" ]; then
    DETECT=$(wc -l < "$ANOMALY_JSONL")
    echo " [OK] Total detections: $DETECT"
else
    echo " [WARN] No anomalies.jsonl found"
fi

# Step 6: API Dashboard Validation
echo ""
echo "[*] Step 6: API Dashboard Validation"
curl -s -k -m 3 "$API_URL" > /dev/null && echo " [OK] API responding" || echo " [FAIL] API not responding (check port 8443)"

# Step 7: Live Traffic Test (Data Flow Validation)
echo ""
echo "[*] Step 7: Live Traffic Test (Data Flow Validation)"
echo "Generating test traffic (ls + curl) to validate flow capture..."

if [ "$DB_TYPE" = "postgres" ]; then
    BEFORE=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -t -c "SELECT COUNT(*) FROM flows;")
else
    BEFORE=$(sqlite3 data/baseline.db "SELECT COUNT(*) FROM flows;")
fi

ls > /dev/null 2>&1
curl -I -s -m 3 https://1.1.1.1 > /dev/null 2>&1 || true
sleep 5

if [ "$DB_TYPE" = "postgres" ]; then
    AFTER=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -t -c "SELECT COUNT(*) FROM flows;")
else
    AFTER=$(sqlite3 data/baseline.db "SELECT COUNT(*) FROM flows;")
fi

DELTA=$((AFTER - BEFORE))
if [[ $DELTA -gt 0 ]]; then
    echo " [OK] SUCCESS — $DELTA new flow(s) captured!"
else
    echo " [FAIL] No new flows from test — check eBPF collector"
fi

echo ""
echo "====================================================================="
echo " HEALTH CHECK COMPLETE — v3.0"
echo "====================================================================="