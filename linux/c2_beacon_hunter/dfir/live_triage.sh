#!/bin/bash

# ======================================================================================
# Script Name: live_triage.sh
# Description: Automates live forensics on a Linux host suspected of C2 compromise.
#              It reads the anomalies JSONL log, identifies high-risk Process IDs
#              (score >= 80), and extracts volatile data before the process terminates.
# Operations Performed:
#   1. Validates root privileges (required for cross-process memory/file inspection).
#   2. Extracts the true command line and underlying binary path (/proc/$PID/exe).
#   3. Generates a SHA256 hash of the binary for static analysis.
#   4. Dumps active network sockets and open file descriptors (using ss and lsof).
#   5. Extracts process environment variables (which may contain C2 configurations).
#   6. Runs a 15-second behavioral trace using strace to capture system calls.
# Output:      Generates a timestamped directory containing individual artifact
#              text files for each analyzed PID.
# ======================================================================================

CONFIG_FILE="config.ini"

# Ensure script is run as root for full forensic visibility
if [ "$EUID" -ne 0 ]; then
  echo "[!] Error: Please run this script as root (sudo)."
  exit 1
fi

# Load paths from config.ini safely
LOG_FILE=$(grep "^LOG_FILE=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d '\r' 2>/dev/null)
OUTPUT_DIR=$(grep "^OUTPUT_DIR=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d '\r' 2>/dev/null)

# Fallbacks if config parsing fails
LOG_FILE=${LOG_FILE:-"../output/anomalies.jsonl"}
OUTPUT_DIR=${OUTPUT_DIR:-"../output/"}

TRIAGE_OUT_DIR="${OUTPUT_DIR}triage_artifacts_$(date +%s)"

echo "[*] Starting Full Live Host Triage..."

# Check dependencies
for cmd in jq lsof strace sha256sum ss; do
    if ! command -v $cmd &> /dev/null; then
        echo "[-] Warning: '$cmd' is not installed. Some forensic data will be missing."
    fi
done

if [ ! -f "$LOG_FILE" ]; then
    echo "[!] Error: Cannot find log file at $LOG_FILE."
    exit 1
fi

mkdir -p "$TRIAGE_OUT_DIR"
echo "[*] Saving artifacts to $TRIAGE_OUT_DIR"

# Extract unique PIDs flagged with high risk (score >= 80)
TARGET_PIDS=$(jq -r 'select(.score >= 80) | .pid' "$LOG_FILE" | sort -u)

if [ -z "$TARGET_PIDS" ]; then
    echo "[+] No high-priority PIDs found in logs. Exiting."
    exit 0
fi

for PID in $TARGET_PIDS; do
    echo "============================================================"
    echo "Triaging PID: $PID"
    echo "============================================================"

    if ! kill -0 "$PID" 2>/dev/null; then
        echo "[-] PID $PID is no longer running. Moving to next."
        continue
    fi

    # 1. Command Line & Executable Path
    echo "    -> Extracting command line & executable path..."
    tr '\0' ' ' < "/proc/$PID/cmdline" > "$TRIAGE_OUT_DIR/${PID}_cmdline.txt" 2>/dev/null
    ls -la "/proc/$PID/exe" > "$TRIAGE_OUT_DIR/${PID}_exe_path.txt" 2>/dev/null

    # 2. Binary Hash
    echo "    -> Hashing binary..."
    sha256sum "/proc/$PID/exe" > "$TRIAGE_OUT_DIR/${PID}_sha256.txt" 2>/dev/null

    # 3. Network Sockets & Open Files
    echo "    -> Dumping network connections and open files..."
    ss -panetu | grep "$PID" > "$TRIAGE_OUT_DIR/${PID}_network_ss.txt" 2>/dev/null
    lsof -p "$PID" -n -P > "$TRIAGE_OUT_DIR/${PID}_lsof.txt" 2>/dev/null

    # 4. Environment Variables
    echo "    -> Extracting environment variables..."
    tr '\0' '\n' < "/proc/$PID/environ" > "$TRIAGE_OUT_DIR/${PID}_environ.txt" 2>/dev/null

    # 5. Behavioral Tracing (15 seconds)
    if command -v strace &> /dev/null; then
        echo "    -> Tracing system calls for 15 seconds (strace)..."
        timeout 15 strace -f -e trace=network,open,openat,execve,clone,write -p "$PID" -o "$TRIAGE_OUT_DIR/${PID}_behavior_trace.txt" 2>/dev/null
    fi
done

echo "============================================================"
echo "[*] Triage complete. Artifacts securely stored in $TRIAGE_OUT_DIR"
echo "============================================================"