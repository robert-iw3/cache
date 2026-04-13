#!/bin/bash
# c2_defend/run.sh
cd "$(dirname "$0")"

echo "=== c2_defend (Integrated DFIR Edition) ==="

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo "[!] This tool must be run as root. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Check parent venv
if [ ! -d "../venv" ]; then
    echo "Error: Parent virtual environment not found."
    exit 1
fi

source ../venv/bin/activate

echo ""
echo "Available modes:"
echo "   1) Analyzer     - View latest detections (safe, read-only)"
echo "   2) Defender     - Manual protection (kill + firewall block)"
echo "   3) Undo         - Reverse previous firewall blocks"
echo "   4) DFIR + Defend - Run Live Triage & CTI, then Contain (Recommended)"
echo ""

read -p "Select mode [4]: " choice
choice=${choice:-4}

case "$choice" in
    1)
        python3 analyzer.py
        ;;
    2)
        python3 defender.py
        ;;
    3)
        python3 undo.py
        ;;
    4)
        echo "[*] Step 1: Running Live Host Triage..."
        if [ -f "../DFIR/live_triage.sh" ]; then
            bash ../DFIR/live_triage.sh
        else
            echo "[-] live_triage.sh not found. Skipping."
        fi

        echo "[*] Step 2: Running Threat Intel Enrichment..."
        if [ -f "../DFIR/threat_intel_check.sh" ]; then
            bash ../DFIR/threat_intel_check.sh
        else
            echo "[-] threat_intel_check.sh not found. Skipping."
        fi

        echo "[*] Step 3: Launching Active Defender..."
        python3 defender.py
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac