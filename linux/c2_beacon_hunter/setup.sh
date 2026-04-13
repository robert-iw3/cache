#!/bin/bash
# c2_beacon_hunter Setup & Management Script
# V2.5/2.6
# - Added comprehensive test mode, systemd service, and configurable whitelist pre-filter
# - Native auditd telemetry integration
# V2.7
# - Added dual-routing support for eBPF and Legacy modes
# - Added --ebpf flag to leverage docker-compose/podman-compose and ebpf.Dockerfile
# @RW

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ====================== TEST DEFAULTS ======================
TEST_DEFAULT_IP="127.0.0.1"
TEST_DEFAULT_PORT="1337"
TEST_DEFAULT_DURATION=300
TEST_DEFAULT_PERIOD=60
TEST_DEFAULT_JITTER=0.35

# --- HELPER: Detect Container Runtime ---
get_runtime() {
    if command -v docker >/dev/null; then
        echo "docker"
    elif command -v podman >/dev/null; then
        echo "podman"
    else
        echo ""
    fi
}
RUNTIME=$(get_runtime)

# --- HELPER: Detect Compose Tool ---
get_compose() {
    if command -v docker-compose >/dev/null; then
        echo "docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v podman-compose >/dev/null; then
        echo "podman-compose"
    else
        echo ""
    fi
}
COMPOSE=$(get_compose)

# --- USAGE HELP ---
if [[ -z "$1" || "$1" == "help" ]]; then
    echo "Usage: sudo ./setup.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  install    - Install host dependencies, auditd rules, and systemd service"
    echo "  container  - Build the Docker/Podman image (--ebpf for native kernel probe stack)"
    echo "  test       - Comprehensive C2 simulation and detection test"
    echo "  run        - Start the background service (options: --ebpf, --container)"
    echo "  stop       - Stop the service/container cleanly"
    echo ""
    echo "Examples:"
    echo "  sudo ./setup.sh run --ebpf         # Runs the v2.7 eBPF stack via compose"
    echo "  sudo ./setup.sh run --container    # Runs the v2.6 classic docker container"
    echo "  sudo ./setup.sh run                # Runs the legacy native systemd/auditd service"
    exit 0
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./setup.sh ...)"
    exit 1
fi

# --- 1. INSTALL ---
if [[ "$1" == "install" ]]; then
    echo "=== Installing Host Dependencies ==="
    apt-get update
    apt-get install -y python3 python3-pip python3-venv libpcap-dev docker.io docker-compose auditd

    echo "=== Setting up Python Environment ==="
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    if [ -f "dev/requirements.txt" ]; then
        pip install -r dev/requirements.txt 2>/dev/null || true
    fi

    echo "=== Configuring Legacy Auditd Rules ==="
    if [ -f "c2_beacon.rules" ]; then
        cp c2_beacon.rules /etc/audit/rules.d/
        auditctl -R /etc/audit/rules.d/c2_beacon.rules || true
        echo "[+] Auditd rules loaded."
    else
        echo "[-] c2_beacon.rules not found, skipping."
    fi

    echo "=== Configuring Systemd Service ==="
    if [ -f "c2_beacon_hunter.service" ]; then
        cp c2_beacon_hunter.service /tmp/c2_beacon_hunter.service.tmp
        sed -i "s|/path/to/c2_beacon_hunter|$PROJECT_DIR|g" /tmp/c2_beacon_hunter.service.tmp
        mv /tmp/c2_beacon_hunter.service.tmp /etc/systemd/system/c2_beacon_hunter.service
        systemctl daemon-reload
        echo "[+] Systemd service configured (Path: $PROJECT_DIR)."
    else
        echo "[-] c2_beacon_hunter.service not found, skipping."
    fi

    echo "[+] Install Complete."
    exit 0
fi

# --- 2. BUILD CONTAINER ---
if [[ "$1" == "container" ]]; then
    if [[ "$2" == "--ebpf" ]]; then
        echo "=== Building c2_beacon_hunter v2.7 (eBPF Mode) ==="
        if [ -z "$COMPOSE" ]; then
            echo "Error: docker-compose or podman-compose not found!"
            exit 1
        fi
        $COMPOSE build --no-cache
        echo "[+] eBPF Compose Build Complete."
    else
        echo "=== Building c2_beacon_hunter Container (Legacy Mode) ==="
        if [ -z "$RUNTIME" ]; then
            echo "Error: docker or podman not found!"
            exit 1
        fi
        $RUNTIME build -t c2-beacon-hunter:v2.6 -f Dockerfile .
        echo "[+] Legacy Container Build Complete."
    fi
    exit 0
fi

# --- 3. TEST MODE ---
if [[ "$1" == "test" ]]; then
    echo "=== Starting Comprehensive C2 Simulation Test ==="
    source venv/bin/activate || true

    if [ -n "$RUNTIME" ] && $RUNTIME ps | grep -q c2-beacon-hunter; then
        echo "[i] Testing against running container..."
    elif systemctl is-active --quiet c2_beacon_hunter; then
        echo "[i] Testing against running systemd service..."
    else
        echo "[i] Starting standalone background hunter for test..."
        TEST_MODE=true python3 c2_beacon_hunter.py --output-dir output &
        HUNTER_PID=$!
        sleep 3
    fi

    echo "=== Running Beacon Simulator ==="
    python3 tests/test_beacon_simulator.py \
        --ip $TEST_DEFAULT_IP --port $TEST_DEFAULT_PORT \
        --duration $TEST_DEFAULT_DURATION --period $TEST_DEFAULT_PERIOD \
        --jitter $TEST_DEFAULT_JITTER

    if [ -n "$HUNTER_PID" ]; then
        echo "Stopping standalone hunter..."
        kill $HUNTER_PID || true
    fi

    echo "=== Test Complete. Check output/anomalies.csv ==="
    exit 0
fi

# --- 4. RUN ---
if [[ "$1" == "run" ]]; then
    mkdir -p output

    if [[ "$2" == "--ebpf" ]]; then
        echo "=== Starting c2_beacon_hunter v2.7 Stack (eBPF Mode) ==="
        if [ -z "$COMPOSE" ]; then
            echo "Error: docker-compose or podman-compose not found!"
            exit 1
        fi
        $COMPOSE up -d
        echo "[+] eBPF Stack started."
    elif [[ "$2" == "--container" ]]; then
        echo "=== Starting c2_beacon_hunter Container (Legacy Mode) ==="
        if [ -z "$RUNTIME" ]; then
            echo "Error: docker or podman not found!"
            exit 1
        fi
        $RUNTIME run -d --name c2-beacon-hunter --restart unless-stopped \
            --network host --pid host --privileged \
            --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
            -v /etc/timezone:/etc/timezone:ro \
            -v /etc/localtime:/etc/localtime:ro \
            -v $(pwd)/config.ini:/app/config.ini \
            -v $(pwd)/c2_beacon_hunter.py:/app/c2_beacon_hunter.py \
            -v $(pwd)/BeaconML.py:/app/BeaconML.py \
            -v $(pwd)/output:/app/output \
            c2-beacon-hunter:v2.6
        echo "[+] Legacy Container started."
    else
        echo "=== Starting Native Systemd Service (Legacy Mode) ==="
        systemctl start c2_beacon_hunter
        systemctl enable c2_beacon_hunter
        echo "[+] Native Systemd Service started."
    fi
    exit 0
fi

# --- 5. STOP ---
if [[ "$1" == "stop" ]]; then
    echo "=== Stopping c2_beacon_hunter ==="

    # Try compose down first if it exists (for eBPF mode)
    if [ -n "$COMPOSE" ] && [ -f "docker-compose.yaml" ]; then
        $COMPOSE down 2>/dev/null || true
    fi

    # Cleanup standard containers (Legacy mode / fallback)
    if [ -n "$RUNTIME" ]; then
        $RUNTIME stop c2-beacon-hunter 2>/dev/null || true
        $RUNTIME rm -f c2-beacon-hunter 2>/dev/null || true
        $RUNTIME stop c2-beacon-hunter-test 2>/dev/null || true
        $RUNTIME rm -f c2-beacon-hunter-test 2>/dev/null || true
    fi

    # Cleanup Systemd if used natively
    if systemctl is-active --quiet c2_beacon_hunter; then
        systemctl stop c2_beacon_hunter || true
    fi

    echo "[+] Stopped."
    exit 0
fi

echo "Invalid command. Use ./setup.sh help"
exit 1