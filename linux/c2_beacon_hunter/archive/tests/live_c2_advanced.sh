#!/bin/bash

# Configuration
TEST_PORT="1337"
DURATION_SECONDS=300
# Find the real LAN IP (excludes 127.0.0.1)
TARGET_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+') || TARGET_IP="127.0.0.1"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}    ADVANCED C2 SIMULATION (High Visibility)${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "${YELLOW}[*] Target IP: ${TARGET_IP}:${TEST_PORT}${NC}"

# --- PRE-FLIGHT: Check & Relax Ptrace (Ubuntu Hardening) ---
ORIG_PTRACE=""
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    ORIG_PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [ "$ORIG_PTRACE" != "0" ]; then
        echo -e "${YELLOW}[*] Ubuntu YAMA Ptrace restriction detected ($ORIG_PTRACE).${NC}"
        echo -e "    Temporarily lowering to 0 to allow container visibility..."
        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope >/dev/null
    fi
fi

# --- CLEANUP TRAP ---
cleanup() {
    echo -e "\n${RED}[*] Teardown: Stopping test components...${NC}"

    # 1. Kill C2 Server
    if [ -n "$SERVER_PID" ]; then kill $SERVER_PID 2>/dev/null; fi

    # 2. Close Firewall Port
    if [ "$FIREWALL_OPENED" == "true" ]; then
        echo -n "    Closing Port $TEST_PORT in Firewalld... "
        sudo firewall-cmd --remove-port=${TEST_PORT}/tcp >/dev/null 2>&1
        echo "Done."
    fi

    # 3. Restore Ptrace Scope
    if [ -n "$ORIG_PTRACE" ] && [ "$ORIG_PTRACE" != "0" ]; then
        echo -n "    Restoring Ptrace scope to $ORIG_PTRACE... "
        echo "$ORIG_PTRACE" | sudo tee /proc/sys/kernel/yama/ptrace_scope >/dev/null
        echo "Done."
    fi

    exit
}
trap cleanup SIGINT SIGTERM EXIT

# --- FIREWALL CHECK ---
FIREWALL_OPENED="false"
if command -v firewall-cmd >/dev/null; then
    if sudo firewall-cmd --state 2>/dev/null | grep -q "running"; then
        echo -e "${YELLOW}[*] Firewalld detected. Punching temporary hole...${NC}"
        if sudo firewall-cmd --add-port=${TEST_PORT}/tcp --timeout=${DURATION_SECONDS} >/dev/null; then
            FIREWALL_OPENED="true"
            echo -e "${GREEN}[+] Port $TEST_PORT opened successfully.${NC}"
        else
            echo -e "${RED}[!] Failed to open firewall port. Test may fail.${NC}"
        fi
    fi
fi

# --- START C2 LISTENER ---
echo -e "${GREEN}[+] Starting C2 Server (Background)...${NC}"
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('0.0.0.0', $TEST_PORT))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        time.sleep(2)
        conn.close()
except: pass
" &
SERVER_PID=$!
sleep 2

# --- START TRAFFIC GENERATION ---
echo -e "${GREEN}[+] Starting Periodic Beaconing Loop...${NC}"
echo -e "${YELLOW}    (Hold: 8s | Sleep: 2s | Jitter: Low)${NC}"
START_TIME=$(date +%s)
COUNTER=0

while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
    if [ $ELAPSED -ge $DURATION_SECONDS ]; then break; fi

    # Client Connection - INCREASED HOLD TIME & ADDED JUNK DATA FOR ENTROPY
    python3 -c "
import socket, time, random, string
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('$TARGET_IP', $TEST_PORT))
    # Payload simulates suspicious command line entropy
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
    time.sleep(8) # INCREASED TO 8s TO GUARANTEE SNAPSHOT HIT
    s.close()
except: pass
"
    COUNTER=$((COUNTER + 1))
    echo -ne "\r${CYAN}[*] Beacon #$COUNTER sent | Active: ${ELAPSED}s${NC}"

    # LOW JITTER (Makes it easier for ML to detect periodicity)
    sleep 2
done

echo -e "\n${GREEN}[+] Test Complete.${NC}"