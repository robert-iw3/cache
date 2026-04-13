#!/bin/bash

# Configuration
TEST_PORT="9999"
HOST_IP=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+')

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Firewall-Aware C2 Test ===${NC}"
echo -e "Targeting LAN IP: ${GREEN}$HOST_IP${NC}"

# --- CLEANUP FUNCTION (Safety Net) ---
cleanup() {
    echo -e "\n${CYAN}[*] Teardown started...${NC}"

    # 1. Kill Python Listener
    if [ -n "$LISTENER_PID" ]; then
        echo -n "    Killing Listener (PID $LISTENER_PID)... "
        kill $LISTENER_PID 2>/dev/null
        echo "Done."
    fi

    # 2. Close Firewall Port (The Critical Step)
    echo -n "    Closing Port $TEST_PORT in Firewalld... "
    sudo firewall-cmd --remove-port=${TEST_PORT}/tcp >/dev/null 2>&1
    echo "Done."

    exit
}
trap cleanup SIGINT SIGTERM EXIT

# --- STEP 1: PUNCH HOLE IN FIREWALL ---
echo -e "${GREEN}[+] Temporarily allowing Port $TEST_PORT/tcp...${NC}"
# We use --timeout to ensure it closes automatically if script crashes hard
sudo firewall-cmd --add-port=${TEST_PORT}/tcp --timeout=60 >/dev/null
if [ $? -eq 0 ]; then
    echo "    Success. Port is open for 60 seconds."
else
    echo -e "${RED}[!] Failed to modify firewall. Run with sudo?${NC}"
    exit 1
fi

# --- STEP 2: START LISTENER ---
echo -e "${GREEN}[+] Starting C2 Listener...${NC}"
# FIXED: Replaced input() with infinite sleep loop to prevent EOFError
python3 -c "import socket, time; s=socket.socket(); s.bind(('0.0.0.0', $TEST_PORT)); s.listen(5);
while True: time.sleep(1)" &
LISTENER_PID=$!
# Give it a second to bind
sleep 1

# --- STEP 3: GENERATE TRAFFIC ---
echo -e "${GREEN}[+] Sending Beacons...${NC}"

for i in {1..5}; do
    echo -n "    Beacon $i/5: Connecting to $HOST_IP:$TEST_PORT... "

    # Connect and HOLD for 10s to ensure Docker sees it
    python3 -c "
import socket, time, sys
try:
    s = socket.socket()
    s.settimeout(3)
    s.connect(('$HOST_IP', $TEST_PORT))
    print('CONNECTED! Holding 10s...')
    sys.stdout.flush()
    time.sleep(10)
    s.close()
except Exception as e:
    print(f'FAILED: {e}')
    sys.exit(1)
"
    # If connection failed, don't wait 10s
    if [ $? -ne 0 ]; then
        sleep 1
    fi
done

echo -e "${CYAN}Test Complete. Cleaning up...${NC}"