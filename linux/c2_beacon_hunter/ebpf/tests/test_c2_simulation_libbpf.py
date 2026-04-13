#!/usr/bin/env python3
"""
test_c2_simulation_libbpf.py - C2 Beacon & Normal Traffic Simulator
Generates network events to test eBPF CO-RE probes and ML baselines.

Verify DB:

sqlite3 baseline.db "SELECT process_name, dst_ip, interval, packet_size_mean, mitre_tactic FROM flows ORDER BY id DESC LIMIT 10;"
"""

import socket
import time
import random
import threading
from datetime import datetime

# Configuration
TARGET_IP = "8.8.8.8"  # Safe external IP to test routing/connections
TARGET_PORT = 53
DURATION = 300  # Run simulation for 5 minutes

def simulate_normal_traffic():
    """Simulates irregular, bursty web traffic (High variance)"""
    print(f"[{datetime.now()}] Starting Normal Traffic Thread...")
    end_time = time.time() + DURATION

    while time.time() < end_time:
        try:
            # Random wait between 2 and 15 seconds
            time.sleep(random.uniform(2.0, 15.0))

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((TARGET_IP, TARGET_PORT))

                # Send variable amount of data (simulating HTTP GET)
                payload_size = random.randint(500, 5000)
                s.sendall(b"A" * payload_size)

                print(f"[Normal] Sent {payload_size} bytes to {TARGET_IP}:{TARGET_PORT}")
        except Exception as e:
            # Ignore timeouts or connection drops
            pass

def simulate_c2_beacon():
    """Simulates strict C2 beaconing (Low variance, consistent intervals)"""
    print(f"[{datetime.now()}] Starting C2 Beacon Thread...")
    end_time = time.time() + DURATION

    beacon_interval = 5.0  # Strict 5-second beacon
    jitter = 0.5           # Up to 0.5s jitter

    while time.time() < end_time:
        try:
            # Calculate next sleep with slight jitter
            sleep_time = beacon_interval + random.uniform(-jitter, jitter)
            time.sleep(sleep_time)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((TARGET_IP, TARGET_PORT))

                # Send small, consistent payload (simulating heartbeat)
                payload_size = random.randint(32, 48)
                s.sendall(b"C2_HEARTBEAT_DATA" + b"X" * (payload_size - 17))

                print(f"[C2 Beacon] Sent {payload_size} bytes to {TARGET_IP}:{TARGET_PORT} (Interval: {sleep_time:.2f}s)")
        except Exception as e:
            pass

if __name__ == "__main__":
    print(f"[{datetime.now()}] Starting Network Simulation (Duration: {DURATION}s)")

    # Start both threads to generate mixed telemetry
    normal_thread = threading.Thread(target=simulate_normal_traffic)
    c2_thread = threading.Thread(target=simulate_c2_beacon)

    normal_thread.start()
    c2_thread.start()

    normal_thread.join()
    c2_thread.join()

    print(f"[{datetime.now()}] Simulation complete. Check your baseline.db to verify capture.")