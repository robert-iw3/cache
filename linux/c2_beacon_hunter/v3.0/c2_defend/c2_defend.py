#!/usr/bin/env python3
"""
c2_defend.py (Central SOAR Engine - v3.0)
Monitors anomalies.jsonl and dispatches containment orders to remote agents via the API.
"""

import json
import time
import argparse
import requests
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_FILE = Path("output/anomalies.jsonl")
DAEMON_LOG = Path("output/c2_defend_daemon.log")
SCORE_THRESHOLD = 120
API_URL = "https://127.0.0.1:8443/api/v1/soar/contain"

def log_action(msg, is_dry_run=True):
    prefix = "[DRY RUN]" if is_dry_run else "[ACTIVE]"
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    entry = f"{ts} | {prefix} {msg}"
    with open(DAEMON_LOG, "a") as f:
        f.write(entry + "\n")
    print(entry)

def tail_log(file_path):
    with open(file_path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def main():
    parser = argparse.ArgumentParser(description="Central C2 Defend SOAR Daemon")
    parser.add_argument("--arm", action="store_true", help="Enable active containment dispatch")
    args = parser.parse_args()

    if not LOG_FILE.exists():
        LOG_FILE.touch()

    mode_str = "ACTIVE CONTAINMENT (Dispatching Orders)" if args.arm else "DRY RUN (Observation Only)"
    print(f"--- Central SOAR Engine: {mode_str} ---")
    log_action(f"Daemon started. Monitoring {LOG_FILE}")

    handled_events = set()
    for line in tail_log(LOG_FILE):
        try:
            data = json.loads(line.strip())
            if data.get("score", 0) >= SCORE_THRESHOLD:
                pid = data.get("pid")
                ip = data.get("dst_ip")
                port = data.get("dst_port", 0)
                agent_id = data.get("agent_id", "local_host") # Uses local_host if running Epic 1 without agents
                event_key = f"{agent_id}_{pid}_{ip}_{port}"

                if event_key not in handled_events:
                    handled_events.add(event_key)

                    if not args.arm:
                        log_action(f"Would dispatch contain order to {agent_id} for PID {pid} / {ip}:{port}", is_dry_run=True)
                        continue

                    # Dispatch to agent via Central API
                    payload = {
                        "agent_id": agent_id,
                        "action": "contain",
                        "pid": pid,
                        "dst_ip": ip,
                        "dst_port": port
                    }

                    try:
                        res = requests.post(API_URL, json=payload, verify=False, timeout=3)
                        if res.status_code == 200:
                            log_action(f"Successfully dispatched containment to {agent_id} | PID: {pid} IP: {ip}", is_dry_run=False)
                        else:
                            log_action(f"Failed to reach {agent_id}: API returned {res.status_code}", is_dry_run=False)
                    except Exception as e:
                        log_action(f"API Dispatch Error: {e}", is_dry_run=False)

        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()