#!/usr/bin/env python3
"""
==============================================================================
Script Name: c2_defend.py (Daemon Mode - v2.8)
Description: Automated threat mitigation daemon. Monitors anomalies.jsonl.
             Surgically terminates processes and blackholes IPs using XDP
             Wire-Speed enforcement, backed by OS firewalls.
==============================================================================
"""

import json
import time
import psutil
import subprocess
import os
import sys
import argparse
import socket
from pathlib import Path

LOG_FILE = Path("../output/anomalies.jsonl")
BLOCKLIST = Path("blocklist.txt")
DAEMON_LOG = Path("c2_defend_daemon.log")
SCORE_THRESHOLD = 90

def log_action(msg, is_dry_run=True):
    prefix = "[DRY RUN]" if is_dry_run else "[ACTIVE]"
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    entry = f"{ts} | {prefix} {msg}"
    with open(DAEMON_LOG, "a") as f:
        f.write(entry + "\n")
    print(entry)

def get_firewall_info():
    if subprocess.call(["which", "firewall-cmd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        try:
            zone = subprocess.check_output(["firewall-cmd", "--get-default-zone"]).decode().strip()
            return "firewalld", zone
        except:
            return "firewalld", "public"
    elif subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return "ufw", None
    elif subprocess.call(["which", "iptables"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return "iptables", None
    return "none", None

def block_ip_xdp(ip):
    """Directly updates the eBPF XDP map for nanosecond wire-speed drops."""
    if ip == "0.0.0.0":
        return
    try:
        packed_ip = socket.inet_aton(ip)
        hex_key = " ".join([f"{b:02x}" for b in packed_ip])

        # Try native bpftool on host
        cmd = f"bpftool map update pinned /sys/fs/bpf/c2_blocklist key hex {hex_key} value hex 01"
        res = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # Fallback to containerized bpftool if host doesn't have it installed
        if res.returncode != 0:
            cmd_docker = f"docker exec c2-beacon-hunter {cmd}"
            subprocess.run(cmd_docker, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    except Exception as e:
        pass # OS Firewall handles the fallback

def block_ip_port(fw_type, zone, ip, port, is_dry_run=True):
    if ip == "0.0.0.0":
        return

    # 1. Engage Wire-Speed XDP Firewall
    if not is_dry_run:
        block_ip_xdp(ip)

    # 2. Engage OS-Level Defense-in-Depth
    try:
        if fw_type == "firewalld":
            if port == 0:
                cmd = ["firewall-cmd", "--zone=" + zone, "--add-rich-rule",
                       f'rule family="ipv4" source address="{ip}" drop']
            else:
                cmd = ["firewall-cmd", "--zone=" + zone, "--add-rich-rule",
                       f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop']
        elif fw_type == "ufw":
            cmd = ["ufw", "deny", "from", ip]
        elif fw_type == "iptables":
            if port == 0:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                cmd2 = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
            else:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"]

        if not is_dry_run:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if fw_type == "iptables" and port == 0:
                subprocess.run(cmd2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Record the block for undo.py
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            with open(BLOCKLIST, "a") as f:
                f.write(f"{ts}|{fw_type}|{zone}|{ip}|{port}\n")

            log_action(f"XDP & {fw_type} block established for {ip}:{port}", is_dry_run=False)
        else:
            log_action(f"Would execute XDP Map Pin + {' '.join(cmd)}", is_dry_run=True)

    except Exception as e:
        log_action(f"Firewall block failed: {e}", is_dry_run=is_dry_run)

def terminate_process(pid, proc_name, is_dry_run=True):
    if pid <= 0:
        return
    try:
        if not is_dry_run:
            os.kill(pid, 9)
            log_action(f"Killed malicious process: {proc_name} (PID: {pid})", is_dry_run=False)
        else:
            log_action(f"Would kill process: {proc_name} (PID: {pid})", is_dry_run=True)
    except ProcessLookupError:
        log_action(f"Process {pid} already dead.", is_dry_run=is_dry_run)
    except Exception as e:
        log_action(f"Failed to kill {pid}: {e}", is_dry_run=is_dry_run)

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
    parser = argparse.ArgumentParser(description="C2 Defend Active Response Daemon")
    parser.add_argument("--arm", action="store_true", help="Enable active containment")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("Fatal: Must run as root to manage firewalls and processes.")
        sys.exit(1)

    if not LOG_FILE.exists():
        LOG_FILE.touch()

    fw_type, zone = get_firewall_info()
    mode_str = "ACTIVE CONTAINMENT" if args.arm else "DRY RUN (Observation Only)"

    print(f"--- c2_defend Daemon: {mode_str} ---")
    print(f"Firewall: XDP Wire-Speed + {fw_type} | Zone: {zone or 'N/A'}")
    log_action(f"Daemon started. Monitoring {LOG_FILE}")

    handled_events = set()
    for line in tail_log(LOG_FILE):
        try:
            data = json.loads(line.strip())
            if data.get("score", 0) >= SCORE_THRESHOLD:
                pid = data.get("pid")
                ip = data.get("dst_ip")
                port = data.get("dst_port", 0)
                event_key = f"{pid}_{ip}_{port}"

                if event_key not in handled_events:
                    handled_events.add(event_key)
                    terminate_process(pid, data.get("process"), is_dry_run=not args.arm)
                    block_ip_port(fw_type, zone, ip, port, is_dry_run=not args.arm)
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()