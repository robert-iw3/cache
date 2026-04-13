#!/usr/bin/env python3
"""
c2_defend/defender.py - Active protection engine (DFIR Enhanced v2.8)
"""

import json
import subprocess
import time
import os
import signal
import socket
from pathlib import Path

BLOCKLIST = Path("blocklist.txt")
LOGFILE = Path("defender.log")
JSONL_LOG = Path("../output/anomalies.jsonl")

def log_action(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(LOGFILE, "a") as f:
        f.write(f"{ts} | {msg}\n")
    print(f"[+] {msg}")

def get_firewall_info():
    if subprocess.call(["which", "firewall-cmd"], stdout=subprocess.DEVNULL) == 0:
        try:
            zone = subprocess.check_output(["firewall-cmd", "--get-default-zone"]).decode().strip()
            return "firewalld", zone
        except:
            return "firewalld", "public"
    elif subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL) == 0:
        return "ufw", None
    elif subprocess.call(["which", "iptables"], stdout=subprocess.DEVNULL) == 0:
        return "iptables", None
    return "none", None

def block_ip_xdp(ip):
    if ip == "0.0.0.0":
        return
    try:
        packed_ip = socket.inet_aton(ip)
        hex_key = " ".join([f"{b:02x}" for b in packed_ip])
        cmd = f"bpftool map update pinned /sys/fs/bpf/c2_blocklist key hex {hex_key} value hex 01"
        res = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if res.returncode != 0:
            cmd_docker = f"docker exec c2-beacon-hunter {cmd}"
            subprocess.run(cmd_docker, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except Exception:
        pass

def block_ip_port(fw_type, zone, ip, port):
    if ip == "0.0.0.0":
        return

    # Native XDP execution
    block_ip_xdp(ip)

    try:
        if fw_type == "firewalld":
            if port == 0:
                cmd = ["firewall-cmd", "--zone=" + zone, "--add-rich-rule", f'rule family="ipv4" source address="{ip}" drop']
            else:
                cmd = ["firewall-cmd", "--zone=" + zone, "--add-rich-rule", f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop']
        elif fw_type == "ufw":
            cmd = ["ufw", "deny", "from", ip]
        elif fw_type == "iptables":
            if port == 0:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            else:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"]

        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(BLOCKLIST, "a") as f:
            f.write(f"{ts}|{fw_type}|{zone}|{ip}|{port}\n")

        log_action(f"XDP & {fw_type} network block enforced for {ip}:{port}")
    except Exception as e:
        log_action(f"Firewall block failed: {e}")

def main():
    if os.getuid() != 0:
        print("Fatal: Must run as root to manage firewalls and processes.")
        sys.exit(1)

    if not JSONL_LOG.exists():
        print("No anomalies.jsonl found. Run the hunter first.")
        return

    suspicious = []
    with open(JSONL_LOG, "r") as f:
        lines = f.readlines()
        for line in lines[-50:]:
            try:
                data = json.loads(line.strip())
                if data.get("score", 0) >= 80:
                    suspicious.append(data)
            except:
                continue

    if not suspicious:
        print("No recent high-confidence anomalies found (Score >= 80).")
        return

    fw_type, zone = get_firewall_info()
    print(f"\n=== c2_defend Manual Containment Mode (v2.8) ===")
    print(f"System Firewall Detected: {fw_type} (Zone: {zone or 'N/A'})\n")

    for i, row in enumerate(suspicious):
        ip_display = row.get("dst_ip")
        print(f"[{i}] PID {row['pid']} ({row['process']}) → {ip_display}:{row['dst_port']} | Score: {row['score']}")

    print("\n[DFIR NOTE] We recommend 'f' (Freeze) instead of 'k' (Kill) to prevent systemd restarts and preserve memory.")
    action = input("\nAction (f=freeze, k=kill, b=block ip, a=all (freeze+block), q=quit): ").strip().lower()

    if action == 'q':
        return

    for row in suspicious:
        pid = int(row.get("pid", 0))
        ip = row.get("dst_ip")
        port = int(row.get("dst_port", 0))
        proc = row.get("process")

        if action in ["a", "f"] and pid > 0:
            try:
                os.kill(pid, signal.SIGSTOP)
                log_action(f"FROZE (SIGSTOP) PID {pid} ({proc}) to preserve memory.")
            except ProcessLookupError:
                log_action(f"PID {pid} no longer running.")
            except Exception as e:
                log_action(f"Failed to freeze PID {pid} - {e}")

        if action == "k" and pid > 0:
            try:
                os.kill(pid, signal.SIGKILL)
                log_action(f"KILLED (SIGKILL) PID {pid} ({proc})")
            except Exception as e:
                log_action(f"Failed to kill PID {pid} - {e}")

        if action in ["a", "b"] and ip:
            block_ip_port(fw_type, zone, ip, port)

if __name__ == "__main__":
    main()