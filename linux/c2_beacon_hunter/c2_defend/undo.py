#!/usr/bin/env python3
"""
==============================================================================
Script Name: undo.py
Epic:        1 - Closed-Loop Active Response (v2.8)
Description: Rollback utility for false positives. Removes the BPF XDP Maps
             before backing out of firewalld, ufw, and iptables.
==============================================================================
"""

import os
import sys
import subprocess
import socket
from pathlib import Path

BLOCKLIST = Path("blocklist.txt")

def unblock_ip_xdp(ip):
    if ip == "0.0.0.0":
        return
    try:
        packed_ip = socket.inet_aton(ip)
        hex_key = " ".join([f"{b:02x}" for b in packed_ip])
        cmd = f"bpftool map delete pinned /sys/fs/bpf/c2_blocklist key hex {hex_key}"
        res = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if res.returncode != 0:
            cmd_docker = f"docker exec c2-beacon-hunter {cmd}"
            subprocess.run(cmd_docker, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except Exception:
        pass

def remove_firewall_rule(line):
    try:
        parts = line.strip().split("|")
        if len(parts) == 5:
            ts, fw_type, zone, ip, port = parts
        elif len(parts) == 3:
            ts, fw_type, ip = parts
            zone, port = "public", "0"
        else:
            return

        print(f"[*] Reversing XDP & {fw_type} block for {ip}...")
        unblock_ip_xdp(ip)

        if fw_type == "firewalld":
            if port == "0":
                rule = f'rule family="ipv4" source address="{ip}" drop'
            else:
                rule = f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop'
            subprocess.run(["firewall-cmd", "--zone=" + zone, "--remove-rich-rule", rule], check=True)

        elif fw_type == "ufw":
            subprocess.run(["ufw", "delete", "deny", "from", ip], check=True)

        elif fw_type == "iptables":
            if port == "0":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            else:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", port, "-j", "DROP"], check=True)

        print(f"[+] Successfully removed block for {ip}")
    except Exception as e:
        print(f"[!] Failed to remove block for {line.strip()}: {e}")

def main():
    if os.geteuid() != 0:
        print("Fatal: This utility must be run as root to modify firewall rules.")
        sys.exit(1)

    if not BLOCKLIST.exists() or BLOCKLIST.stat().st_size == 0:
        print("No active blocks found in blocklist.txt.")
        return

    with open(BLOCKLIST, "r") as f:
        blocks = f.readlines()

    print(f"=== Active Containment Rules ({len(blocks)}) ===")
    for i, line in enumerate(blocks):
        parts = line.strip().split("|")
        if len(parts) >= 3:
            ip = parts[3] if len(parts) == 5 else parts[2]
            fw = parts[1]
            print(f"{i+1:2d}. Target: {ip:<15} | Manager: {fw}")

    confirm = input("\nRemove ALL blocks and restore network access? (y/N): ").strip().lower()

    if confirm == "y":
        for line in blocks:
            remove_firewall_rule(line)
        open(BLOCKLIST, "w").close()
        print("\n[+] Network restoration complete.")
    else:
        print("Aborted.")

if __name__ == "__main__":
    main()