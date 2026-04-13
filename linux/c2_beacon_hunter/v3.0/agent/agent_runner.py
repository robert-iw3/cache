#!/usr/bin/env python3
"""
agent_runner.py - Active Agent
Collector + encrypted forward to central over HTTPS.
Listens on Secure WebSockets for SOAR execution orders.
@RW
"""

import os
import sys
import configparser
import time
import json
import socket
import signal
import subprocess
import threading
import asyncio
import ssl
import websockets
from pathlib import Path
from libbpf_collector import LibBPFCollector

# ====================== CONTAINMENT FUNCTIONS ======================
BLOCKLIST = Path("blocklist.txt")

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
    if ip == "0.0.0.0": return
    try:
        packed_ip = socket.inet_aton(ip)
        hex_key = " ".join([f"{b:02x}" for b in packed_ip])
        cmd = f"bpftool map update pinned /sys/fs/bpf/c2_blocklist key hex {hex_key} value hex 01"
        subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except Exception:
        pass

def block_ip_port(fw_type, zone, ip, port):
    if ip == "0.0.0.0": return
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
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                cmd = None
            else:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"]

        if cmd:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(BLOCKLIST, "a") as f:
            f.write(f"{ts}|{fw_type}|{zone}|{ip}|{port}\n")
        print(f"[AGENT DEFENSE] XDP & {fw_type} block enforced for {ip}:{port}")
    except Exception as e:
        print(f"[AGENT ERROR] Firewall block failed: {e}")

def terminate_process(pid):
    if pid <= 0: return
    try:
        os.kill(pid, signal.SIGKILL)
        print(f"[AGENT DEFENSE] KILLED (SIGKILL) PID {pid}")
    except ProcessLookupError:
        print(f"[AGENT DEFENSE] PID {pid} already dead.")
    except Exception as e:
        print(f"[AGENT ERROR] Failed to kill PID {pid} - {e}")

# ====================== C2 LISTENER ======================
async def listen_for_commands(central_url, agent_id, ca_cert):
    ws_url = central_url.replace("https://", "wss://").replace("/api/v1/ingest/events", f"/ws/agent/{agent_id}")
    ssl_context = ssl.create_default_context(cafile=ca_cert)

    while True:
        try:
            async with websockets.connect(ws_url, ssl=ssl_context) as ws:
                print(f"[AGENT C2] Connected to Central Command: {ws_url}")
                while True:
                    msg = await ws.recv()
                    cmd = json.loads(msg)

                    if cmd.get("action") == "contain":
                        pid = cmd.get("pid", 0)
                        ip = cmd.get("dst_ip")
                        port = cmd.get("dst_port", 0)

                        print(f"\n[!!!] CONTAINMENT ORDER RECEIVED [!!!]")
                        print(f"Target: PID {pid} | IP {ip}:{port}")

                        fw_type, zone = get_firewall_info()
                        terminate_process(pid)
                        block_ip_port(fw_type, zone, ip, port)

        except Exception as e:
            print(f"[AGENT C2] Connection lost: {e}. Retrying in 5s...")
            await asyncio.sleep(5)

# ====================== MAIN RUNNER ======================
def start_collector():
    collector = LibBPFCollector()
    collector.run()

def main():
    print("[AGENT v3.0] Starting Active Endpoint Defender...")

    config = configparser.ConfigParser()
    config.read(['/app/config.ini', '/app/agent/config.ini'])

    central_url = config.get('central', 'url', fallback='https://127.0.0.1:8443/api/v1/ingest/events')
    ca_cert = config.get('central', 'ca_cert', fallback='/app/certs/ca.crt')
    agent_id = config.get('central', 'agent_id', fallback=f"endpoint-{os.uname().nodename}")
    ca_cert_hash = config.get('central', 'ca_cert_hash', fallback='')

    print(f"[AGENT] Forwarding to {central_url} | ID: {agent_id}")

    os.environ["MODE"] = "agent"
    os.environ["CENTRAL_URL"] = central_url
    os.environ["CA_CERT"] = ca_cert
    os.environ["AGENT_ID"] = agent_id
    os.environ["CA_CERT_HASH"] = ca_cert_hash

    # Start the eBPF telemetry shipper in the background
    threading.Thread(target=start_collector, daemon=True).start()

    # Start the Active Defense C2 listener on the main thread
    try:
        asyncio.run(listen_for_commands(central_url, agent_id, ca_cert))
    except KeyboardInterrupt:
        print("[AGENT] Shutdown complete.")

if __name__ == "__main__":
    main()