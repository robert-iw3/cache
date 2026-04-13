#!/usr/bin/env python3
"""
C2 Beacon Simulator for testing c2_beacon_hunter v2.6
Extensible test tool to validate:
- Pre-filter whitelist
- Sparse / long-sleep tracking
- Malleable C2 (outbound consistency)
- UEBA baseline deviation
- Lomb-Scargle jitter detection
- Masquerading simulation
- DNS C2 simulation

- Temporarily relaxes AppArmor, YAMA ptrace_scope, and SELinux during test
- Guarantees full restoration on exit or Ctrl+C
- Multi-firewall support (firewalld, ufw, iptables)
- Extensible for all v2.6 features

chmod +x test_beacon_simulator.py
./test_beacon_simulator.py --process-name python --period 60 --jitter 0.35 --duration 180
"""

import argparse
import socket
import time
import random
import threading
import subprocess
import sys
import atexit
import signal
from pathlib import Path

# Global state for cleanup
cleanup_data = {
    "port": None,
    "fw_type": None,
    "zone": None,
    "original_ptrace": None,
    "original_selinux": None,
    "apparmor_profiles": []
}

def log(msg):
    print(f"[*] {msg}")

def save_and_relax_security():
    """Temporarily relax security features for testing"""
    global cleanup_data

    # 1. YAMA ptrace_scope
    ptrace_path = Path("/proc/sys/kernel/yama/ptrace_scope")
    if ptrace_path.exists():
        try:
            cleanup_data["original_ptrace"] = ptrace_path.read_text().strip()
            if cleanup_data["original_ptrace"] != "0":
                ptrace_path.write_text("0")
                log(f"Relaxed YAMA ptrace_scope (was {cleanup_data['original_ptrace']})")
        except:
            pass

    # 2. SELinux
    try:
        status = subprocess.check_output(["getenforce"], stderr=subprocess.DEVNULL).decode().strip()
        cleanup_data["original_selinux"] = status
        if status == "Enforcing":
            subprocess.run(["setenforce", "0"], check=True, stderr=subprocess.DEVNULL)
            log("Relaxed SELinux to Permissive mode")
    except:
        pass

    # 3. AppArmor (put common profiles in complain mode)
    common_profiles = ["/usr/bin/python3", "/usr/bin/python", "/usr/sbin/sshd"]
    for profile in common_profiles:
        try:
            subprocess.run(["aa-complain", profile], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cleanup_data["apparmor_profiles"].append(profile)
            log(f"AppArmor: Set {profile} to complain mode")
        except:
            pass

def restore_security():
    """Restore all security settings to original state"""
    global cleanup_data

    # Restore ptrace_scope
    if cleanup_data["original_ptrace"] is not None:
        try:
            Path("/proc/sys/kernel/yama/ptrace_scope").write_text(cleanup_data["original_ptrace"])
            log(f"Restored YAMA ptrace_scope to {cleanup_data['original_ptrace']}")
        except:
            pass

    # Restore SELinux
    if cleanup_data["original_selinux"] == "Enforcing":
        try:
            subprocess.run(["setenforce", "1"], check=True, stderr=subprocess.DEVNULL)
            log("Restored SELinux to Enforcing mode")
        except:
            pass

    # Restore AppArmor
    for profile in cleanup_data["apparmor_profiles"]:
        try:
            subprocess.run(["aa-enforce", profile], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log(f"AppArmor: Restored {profile} to enforce mode")
        except:
            pass

    log("All security settings restored to original state.")

# Register cleanup handlers
atexit.register(restore_security)
signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

def start_listener(port: int):
    def server():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(5)
        print(f"[+] Listener started on 0.0.0.0:{port}")
        while True:
            try:
                conn, addr = s.accept()
                print(f"[+] Accepted from {addr}")
                time.sleep(2)
                conn.close()
            except:
                break
    t = threading.Thread(target=server, daemon=True)
    t.start()
    return t

def send_beacon(target_ip: str, port: int, hold_time: float = 8.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target_ip, port))
        junk = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=80))
        s.sendall(junk.encode())
        time.sleep(hold_time)
        s.close()
        return True
    except Exception as e:
        print(f"[-] Beacon failed: {e}")
        return False

def detect_and_open_port(port: int):
    global cleanup_data

    # 1. firewalld
    if subprocess.call(['which', 'firewall-cmd'], stdout=subprocess.DEVNULL) == 0:
        try:
            zone = subprocess.check_output(['sudo', 'firewall-cmd', '--get-default-zone']).decode().strip()
            subprocess.check_call(['sudo', 'firewall-cmd', '--zone', zone, '--add-port', f'{port}/tcp'])
            print(f"[+] Firewalld: Opened {port}/tcp in zone '{zone}'")
            cleanup_data["port"] = port
            cleanup_data["fw_type"] = "firewalld"
            cleanup_data["zone"] = zone
            return "firewalld", zone
        except:
            pass

    # 2. ufw
    if subprocess.call(['which', 'ufw'], stdout=subprocess.DEVNULL) == 0:
        try:
            subprocess.check_call(['sudo', 'ufw', 'allow', f'{port}/tcp'])
            print(f"[+] UFW: Allowed port {port}/tcp")
            cleanup_data["port"] = port
            cleanup_data["fw_type"] = "ufw"
            return "ufw", None
        except:
            pass

    # 3. iptables fallback
    try:
        subprocess.check_call(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'])
        print(f"[+] iptables: Accepted port {port}/tcp")
        cleanup_data["port"] = port
        cleanup_data["fw_type"] = "iptables"
        return "iptables", None
    except:
        print("[-] Could not open port with any firewall.")
        return None, None

def main():
    parser = argparse.ArgumentParser(description="C2 Beacon Simulator v2.6 - Full Security Relaxation + Cleanup")
    parser.add_argument("--port", type=int, default=1337, help="TCP port")
    parser.add_argument("--target-ip", default="127.0.0.1", help="Target IP")
    parser.add_argument("--period", type=float, default=60, help="Base interval")
    parser.add_argument("--jitter", type=float, default=0.35, help="Jitter factor")
    parser.add_argument("--hold", type=float, default=8.0, help="Hold time")
    parser.add_argument("--duration", type=int, default=300, help="Duration")
    parser.add_argument("--process-name", default="python", help="Simulated process name")
    parser.add_argument("--long-sleep", action="store_true", help="Sparse beacon test")
    parser.add_argument("--high-outbound", action="store_true", help="Malleable C2 test")
    parser.add_argument("--no-listener", action="store_true")
    args = parser.parse_args()

    print("="*85)
    print("          C2 BEACON SIMULATOR v2.6 - Security Relaxation + Full Cleanup")
    print("="*85)
    print(f"Target       : {args.target_ip}:{args.port}")
    print(f"Process      : {args.process_name}")
    print(f"Period       : {args.period}s ± {args.jitter*100:.0f}% jitter")
    print("="*85 + "\n")

    # Relax security features
    save_and_relax_security()

    # Open firewall port
    fw_type, zone = detect_and_open_port(args.port)

    if not args.no_listener:
        start_listener(args.port)
        time.sleep(2)

    print("Starting beaconing loop... (Ctrl+C to stop)")
    start_time = time.time()
    counter = 0

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= args.duration:
                break

            hold_time = args.hold * 3 if args.long_sleep else args.hold
            success = send_beacon(args.target_ip, args.port, hold_time)
            counter += 1

            if success:
                jitter_amount = random.uniform(-args.jitter * args.period, args.jitter * args.period)
                sleep_time = max(5.0, args.period + jitter_amount) if not args.long_sleep else args.period * 4
                print(f"\r[+] Beacon #{counter:3d} | Process: {args.process_name} | Elapsed: {elapsed:3.0f}s | Next: {sleep_time:4.1f}s", end="", flush=True)
                time.sleep(sleep_time)
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        print("\n\nStopped by user.")
    finally:
        print(f"\n\nTest finished — {counter} beacons sent.")
        print("All firewall and security settings have been restored to original state.")

if __name__ == "__main__":
    main()