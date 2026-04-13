import re
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_PATH = os.path.join(BASE_DIR, "..", "c2_beacon_hunter.py")

#FILE_PATH = "../c2_beacon_hunter.py"

try:
    with open(FILE_PATH, "r") as f:
        content = f.read()

    print(f"[*] Patching {FILE_PATH}...")

    # FIX 1: Handle '%' in IPv6 or scoped IPv4 addresses (e.g. 192.168.1.1%eth0)
    # Original: remote_ip = remote_addr.split(':')[0]
    # Target:   remote_ip = remote_addr.split('%')[0].split(':')[0]
    if "split('%')" not in content:
        print("    Applying '%' Parsing Fix...")
        content = re.sub(
            r"(remote_ip\s*=\s*remote_addr)\.split\(':'\)",
            r"\1.split('%')[0].split(':')",
            content
        )
    else:
        print("    '%' Parsing Fix already applied.")

    # FIX 2: Disable Private IP Filtering for Testing
    # We look for the check "if ip_is_private(remote_ip):" and comment it out
    # or force it to False.
    if "if False and ip_is_private" not in content:
        print("    Disabling Private IP Filter (for testing)...")
        content = re.sub(
            r"if\s+ip_is_private\(remote_ip\):",
            r"if False and ip_is_private(remote_ip): # PATCHED FOR TESTING",
            content
        )
    else:
        print("    Private IP Filter already disabled.")

    # FIX 3: Disable Self-Traffic Filtering (Source == Dest)
    # Often tools ignore localhost traffic; let's ensure we catch it
    if "if False and (remote_ip == local_ip):" not in content:
        print("    Disabling Self-Traffic Filter...")
        content = re.sub(
            r"if\s+\(remote_ip\s*==\s*local_ip\):",
            r"if False and (remote_ip == local_ip): # PATCHED FOR TESTING",
            content
        )

    with open(FILE_PATH, "w") as f:
        f.write(content)

    print("[+] Patch applied successfully!")

except FileNotFoundError:
    print(f"[-] Error: Could not find {FILE_PATH}. Run this in the patches directory.")
except Exception as e:
    print(f"[-] Error: {e}")