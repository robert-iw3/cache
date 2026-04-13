#!/bin/bash
# This script applies necessary patches to c2_beacon_hunter.py to fix parsing issues with the 'ss' command output.
# It addresses:
# 1. Interface suffixes in IP addresses (e.g., 192.168.1.5%wlo1)
# 2. Column mismatches in 'ss' command output (Netid vs State column)
# 3. Optional: Disabling private IP filtering for testing

cat << 'EOF' > patches/fix_parsing.sh
#!/bin/bash

# Configuration
TARGET_FILE="../c2_beacon_hunter.py"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] Starting C2 Beacon Hunter Patcher...${NC}"

# 1. Verify Target Exists
if [ ! -f "$TARGET_FILE" ]; then
    echo -e "${RED}[-] Error: Target file '$TARGET_FILE' not found.${NC}"
    echo "    Make sure you run this script from inside the 'patches' folder."
    exit 1
fi

# 2. Backup
cp "$TARGET_FILE" "${TARGET_FILE}.bak"
echo "[*] Backup created: ${TARGET_FILE}.bak"

# 3. Apply Patch (Using embedded Python for safe multi-line replacement)
python3 - <<END
import sys
import re

file_path = "$TARGET_FILE"

with open(file_path, 'r') as f:
    content = f.read()

# --- DEFINE REPLACEMENTS ---

# 1. Fix Interface Suffixes (e.g., 192.168.1.5%wlo1)
#    Target: raddr, rport_str = remote.rsplit(':', 1)
old_split = "raddr, rport_str = remote.rsplit(':', 1)"
new_split = "remote = remote.split('%')[0]; raddr, rport_str = remote.rsplit(':', 1)"

if old_split in content:
    content = content.replace(old_split, new_split)
    print(f"    [+] Fixed: Interface suffix parsing (%wlo1)")
else:
    print(f"    [.] Info: Interface suffix fix already present or not found.")

# 2. Fix Column Mismatch (Netid vs State column)
#    Target: The specific block that hardcodes index 0, 3, and 4
#    We use regex to find the block ignoring minor whitespace differences
pattern_block = r'(if len\(parts\) < 6 or "ESTAB" not in parts\[0\]:\s+continue\s+local = parts\[3\]\s+remote = parts\[4\])'

#    Replacement: Dynamic index logic
new_block = """# [PATCH] Dynamic column detection (RHEL/CentOS support)
                state_idx = -1
                if "ESTAB" in parts[0]: state_idx = 0
                elif len(parts) > 1 and "ESTAB" in parts[1]: state_idx = 1

                if state_idx == -1 or len(parts) < state_idx + 5: continue
                local = parts[state_idx + 3]
                remote = parts[state_idx + 4]"""

match = re.search(pattern_block, content)
if match:
    content = content.replace(match.group(1), new_block)
    print(f"    [+] Fixed: SS command column mismatch (Netid offset)")
else:
    print(f"    [.] Info: Column mismatch fix already present or block modified.")

# 3. Disable Private IP Filtering (Optional, for easy testing)
#    This ensures your 192.168.x.x tests aren't ignored
if "if False and (remote_ip == local_ip):" not in content:
    content = re.sub(
        r"if\s+\(remote_ip\s*==\s*local_ip\):",
        r"if False and (remote_ip == local_ip): # PATCHED",
        content
    )
    print(f"    [+] Fixed: Disabled self-traffic filter for testing")

# --- WRITE BACK ---
with open(file_path, 'w') as f:
    f.write(content)
END

echo -e "${GREEN}[+] Patching complete!${NC}"
echo "    You can now run: sudo ./setup.sh test"
EOF

chmod +x patches/fix_parsing.sh