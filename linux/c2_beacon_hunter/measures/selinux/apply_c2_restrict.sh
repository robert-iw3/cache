#!/bin/bash
# apply_c2_restrict.sh - Automatically compile, install, and apply c2_restrict policy

echo "=== Applying c2_restrict SELinux Policy ==="

# Check for required tools
if ! command -v checkmodule >/dev/null || ! command -v semodule_package >/dev/null; then
    echo "Error: SELinux policy tools not found. Install selinux-policy-devel"
    exit 1
fi

# 1. Compile the policy
echo "[1/4] Compiling policy..."
checkmodule -M -m -o c2_restrict.mod c2_restrict.te
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

# 2. Package the module
echo "[2/4] Packaging module..."
semodule_package -o c2_restrict.pp -m c2_restrict.mod -f c2_restrict.fc

# 3. Install the module
echo "[3/4] Installing policy module..."
sudo semodule -i c2_restrict.pp
if [ $? -ne 0 ]; then
    echo "Module installation failed."
    exit 1
fi

# 4. Apply file contexts
echo "[4/4] Applying file contexts..."
sudo semodule -e c2_restrict
sudo restorecon -Rv /usr/bin/curl /usr/bin/wget /usr/bin/socat /usr/bin/nc \
                 /usr/bin/netcat /usr/bin/openssl /usr/bin/python3* \
                 /usr/bin/python /usr/bin/bash /usr/bin/ssh /usr/bin/perl /usr/bin/ruby*

echo ""
echo "c2_restrict policy successfully applied and enforced!"
echo ""
echo "Restricted tools now run under confined domains."
echo "To check status: sudo semodule -l | grep c2_restrict"
echo "To view AVC denials: sudo ausearch -m avc -ts recent"