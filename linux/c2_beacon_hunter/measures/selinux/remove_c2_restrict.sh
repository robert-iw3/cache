#!/bin/bash
# remove_c2_restrict.sh - Completely remove the c2_restrict SELinux policy

echo "=== Removing c2_restrict SELinux Policy ==="

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exec sudo "$0" "$@"
fi

# Remove the policy module
echo "[1/3] Removing policy module..."
sudo semodule -r c2_restrict 2>/dev/null || echo "Policy module not found or already removed."

# Restore default file contexts for the restricted binaries
echo "[2/3] Restoring default file contexts..."
sudo restorecon -v /usr/bin/curl /usr/bin/wget /usr/bin/socat /usr/bin/nc \
                 /usr/bin/netcat /usr/bin/openssl /usr/bin/python3* \
                 /usr/bin/python /usr/bin/bash /usr/bin/ssh /usr/bin/perl /usr/bin/ruby*

# Reload SELinux policy
echo "[3/3] Reloading SELinux policy..."
sudo semodule -R

echo ""
echo "c2_restrict policy has been removed."
echo "All binaries have been restored to default SELinux contexts."
echo "Current mode: $(getenforce)"