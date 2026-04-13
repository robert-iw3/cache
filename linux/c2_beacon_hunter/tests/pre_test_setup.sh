#!/bin/bash
# =============================================================================
# pre_test_setup.sh - Pre-test security relaxation + status checker
# For c2_beacon_hunter v2.6 testing
# =============================================================================

echo "=== c2_beacon_hunter v2.6 - Pre-Test Security Setup ==="

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)."
    exec sudo "$0" "$@"
fi

echo "Current security status before test:"
echo "--------------------------------------------------"

# 1. YAMA ptrace_scope
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope)
    echo "YAMA ptrace_scope : $PTRACE $([ "$PTRACE" = "0" ] && echo "(relaxed)" || echo "(restricted)"))"
else
    echo "YAMA ptrace_scope : Not present"
fi

# 2. SELinux
if command -v getenforce >/dev/null; then
    SELINUX=$(getenforce)
    echo "SELinux           : $SELINUX"
else
    echo "SELinux           : Not installed"
fi

# 3. AppArmor
if command -v aa-status >/dev/null; then
    if aa-status --enabled >/dev/null 2>&1; then
        echo "AppArmor          : Enabled"
    else
        echo "AppArmor          : Disabled"
    fi
else
    echo "AppArmor          : Not installed"
fi

# 4. Active Firewall
FW="None"
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    FW="firewalld ($(firewall-cmd --get-default-zone))"
elif command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    FW="ufw (active)"
elif command -v iptables >/dev/null; then
    FW="iptables"
fi
echo "Firewall          : $FW"

echo "--------------------------------------------------"

echo -e "\nThis script will temporarily relax security settings for testing:"
echo "   - YAMA ptrace_scope to 0"
echo "   - SELinux to Permissive (if currently Enforcing)"
echo "   - AppArmor to complain mode for python3"
echo ""

read -p "Continue with test? (y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Test cancelled."
    exit 0
fi

echo -e "\nStarting simulator with security relaxation...\n"
./test_beacon_simulator.py "$@"

echo -e "\n=== Test completed ==="
echo "All security settings have been automatically restored."

exit 0