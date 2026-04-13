#!/bin/bash
# =============================================================================
# post_test_check.sh - Verify security settings were properly restored
# Companion script for c2_beacon_hunter v2.6 testing
# =============================================================================

echo "=== c2_beacon_hunter v2.6 - Post-Test Security Verification ==="
echo "Running checks to confirm all settings were restored..."
echo "--------------------------------------------------"

STATUS="PASS"
WARNINGS=0

# 1. YAMA ptrace_scope
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    CURRENT=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [ "$CURRENT" = "0" ]; then
        echo "YAMA ptrace_scope : WARNING - Still set to 0 (should be 1 or 2)"
        STATUS="WARNING"
        ((WARNINGS++))
    else
        echo "YAMA ptrace_scope : OK ($CURRENT)"
    fi
else
    echo "YAMA ptrace_scope : Not present (OK)"
fi

# 2. SELinux
if command -v getenforce >/dev/null; then
    CURRENT=$(getenforce)
    if [ "$CURRENT" = "Permissive" ]; then
        echo "SELinux           : WARNING - Still in Permissive mode"
        STATUS="WARNING"
        ((WARNINGS++))
    else
        echo "SELinux           : OK ($CURRENT)"
    fi
else
    echo "SELinux           : Not installed (OK)"
fi

# 3. AppArmor
if command -v aa-status >/dev/null; then
    if aa-status --enabled >/dev/null 2>&1; then
        COMPLAIN_COUNT=$(aa-status | grep -c "complain")
        if [ "$COMPLAIN_COUNT" -gt 0 ]; then
            echo "AppArmor          : WARNING - $COMPLAIN_COUNT profile(s) still in complain mode"
            STATUS="WARNING"
            ((WARNINGS++))
        else
            echo "AppArmor          : OK (all profiles in enforce mode)"
        fi
    else
        echo "AppArmor          : Disabled (OK)"
    fi
else
    echo "AppArmor          : Not installed (OK)"
fi

# 4. Firewall Port Check (port 1337)
PORT_OPEN=0
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    if firewall-cmd --query-port=1337/tcp >/dev/null 2>&1; then
        PORT_OPEN=1
    fi
elif command -v ufw >/dev/null && ufw status | grep -q "1337/tcp"; then
    PORT_OPEN=1
elif command -v iptables >/dev/null; then
    if iptables -L INPUT -n | grep -q "1337"; then
        PORT_OPEN=1
    fi
fi

if [ $PORT_OPEN -eq 1 ]; then
    echo "Firewall Port 1337: WARNING - Still open"
    STATUS="WARNING"
    ((WARNINGS++))
else
    echo "Firewall Port 1337: OK (closed)"
fi

echo "--------------------------------------------------"

if [ "$STATUS" = "PASS" ]; then
    echo "ALL SECURITY SETTINGS SUCCESSFULLY RESTORED!"
    echo "Your system is back to its original security state."
elif [ "$STATUS" = "WARNING" ]; then
    echo "$WARNINGS issue(s) detected that may need manual cleanup."
    echo "Run this script again after a few seconds to re-check."
else
    echo "Some settings could not be verified."
fi

echo ""
echo "Tip: You can re-run this check anytime with:"
echo "     sudo ./post_test_check.sh"

exit 0