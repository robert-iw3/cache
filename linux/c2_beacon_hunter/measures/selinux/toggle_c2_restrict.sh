#!/bin/bash
# toggle_c2_restrict.sh - Easily enable/disable the c2_restrict policy

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exec sudo "$0" "$@"
fi

if [ -z "$1" ]; then
    echo "Usage: $0 [on|off|status]"
    echo ""
    echo "  on     - Enable restricted mode (hardened)"
    echo "  off    - Disable restricted mode (normal)"
    echo "  status - Show current status"
    exit 1
fi

case "$1" in
    on|enable)
        echo "=== Enabling c2_restrict (Restricted Mode) ==="
        if [ -f "c2_restrict.pp" ]; then
            sudo semodule -i c2_restrict.pp
            sudo restorecon -Rv /usr/bin/curl /usr/bin/wget /usr/bin/socat /usr/bin/nc \
                             /usr/bin/netcat /usr/bin/openssl /usr/bin/python3* \
                             /usr/bin/python /usr/bin/bash /usr/bin/ssh /usr/bin/perl /usr/bin/ruby*
            echo "Restricted mode ENABLED."
        else
            echo "Error: c2_restrict.pp not found. Run apply_c2_restrict.sh first."
        fi
        ;;

    off|disable)
        echo "=== Disabling c2_restrict (Normal Mode) ==="
        sudo semodule -r c2_restrict 2>/dev/null || true
        sudo restorecon -Rv /usr/bin/curl /usr/bin/wget /usr/bin/socat /usr/bin/nc \
                         /usr/bin/netcat /usr/bin/openssl /usr/bin/python3* \
                         /usr/bin/python /usr/bin/bash /usr/bin/ssh /usr/bin/perl /usr/bin/ruby*
        echo "Restricted mode DISABLED. System returned to normal SELinux contexts."
        ;;

    status)
        echo "=== c2_restrict Status ==="
        if sudo semodule -l | grep -q c2_restrict; then
            echo "Status: ENABLED (Restricted Mode Active)"
        else
            echo "Status: DISABLED (Normal Mode)"
        fi
        echo "Current SELinux mode: $(getenforce)"
        ;;

    *)
        echo "Invalid option. Use: on | off | status"
        ;;
esac