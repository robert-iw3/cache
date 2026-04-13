#!/bin/bash
# enable_all_profiles.sh - Load and enforce all AppArmor profiles in current directory

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exec sudo "$0" "$@"
fi

echo "Loading and enforcing all AppArmor profiles in current directory..."

for profile in *.profile; do
    if [ -f "$profile" ]; then
        echo "Loading: $profile"
        apparmor_parser -r "$profile"
        aa-enforce "$profile"
    fi
done

echo "All profiles loaded and set to enforce mode."
echo "Check status with: sudo aa-status"