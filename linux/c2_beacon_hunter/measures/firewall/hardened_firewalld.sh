#!/bin/bash
# hardened_firewalld.sh - Hardened firewalld rules for C2 defense

# 1. Create new restricted zone
sudo firewall-cmd --permanent --new-zone=restricted

# 2. Set default behavior: Drop everything inbound, allow limited outbound
sudo firewall-cmd --permanent --zone=restricted --set-target=DROP

# 3. Allow essential outbound services
sudo firewall-cmd --permanent --zone=restricted --add-service=dhcpv6-client
sudo firewall-cmd --permanent --zone=restricted --add-service=dns
sudo firewall-cmd --permanent --zone=restricted --add-service=http
sudo firewall-cmd --permanent --zone=restricted --add-service=https
sudo firewall-cmd --permanent --zone=restricted --add-service=ssh   # Remove if not needed

# 4. (Optional but recommended) Allow only specific outbound IPs for extra hardening
# Example: Allow only Cloudflare/Google DNS + your internal network
sudo firewall-cmd --permanent --zone=restricted --add-rich-rule='rule family="ipv4" destination address="1.1.1.1" accept'
sudo firewall-cmd --permanent --zone=restricted --add-rich-rule='rule family="ipv4" destination address="8.8.8.8" accept'
sudo firewall-cmd --permanent --zone=restricted --add-rich-rule='rule family="ipv4" destination address="192.168.0.0/16" accept'

# 5. Make this zone the default and reload
sudo firewall-cmd --permanent --set-default-zone=restricted
sudo firewall-cmd --reload

echo "Hardened 'restricted' zone is now active and set as default."