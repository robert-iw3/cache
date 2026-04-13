#!/bin/bash
# hardened_ufw.sh - Hardened UFW configuration for C2 defense

echo "=== Applying Hardened UFW Rules ==="

sudo ufw reset --force

# Default policies
sudo ufw default deny incoming
sudo ufw default deny outgoing   # Strict egress

# Allow essential outbound only
sudo ufw allow out 53/udp        # DNS
sudo ufw allow out 53/tcp
sudo ufw allow out 80/tcp        # HTTP
sudo ufw allow out 443/tcp       # HTTPS
sudo ufw allow out 123/udp       # NTP

# Optional: Allow SSH from specific IPs only (uncomment and edit)
# sudo ufw allow from 192.168.1.100 to any port 22

sudo ufw --force enable

echo "Hardened UFW applied (default deny outbound + limited services)"
echo "Review rules with: sudo ufw status verbose"