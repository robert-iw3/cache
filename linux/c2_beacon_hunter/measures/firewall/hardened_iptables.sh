#!/bin/bash
# hardened_iptables.sh - Hardened iptables rules for C2 defense

echo "=== Applying Hardened iptables Rules ==="

# Flush existing rules
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP   # Strict egress

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow essential outbound
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT     # DNS
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT     # HTTP
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT    # HTTPS
sudo iptables -A OUTPUT -p udp --dport 123 -j ACCEPT    # NTP

# Optional: Allow SSH inbound from specific IP
# sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT

echo "Hardened iptables applied."
echo "Save rules permanently: sudo iptables-save > /etc/iptables.rules"