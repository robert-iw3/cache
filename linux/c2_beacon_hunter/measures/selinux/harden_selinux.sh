#!/bin/bash
# harden_selinux.sh - Aggressive SELinux hardening for C2 defense

echo "=== Applying Aggressive SELinux Hardening ==="

# Core hardening
sudo setenforce 1
sudo sed -i 's/SELINUX=.*$/SELINUX=enforcing/' /etc/selinux/config

# Disable dangerous capabilities
sudo setsebool -P deny_ptrace on
sudo setsebool -P allow_execmem off
sudo setsebool -P allow_execheap off
sudo setsebool -P user_exec_content off
sudo setsebool -P tmp_exec off

# Restrict network and execution
sudo setsebool -P httpd_can_network_connect off
sudo setsebool -P nis_enabled off
sudo setsebool -P ftp_home_dir off

# Block execution from common dropper locations
sudo semanage fcontext -a -t noexec_t "/tmp(/.*)?"
sudo semanage fcontext -a -t noexec_t "/dev/shm(/.*)?"
sudo semanage fcontext -a -t noexec_t "/run(/.*)?"
sudo restorecon -Rv /tmp /dev/shm /run

echo "SELinux hardening applied."
echo "Current mode: $(getenforce)"
echo "Run 'sestatus' for full status."