#!/bin/bash

# Set SELinux to enforcing mode
sudo setenforce 1
sudo sed -i 's/SELINUX=.*$/SELINUX=enforcing/' /etc/selinux/config

# Enable key booleans for better confinement
sudo setsebool -P httpd_can_network_connect off
sudo setsebool -P nis_enabled off
sudo setsebool -P allow_execheap off
sudo setsebool -P allow_execmem off
sudo setsebool -P deny_ptrace on
sudo setsebool -P user_exec_content off

# Restrict execution from temporary directories
sudo setsebool -P tmp_exec off
sudo setsebool -P var_lib_t_exec off

echo "Basic SELinux hardening applied."