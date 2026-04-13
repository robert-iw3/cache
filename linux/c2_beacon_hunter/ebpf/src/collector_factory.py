#!/usr/bin/env python3
"""
collector_factory.py - Backend selector (BCC or libbpf)

This module implements the CollectorFactory class, which is responsible for selecting and
instantiating the appropriate eBPF collector backend (BCC or libbpf) based on configuration settings.
The factory reads the configuration file to determine which backend to use and handles the logic
for loading the corresponding collector class. This allows for flexibility in choosing the eBPF
backend without modifying the main application code, enabling easy switching between development
and production environments.
"""

import configparser
import traceback
from pathlib import Path

class CollectorFactory:
    @staticmethod
    def create_collector():
        config = configparser.ConfigParser()

        # Check all possible paths depending on where the script was launched from
        possible_configs = [
            '/app/ebpf/config_dev.ini',
            '/app/config.ini',
            'config_dev.ini',
            '../config_dev.ini',
            'config.ini'
        ]

        loaded = config.read(possible_configs)
        print(f"[CollectorFactory] Loaded config from: {loaded}")

        # Default to libbpf now to force the traceback if it fails
        backend = config.get('ebpf', 'backend', fallback='libbpf').lower()
        print(f"[CollectorFactory] Selected eBPF backend: {backend}")

        if backend == "libbpf":
            try:
                from libbpf_collector import LibBPFCollector
                print("Using libbpf + CO-RE backend (production mode)")
                return LibBPFCollector()
            except Exception as e:
                print("libbpf failed to load. Exception details:")
                traceback.print_exc()
                print("Falling back to BCC backend.")
                from bcc_collector import BCCCollector
                return BCCCollector()
        else:
            from bcc_collector import BCCCollector
            print(f"Using BCC backend (development mode). Config returned: {backend}")
            return BCCCollector()