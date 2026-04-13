#!/usr/bin/env python3
"""
collector_factory.py - v3.0

Factory for eBPF collectors with multi-mode support (host, promisc, cloud, agent, central).
- Auto-detects mode from config.ini.
- Returns appropriate collector instance.
- Agent mode: Lightweight forwarder.
- Central mode: No collector (handled by hunter API).
Author: Robert Weber
"""

import configparser
import sys
from pathlib import Path

from ebpf_collector_base import EBPFCollectorBase

try:
    from libbpf_collector import LibBPFCollector
except ImportError:
    LibBPFCollector = None

try:
    from cloud_flow_collector import CloudFlowCollector
except ImportError:
    CloudFlowCollector = None

def get_collector(config_path: str = None) -> EBPFCollectorBase:
    mode = "host"
    config_paths = ["config.ini", "v3.0/config.ini", "/app/config.ini"]
    if config_path:
        config_paths.insert(0, config_path)

    try:
        parser = configparser.ConfigParser()
        parser.read(config_paths)
        if parser.has_section("general"):
            mode = parser.get("general", "mode", fallback="host").strip().lower()
        print(f"[CollectorFactory v3.0] Mode detected: {mode.upper()}")
    except Exception as e:
        print(f"[CollectorFactory ERROR] {e} — defaulting to host mode")

    if mode == "cloud":
        print("[CollectorFactory] → Using Cloud Flow Log Adapter (Epic 4)")
        if CloudFlowCollector:
            return CloudFlowCollector()
        else:
            print("[WARNING] Cloud collector not found, falling back to libbpf")
            return LibBPFCollector() if LibBPFCollector else None
    elif mode == "promisc":
        print("[CollectorFactory] → Using Promiscuous Wire-Speed Parser (Epic 1+2)")
        return LibBPFCollector() if LibBPFCollector else None
    elif mode == "agent":
        print("[CollectorFactory] → AGENT MODE: Lightweight forwarder only (Epic 7)")
        return LibBPFCollector()  # Agent version
    elif mode == "central":
        print("[CollectorFactory] → CENTRAL MODE: No local collector (ingest via API)")
        return None  # No collector needed
    else:
        print("[CollectorFactory] → Using Legacy Host Mode (full v2.8.2 compatibility)")
        return LibBPFCollector() if LibBPFCollector else None

# Backward compatibility
def register_collector(name: str, cls):
    pass


print("[CollectorFactory v3.0] Initialized — supports host / promisc / cloud / agent / central")