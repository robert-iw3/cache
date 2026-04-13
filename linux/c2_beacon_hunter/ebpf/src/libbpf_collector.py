#!/usr/bin/env python3
"""
libbpf_collector.py - eBPF Collector (C-Loader Subprocess Mode)

This module implements the LibBPFCollector class, which uses a native C loader to run a CO-RE eBPF program.
The collector spawns the C loader as a subprocess, which loads the eBPF program and captures events related
to process execution, network connections, and memory file descriptor creation.
The C loader outputs captured events in JSON format to stdout, which the Python collector reads and processes
to record flows for baseline learning.
This approach allows us to leverage the performance and compatibility benefits of libbpf and CO-RE while
maintaining the flexibility of Python for data processing and integration with the baseline learner.
"""

import os
from ebpf_collector_base import EBPFCollectorBase
import time
import subprocess
import json
import threading
from datetime import datetime
from pathlib import Path
import configparser

class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.process = None
        self.loader_path = None
        self.target_interface = os.environ.get("TARGET_INTERFACE", "eth0")
        self.event_count = 0

        # Configurable loopback filtering (respects config.ini)
        self.capture_loopback = True
        try:
            parser = configparser.ConfigParser()
            parser.read(['config.ini', '/app/config.ini', '/app/ebpf/config_dev.ini'])
            if parser.has_section('ebpf'):
                self.capture_loopback = parser.getboolean('ebpf', 'capture_loopback', fallback=True)
        except Exception:
            pass  # safe fallback

        print(f"[LibBPF] Loopback capture: {'ENABLED' if self.capture_loopback else 'DISABLED (localhost/0.0.0.0 skipped)'}")

    def _is_loopback(self, ip: str) -> bool:
        """Quick check for loopback / unspecified addresses."""
        if not ip or ip.strip() in ("", "0.0.0.0", "127.0.0.1", "::1", "::"):
            return True
        if ip.startswith(("127.", "169.254.", "fe80::")):
            return True
        return False

    def load_probes(self):
        loader_paths = [
            Path("probes/c2_loader"),
            Path("../probes/c2_loader"),
            Path("/app/ebpf/probes/c2_loader")
        ]
        self.loader_path = next((p for p in loader_paths if p.exists()), None)

        if not self.loader_path:
            print("Error: c2_loader binary not found. Build it first with 'make' in probes/")
            return False
        return True

    def process_stdout(self):
        print(f"[Collector] Listening for events from C-Loader on {self.target_interface}...")

        while self.running and self.process.poll() is None:
            line = self.process.stdout.readline()
            if not line:
                continue
            line = line.strip()

            if not line.startswith('{'):
                if line and ("XDP" in line or "SUCCESS" in line or "initialized" in line):
                    print(f"[C-Loader] {line}")
                continue

            try:
                event = json.loads(line)
                self.event_count += 1

                pid = event.get("pid", 0)
                process_name = event.get("comm", "unknown")
                raw_type = event.get("type", "unknown")
                dst_ip = event.get("dst_ip", "0.0.0.0")
                packet_size = event.get("packet_size", 0)
                interval_ns = event.get("interval_ns", 0)
                interval_sec = interval_ns / 1_000_000_000.0
                entropy = event.get("entropy", 0.0)

                # Configurable Loopback Filter (early exit)
                if not self.capture_loopback and self._is_loopback(dst_ip):
                    if self.event_count % 100 == 0:  # rate-limited debug
                        print(f"[LOOPBACK SKIP #{self.event_count}] {process_name} (PID {pid}) → {dst_ip}")
                    continue

                # Normalize type (handles BOTH old int and new string types)
                etype = str(raw_type).lower()

                # Live visibility (first 30 events + every 50th)
                if self.event_count <= 30 or self.event_count % 50 == 0:
                    print(f"[EVENT #{self.event_count:03d}] {etype.upper():<12} | "
                          f"PID:{pid:<6} | {process_name:<12} → {dst_ip} | "
                          f"entropy={entropy:.3f} | size={packet_size}")

                mitre_tactic = "Unknown"
                if etype in ["send", "3", "recv", "4", "dns", "6"] or etype == "tcp_payload":
                    mitre_tactic = "C2_Beaconing"
                elif etype in ["memfd", "5"]:
                    mitre_tactic = "Process_Injection"
                elif etype in ["connect", "2"]:
                    mitre_tactic = "Data_Exfiltration"
                elif etype in ["exec", "1"]:
                    mitre_tactic = "Execution"

                # Force high-entropy TCP payloads into C2 tracking (original behavior)
                if etype == "tcp_payload" and entropy > 0.7:
                    mitre_tactic = "C2_Beaconing"

                # Record to BaselineLearner (this is what populates baseline.db + active flows)
                self.record_flow(
                    process_name=process_name,
                    dst_ip=dst_ip,
                    interval=interval_sec,
                    entropy=entropy,
                    packet_size_mean=packet_size,
                    packet_size_std=0.0,
                    packet_size_min=packet_size,
                    packet_size_max=packet_size,
                    mitre_tactic=mitre_tactic,
                    pid=pid
                )

            except json.JSONDecodeError:
                pass  # ignore non-JSON status lines
            except Exception as e:
                print(f"[Collector] Processing error: {e}")

    def run(self):
        if not self.load_probes():
            return

        self.running = True
        print(f"[{datetime.now()}] libbpf collector running (Native C-Loader on {self.target_interface})")

        try:
            self.process = subprocess.Popen(
                [str(self.loader_path), self.target_interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            threading.Thread(target=self.process_stdout, daemon=True).start()

            while self.running and self.process.poll() is None:
                time.sleep(1)

        except Exception as e:
            print(f"C-loader execution error: {e}")

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except:
                self.process.kill()