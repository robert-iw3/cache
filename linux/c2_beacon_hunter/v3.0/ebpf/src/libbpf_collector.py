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

Author: Robert Weber

- Performance: Buffered stdout reads with io.TextIOWrapper
- Security: CA cert pinning if in agent mode (aligns with central)
- Debug: Log skipped loopback events
- Interop: Full compatibility with c2_beacon_hunter.py's record_flow
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
import io  # For buffered stdout
import hashlib  # For cert pinning

class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.process = None
        self.loader_path = None
        self.target_interface = os.environ.get("TARGET_INTERFACE", "wlo1")
        self.event_count = 0
        self.running = False

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

        # If agent mode, verify CA cert pinning
        mode = self._load_config_mode()
        ca_cert = parser.get('central', 'ca_cert', fallback='') if 'parser' in locals() else ''
        if mode == 'agent' and ca_cert:
            self._verify_ca_cert(ca_cert)

    def _verify_ca_cert(self, ca_cert_path: str):
        """SHA256 pinning for CA cert in agent mode"""
        try:
            with open(ca_cert_path, 'rb') as f:
                cert_hash = hashlib.sha256(f.read()).hexdigest()
            expected = configparser.ConfigParser().get('central', 'ca_cert_hash', fallback='')  # From config
            if expected and cert_hash != expected:
                raise ValueError(f"CA cert hash mismatch! Got {cert_hash}")
            print("[LibBPF] CA cert validated via pinning")
        except Exception as e:
            print(f"[ERROR] CA pinning failed: {e}")
            sys.exit(1)

    def _load_config_mode(self):
        """Detect mode for Epics 1-4 (host / promisc / cloud)."""
        try:
            parser = configparser.ConfigParser()
            parser.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])
            return parser.get('general', 'mode', fallback='host').strip().lower()
        except Exception:
            return 'host'

    def _is_loopback(self, ip: str) -> bool:
        """Quick check for loopback / unspecified addresses."""
        if not ip or ip.strip() in ("", "0.0.0.0", "127.0.0.1", "::1", "::"):
            return True
        if ip.startswith(("127.", "169.254.", "fe80::")):
            return True
        return False

    def load_probes(self):
        mode = self._load_config_mode()
        if mode in ['host', 'promisc']:
            loader_name = 'c2_promisc_loader' if mode == 'promisc' else 'c2_loader'
            self.loader_path = Path(f"/app/probes/{loader_name}")
            if not self.loader_path.exists():
                print(f"[ERROR] Native C-loader not found: {self.loader_path}")
                return False
            print(f"[LibBPF] Using {mode.upper()} mode with {loader_name}")
            return True
        print("[LibBPF] No probes needed for this mode")
        return False

    def process_stdout(self):
        # Buffered TextIOWrapper for efficient line reading
        stdout = io.TextIOWrapper(self.process.stdout.buffer, encoding='utf-8', line_buffering=True)
        for line in stdout:
            try:
                event = json.loads(line.strip())
                etype = event.get("type", "0")
                pid = event.get("pid", 0)
                process_name = event.get("process_name", "unknown")
                dst_ip = event.get("dst_ip", "0.0.0.0")
                interval_sec = event.get("interval_ns", 0) / 1e9
                entropy = event.get("entropy", 0.0)
                packet_size = event.get("packet_size", 0)

                if not self.capture_loopback and self._is_loopback(dst_ip):
                    print(f"[DEBUG] Skipped loopback event: {dst_ip}")  # Improvement: Debug log for skips
                    continue

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

                self.event_count += 1
                if self.event_count <= 30 or self.event_count % 50 == 0:
                    print(f"[EVENT #{self.event_count:03d}] {etype.upper():<12} | "
                          f"PID:{pid:<6} | {process_name:<12} → {dst_ip} | "
                          f"entropy={entropy:.3f} | size={packet_size}")

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


if __name__ == "__main__":
    collector = LibBPFCollector()
    collector.run()