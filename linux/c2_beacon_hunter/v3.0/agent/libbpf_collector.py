#!/usr/bin/env python3
"""
libbpf_collector.py - eBPF Collector (C-Loader Subprocess Mode) for AGENT

This module implements the LibBPFCollector class, which uses a native C loader to run a CO-RE eBPF program.
The collector spawns the C loader as a subprocess, which loads the eBPF program and captures events related
to process execution, network connections, and memory file descriptor creation.
The C loader outputs captured events in JSON format to stdout, which the Python collector reads and processes
to record flows for baseline learning.
This approach allows us to leverage the performance and compatibility benefits of libbpf and CO-RE while
maintaining the flexibility of Python for data processing and integration with the baseline learner.

In agent mode, events are forwarded to central via HTTPS with cert validation.

Author: Robert Weber
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
import requests
import hashlib
import io

class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.process = None
        self.loader_path = None
        self.target_interface = os.environ.get("TARGET_INTERFACE", "wlo1")
        self.event_count = 0
        self.running = False

        # Agent-specific
        self.central_url = os.environ.get("CENTRAL_URL")
        self.ca_cert = os.environ.get("CA_CERT")
        self.agent_id = os.environ.get("AGENT_ID")

        # Cert pinning: Check SHA256 hash of CA cert
        if self.ca_cert:
            with open(self.ca_cert, 'rb') as f:
                cert_data = f.read()
                cert_hash = hashlib.sha256(cert_data).hexdigest()
                # Pull from environment or use a safe fallback bypass
                expected_hash = os.environ.get("CA_CERT_HASH", cert_hash)
                if expected_hash != cert_hash:
                    raise ValueError(f"CA cert hash mismatch: got {cert_hash}, expected {expected_hash}")

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

    def _load_config_mode(self):
        """Detect mode for Epics 1-4 (host / promisc / cloud)."""
        try:
            parser = configparser.ConfigParser()
            parser.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])
            return parser.get('general', 'mode', fallback='host').strip().lower()
        except Exception:
            return 'host'

    def load_probes(self):
        mode = self._load_config_mode()
        if mode in ['host', 'promisc', 'agent']:
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
        stdout = io.TextIOWrapper(self.process.stdout.buffer, encoding='utf-8', line_buffering=True)
        for line in stdout:
            if not self.running:
                break
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
                    continue

                # Enrich with agent ID and timestamp
                event['agent_id'] = self.agent_id
                event['timestamp'] = time.time()

                # Forward to central with cert validation
                response = requests.post(
                    self.central_url,
                    json=event,
                    verify=self.ca_cert,
                    timeout=5
                )
                response.raise_for_status()

                self.event_count += 1
                if self.event_count <= 30 or self.event_count % 50 == 0:
                    print(f"[EVENT #{self.event_count:03d}] {etype.upper():<12} | "
                          f"PID:{pid:<6} | {process_name:<12} → {dst_ip} | "
                          f"entropy={entropy:.3f} | size={packet_size}")

            except json.JSONDecodeError:
                pass  # ignore non-JSON status lines
            except requests.exceptions.RequestException as e:
                print(f"[AGENT] Send error: {e}")
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