#!/usr/bin/env python3
"""
cloud_flow_collector.py - v3.0 Cloud-Native Flow Log Adapter
Auto-detects AWS VPC Flow Logs, Azure NSG, GCP VPC Flow Logs (JSON lines).
Pure flow-log mode with reduced features (no entropy, no PID, no process tree).
Robust error handling and batch processing.
Author: Robert Weber
"""

import json
import time
from pathlib import Path
from ebpf_collector_base import EBPFCollectorBase
import configparser


class CloudFlowCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.running = False
        self.log_path = None
        self.provider = "auto"

        # Robust config loading
        try:
            parser = configparser.ConfigParser()
            parser.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])
            self.log_path = parser.get('cloud', 'flow_log_path', fallback='/app/cloud_logs/flow_logs.jsonl')
            self.provider = parser.get('cloud', 'provider', fallback='auto').lower()
        except Exception as e:
            print(f"[CloudCollector WARNING] Config error: {e} — using defaults")
            self.log_path = '/app/cloud_logs/flow_logs.jsonl'

        print(f"[CloudCollector] Starting in CLOUD mode | Provider: {self.provider.upper()} | Log: {self.log_path}")

    def load_probes(self):
        path = Path(self.log_path)
        if not path.exists():
            print(f"[ERROR] Cloud log file not found: {self.log_path}")
            print("   → Mount a volume or create the file with flow logs.")
            return False
        return True

    def _detect_provider(self, line: dict):
        if "vpc-id" in line or "srcaddr" in line or "dstaddr" in line:
            return "aws"
        if "ResourceId" in line or "NSG" in str(line) or "destinationIp" in line:
            return "azure"
        if "src_ip" in line or "dest_ip" in line:
            return "gcp"
        return "generic"

    def process_log_line(self, line: dict):
        try:
            dst_ip = line.get("dstaddr") or line.get("DestinationIp") or line.get("dest_ip") or line.get("destinationAddress") or "0.0.0.0"
            bytes_transferred = int(line.get("bytes", 0) or line.get("Bytes", 0) or line.get("packetLength", 0))
            start_time = float(line.get("start", line.get("StartTime", time.time())))
            end_time = float(line.get("end", line.get("EndTime", start_time + 1)))
            interval = max(end_time - start_time, 0.0)

            self.record_flow(
                process_name="cloud_flow",
                dst_ip=dst_ip,
                interval=interval,
                entropy=0.0,                    # reduced features for cloud mode
                packet_size_mean=bytes_transferred,
                packet_size_std=0.0,
                packet_size_min=bytes_transferred,
                packet_size_max=bytes_transferred,
                mitre_tactic="C2_Beaconing",
                pid=0
            )
        except Exception as e:
            print(f"[CloudCollector ERROR] Line processing failed: {e}")

    def run(self):
        if not self.load_probes():
            return

        self.running = True
        print(f"[CloudCollector] Ingestion started from {self.log_path}")

        try:
            with open(self.log_path, "r") as f:
                batch = []
                for line in f:
                    if not self.running:
                        break
                    if line.strip():
                        batch.append(line.strip())
                        if len(batch) >= 100:
                            for batch_line in batch:
                                try:
                                    event = json.loads(batch_line)
                                    self.process_log_line(event)
                                except json.JSONDecodeError:
                                    continue
                            batch = []
                # Process remaining batch
                for batch_line in batch:
                    try:
                        event = json.loads(batch_line)
                        self.process_log_line(event)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[CloudCollector ERROR] Ingestion failed: {e}")

    def stop(self):
        self.running = False
        print("[CloudCollector] Stopped.")


# Register for factory
from collector_factory import register_collector
register_collector("cloud", CloudFlowCollector)