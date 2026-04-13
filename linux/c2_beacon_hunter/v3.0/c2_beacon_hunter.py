#!/usr/bin/env python3
"""
c2_beacon_hunter - Linux C2 Beacon Detector (v3.0)
Author: Robert Weber

v2.8 - Active Enforcement & Scalability
- Asynchronous HTTP POST SIEM Shipper (ELK/Splunk)
- Persistent SQLite integration with Race Condition fixes
- JSONL Append-mode for real-time c2_defend.py tailing
- All v2.7 eBPF and ML features preserved

v3.0 Epics 1-4 Addition:
- Multi-mode support (host | promisc | cloud)
- Fast Flux / DGA / Campaign Correlation + Refined Confidence Scoring

- psutil system profiling
- Buffered subprocess + early exits
- CA cert pinning
- Input sanitization
- Tunable eBPF aggregation awareness
"""

import argparse
import configparser
import json
import logging
import logging.handlers
import math
import os
import signal
import subprocess
import sys
import threading
import time
import requests
import queue
import hashlib  # For potential cert pinning logging
from collections import defaultdict, deque, Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import psutil
import sqlite3

# Optional DNS monitoring
try:
    from scapy.all import sniff, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Advanced ML module
try:
    from BeaconML import detect_beaconing_list, detect_advanced_c2
except ImportError:
    def detect_beaconing_list(*args, **kwargs): return None, 0
    def detect_advanced_c2(*args, **kwargs): return None, 0

# ====================== SIEM SHIPPER ======================
class SIEMShipper:
    def __init__(self, endpoint_url, auth_token=None, batch_size=10, timeout=3.0):
        self.endpoint_url = endpoint_url
        self.headers = {"Content-Type": "application/json"}
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"
        self.batch_size = batch_size
        self.timeout = timeout
        self.queue = queue.Queue()
        self.running = True
        if self.endpoint_url:
            self.worker = threading.Thread(target=self._shipping_loop, daemon=True)
            self.worker.start()

    def send(self, anomaly_dict):
        if self.endpoint_url:
            self.queue.put(anomaly_dict)

    def _shipping_loop(self):
        while self.running:
            batch = []
            try:
                item = self.queue.get(timeout=2.0)
                batch.append(item)
                while len(batch) < self.batch_size and not self.queue.empty():
                    batch.append(self.queue.get_nowait())
                if batch:
                    requests.post(self.endpoint_url, headers=self.headers, json={"events": batch}, timeout=self.timeout)
            except queue.Empty:
                continue
            except Exception as e:
                logging.debug(f"SIEM Shipping error: {e}")

    def stop(self):
        self.running = False
        if self.endpoint_url:
            self.worker.join(timeout=2.0)

# ====================== CONFIG (with sanitization) ======================
config = configparser.ConfigParser()
config.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])

OUTPUT_DIR = Path(config.get('general', 'output_dir', fallback='output'))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODE = config.get('general', 'mode', fallback='host').strip().lower()
# Sanitize mode input
if MODE not in ['host', 'promisc', 'cloud']:
    logger.error(f"Invalid mode: {MODE} — defaulting to 'host'")
    MODE = 'host'
print(f"[v3.0] Operating in {MODE.upper()} mode")

# ====================== LOGGING ======================
logger = logging.getLogger("c2_beacon_hunter")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.handlers.RotatingFileHandler(
    OUTPUT_DIR / "c2_beacon_hunter.log", maxBytes=20*1024*1024, backupCount=5
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# ====================== THRESHOLDS (config-driven with sanitization) ======================
try:
    SCORE_THRESHOLD = int(config.get('general', 'score_threshold', fallback=72))
    MAX_FLOW_AGE = int(config.get('general', 'max_flow_age_hours', fallback=48)) * 3600
    MIN_SAMPLES_SPARSE = int(config.get('general', 'min_samples_sparse', fallback=8))
    LONG_SLEEP_THRESHOLD = int(config.get('general', 'long_sleep_threshold', fallback=1800))
except ValueError as e:
    logger.error(f"Invalid config value: {e} — using defaults")
    SCORE_THRESHOLD = 72
    MAX_FLOW_AGE = 48 * 3600
    MIN_SAMPLES_SPARSE = 8
    LONG_SLEEP_THRESHOLD = 1800

USE_EBPF = config.getboolean('ebpf', 'enabled', fallback=False)
SNAPSHOT_INTERVAL = int(config.get('general', 'snapshot_interval', fallback=60))
ANALYZE_INTERVAL = int(config.get('general', 'analyze_interval', fallback=300))
ANOMALY_CSV = OUTPUT_DIR / "anomalies.csv"
ANOMALY_JSONL = OUTPUT_DIR / "anomalies.jsonl"
ML_USE_DBSCAN = config.getboolean('ml', 'use_dbscan', fallback=True)
USE_UEBA = config.getboolean('ml', 'use_ueba', fallback=True)
USE_ENHANCED_DNS = config.getboolean('ml', 'use_enhanced_dns', fallback=True)

# Stricter whitelist parsing + lowercase normalization
BENIGN_PROCESSES = {p.strip().lower() for p in config.get('whitelist', 'benign_processes', fallback="").split(',') if p.strip()}
BENIGN_DESTINATIONS = {d.strip() for d in config.get('whitelist', 'benign_destinations', fallback="").split(',') if d.strip()}

COMMON_PORTS = {53, 80, 443, 22, 25, 465, 587, 993, 995, 8080, 8443}

MITRE_MAP = {
    "beacon_periodic": ("TA0011", "T1071", "Application Layer Protocol"),
    "high_entropy": ("TA0011", "T1568.002", "Domain Generation Algorithms"),
    "unusual_port": ("TA0011", "T1090", "Proxy"),
    "suspicious_process": ("TA0002", "T1059", "Command and Scripting Interpreter"),
    "masquerade": ("TA0005", "T1036", "Masquerading"),
}

# ====================== HELPER: CERT PINNING (if central/agent mode) ======================
def verify_ca_cert(ca_cert_path: str):
    """SHA256 pinning for CA cert (if configured)"""
    try:
        with open(ca_cert_path, 'rb') as f:
            cert_hash = hashlib.sha256(f.read()).hexdigest()
        expected = config.get('central', 'ca_cert_hash', fallback='')  # From config.ini [central] ca_cert_hash = abc123...
        if expected and cert_hash != expected:
            raise ValueError(f"CA cert hash mismatch! Got {cert_hash}, expected {expected}")
        logger.info(f"CA certificate validated: hash {cert_hash}")
    except Exception as e:
        logger.error(f"CA pinning failed: {e}")
        sys.exit(1)

# If in agent/central mode and ca_cert defined, verify it
ca_cert = config.get('central', 'ca_cert', fallback='')
if MODE in ['agent', 'central'] and ca_cert:
    verify_ca_cert(ca_cert)

# ====================== BEACON HUNTER ======================
class BeaconHunter:
    def __init__(self, output_dir=OUTPUT_DIR):
        self.output_dir = Path(output_dir)
        self.flows = defaultdict(dict)
        self.last_analyzed = {}
        self.anomalies = []
        self.running = True
        self.lock = threading.Lock()
        self.detection_count = 0
        self.process_baselines = defaultdict(list)
        self.dns_resolutions = defaultdict(lambda: {"ips": [], "ttls": [], "timestamps": []})
        self.domain_cache = {}

        Path("data").mkdir(exist_ok=True)

        # SIEM
        siem_endpoint = config.get('siem', 'endpoint', fallback='')
        self.shipper = SIEMShipper(endpoint_url=siem_endpoint)

        # System profiling thread
        threading.Thread(target=self._profile_system, daemon=True).start()

        # DB init (SQLite only in this version)
        self._init_db()

        # eBPF collector
        self.ebpf_collector = None
        if config.getboolean('ebpf', 'enabled', fallback=False):
            logger.info(f"Starting eBPF collector in {MODE.upper()} mode...")
            try:
                from collector_factory import get_collector
                self.ebpf_collector = get_collector()
                threading.Thread(target=self.ebpf_collector.run, daemon=True).start()
            except Exception as e:
                logger.warning(f"eBPF collector failed to start: {e}")

        # DNS sniffer
        if SCAPY_AVAILABLE and USE_ENHANCED_DNS:
            threading.Thread(target=self._dns_sniffer, daemon=True).start()

        # Signal handlers
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

        logger.info("BeaconHunter initialized successfully")

    def _profile_system(self):
        """log resource usage every 60s"""
        while self.running:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            logger.info(f"[PROFILE] CPU: {cpu:.1f}% | MEM: {mem:.1f}% | Active flows: {len(self.flows)}")
            time.sleep(60)

    def _init_db(self):
        try:
            conn = sqlite3.connect(Path("data/baseline.db"))
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    process_name TEXT,
                    dst_ip TEXT,
                    interval REAL,
                    cv REAL,
                    outbound_ratio REAL,
                    entropy REAL,
                    packet_size_mean REAL,
                    packet_size_std REAL,
                    packet_size_min REAL,
                    packet_size_max REAL,
                    mitre_tactic TEXT,
                    pid INTEGER,
                    cmd_entropy REAL
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database init failed: {e}")

    def shutdown(self, *args):
        self.running = False
        logger.info("Shutting down gracefully...")
        if self.ebpf_collector:
            self.ebpf_collector.stop()
        self.shipper.stop()
        self.export_all()
        sys.exit(0)

    # ---------------------- SNAPSHOT (with psutil generator + early prune) ----------------------
    def snapshot(self):
        ts = time.time()
        try:
            # Use psutil generator for efficient process iteration
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
                try:
                    pid = proc.info['pid']
                    process_name = proc.info['name'].lower()
                    cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                    # Normalize process path to detect masquerading
                    exe_path = proc.exe()  # Get full path
                    if any(b in process_name for b in BENIGN_PROCESSES):
                        continue  # Strict whitelist

                    for conn in proc.info['connections']:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            dst_ip, dst_port = conn.raddr
                            if any(dst_ip.startswith(b) for b in BENIGN_DESTINATIONS) or dst_port in COMMON_PORTS:
                                continue  # Add port whitelist

                            key = f"{process_name}:{dst_ip}:{dst_port}"
                            with self.lock:
                                if key not in self.flows:
                                    self.flows[key] = {
                                        "intervals": deque(maxlen=2000),
                                        "entropies": deque(maxlen=2000),
                                        "packet_sizes": deque(maxlen=2000),
                                        "outbound_bytes": 0,
                                        "inbound_bytes": 0,
                                        "pid": pid,
                                        "cmdline": cmdline,
                                        "exe_path": exe_path,  # Log full path
                                        "count": 0,
                                        "last_seen": ts
                                    }
                                flow = self.flows[key]
                                flow["last_seen"] = ts
                                flow["count"] += 1
                                # Simulate interval/entropy (in full eBPF, this is from kernel)
                                interval = ts - flow.get("last_ts", ts)
                                entropy = math.log(len(cmdline) + 1) if cmdline else 0.0  # Placeholder
                                packet_size = conn.laddr[1] if conn.laddr else 0  # Placeholder

                                flow["intervals"].append(interval)
                                flow["entropies"].append(entropy)
                                flow["packet_sizes"].append(packet_size)
                                flow["outbound_bytes"] += packet_size  # Simulate
                                flow["last_ts"] = ts

                                # UEBA baseline
                                self.process_baselines[process_name].append(interval)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Early prune old flows
            cutoff = ts - MAX_FLOW_AGE
            with self.lock:
                for k in list(self.flows.keys()):
                    if self.flows[k]["last_seen"] < cutoff:
                        del self.flows[k]

        except Exception as e:
            logger.error(f"Snapshot error: {e}")

    def snapshot_db(self):
        try:
            conn = sqlite3.connect(Path("data/baseline.db"))
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM flows WHERE timestamp > ?", (time.time() - 86400,))
            rows = cursor.fetchall()
            for row in rows:
                id_, timestamp, process_name, dst_ip, interval, cv, outbound_ratio, entropy, \
                packet_size_mean, packet_size_std, packet_size_min, packet_size_max, \
                mitre_tactic, pid, cmd_entropy = row

                key = f"{process_name}:{dst_ip}"
                with self.lock:
                    if key not in self.flows:
                        self.flows[key] = {
                            "intervals": deque(maxlen=2000),
                            "entropies": deque(maxlen=2000),
                            "packet_sizes": deque(maxlen=2000),
                            "outbound_bytes": 0,
                            "inbound_bytes": 0,
                            "pid": pid,
                            "cmdline": "",  # Not in DB
                            "count": 0,
                            "last_seen": timestamp
                        }
                    flow = self.flows[key]
                    flow["intervals"].append(interval)
                    flow["entropies"].append(entropy)
                    flow["packet_sizes"].append(packet_size_mean)
                    flow["outbound_bytes"] += outbound_ratio * packet_size_mean  # Approximate
                    flow["count"] += 1
                    flow["last_seen"] = timestamp

            conn.close()
        except Exception as e:
            logger.error(f"DB snapshot failed: {e}")

    # ---------------------- ANALYZE_FLOW — PERFORMANCE EARLY-EXIT ----------------------
    def analyze_flow(self, key, flow):
        now = time.time()
        last = self.last_analyzed.get(key, 0)
        if flow.get("count", 0) < MIN_SAMPLES_SPARSE or (now - last < 30):
            return None  # Early exit for low-sample or recent analysis

        self.last_analyzed[key] = now

        intervals = list(flow["intervals"])
        entropies = list(flow["entropies"])
        packet_sizes = list(flow["packet_sizes"])

        # Basic metrics
        avg_interval = np.mean(intervals)
        cv = np.std(intervals) / (avg_interval + 1e-6)
        avg_entropy = np.mean(entropies)
        packet_mean = np.mean(packet_sizes)
        packet_std = np.std(packet_sizes)
        packet_min = min(packet_sizes)
        packet_max = max(packet_sizes)
        outbound_ratio = flow["outbound_bytes"] / (flow["outbound_bytes"] + flow["inbound_bytes"] + 1e-6)

        # ML beaconing
        beacon_result, beacon_conf = detect_beaconing_list({
            key: {
                "intervals": intervals,
                "entropies": entropies,
                "packet_sizes": packet_sizes
            }
        }, use_dbscan=ML_USE_DBSCAN)

        # Scoring flags
        flags = []
        score = beacon_conf

        if cv < 0.2 and len(intervals) > 5:
            flags.append("beacon_periodic")
            score += 20 if avg_interval > LONG_SLEEP_THRESHOLD else 15

        if avg_entropy > 0.75:
            flags.append("high_entropy")
            score += 25

        process_name, dst_ip, dst_port = key.rsplit(':', 2)
        dst_port = int(dst_port)
        if dst_port not in COMMON_PORTS:
            flags.append("unusual_port")
            score += 10

        if process_name not in BENIGN_PROCESSES:
            flags.append("suspicious_process")
            score += 15

        # Masquerade detection (improved with path normalization)
        cmd_entropy = math.log(len(flow["cmdline"]) + 1) if flow["cmdline"] else 0.0
        if cmd_entropy > 4.0 or os.path.basename(flow["exe_path"]).lower() != process_name:
            flags.append("masquerade")
            score += 30
            logger.warning(f"Masquerade suspected: {process_name} path {flow['exe_path']}")

        # UEBA
        if USE_UEBA and process_name in self.process_baselines:
            baseline = np.mean(self.process_baselines[process_name])
            if abs(avg_interval - baseline) > 2 * np.std(self.process_baselines[process_name]):
                score += 10

        if score < SCORE_THRESHOLD:
            return None

        mitre_ids = [MITRE_MAP.get(f, ("", "", "")) for f in flags]
        description = "; ".join([f"{tactic} {technique} ({sub})" for tactic, technique, sub in mitre_ids])

        anomaly = {
            "timestamp": datetime.now().isoformat(),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "process": process_name,
            "cmd_snippet": flow["cmdline"][:50],
            "pid": flow["pid"],
            "process_tree": " ".join(psutil.Process(flow["pid"]).parents()) if flow["pid"] else "",  # Improvement: Security - Full tree
            "masquerade_detected": "masquerade" in flags,
            "avg_interval_sec": avg_interval,
            "cv": cv,
            "entropy": avg_entropy,
            "packet_size_mean": packet_mean,
            "packet_size_std": packet_std,
            "packet_size_min": packet_min,
            "packet_size_max": packet_max,
            "score": score,
            "description": description,
            "mitre_ids": mitre_ids
        }

        self.anomalies.append(anomaly)
        return anomaly

    def run_analysis(self):
        with self.lock:
            active_flows = {k: v.copy() for k, v in self.flows.items() if v.get("count", 0) >= MIN_SAMPLES_SPARSE}

        new_anomalies = []
        for key, flow in active_flows.items():
            anomaly = self.analyze_flow(key, flow)
            if anomaly:
                new_anomalies.append(anomaly)
                self.detection_count += 1
                print(f"\033[91m[DETECTION #{self.detection_count:04d}] {anomaly['description']} Score={anomaly['score']}\033[0m")
                logger.info(f"DETECTION: {anomaly['description']} Score={anomaly['score']}")

        # === Campaign-level analysis (disparate dataset) ===
        campaign_result, campaign_conf = detect_advanced_c2(self.flows, self.dns_resolutions)
        if campaign_result and campaign_conf >= 68:
            print(f"\033[91m[CAMPAIGN DETECTION] {campaign_result} (conf:{campaign_conf})\033[0m")
            logger.info(f"CAMPAIGN: {campaign_result} Score={campaign_conf}")

        if new_anomalies:
            self.anomalies.extend(new_anomalies)
            self.export_all()

    def export_all(self):
        if not self.anomalies:
            return

        # 1. Append to JSONL for the API, WebSockets, and Dashboard
        with open(ANOMALY_JSONL, 'a') as f:
            for anomaly in self.anomalies:
                f.write(json.dumps(anomaly) + '\n')

        # 2. Export to CSV for manual analyst review
        df = pd.DataFrame(self.anomalies)
        df.to_csv(ANOMALY_CSV, index=False)

        # 3. Clear the buffer so we don't duplicate entries
        current_count = len(self.anomalies)
        self.anomalies.clear()

        logger.info(f"Exported {current_count} anomalies to JSONL and CSV in {self.output_dir}")

    def _dns_sniffer(self):
        # Batch DNS processing (every 10 packets)
        dns_batch = []
        def process_dns(pkt):
            nonlocal dns_batch
            if DNSQR in pkt and pkt[DNS].qr == 0:
                query = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
            elif DNSRR in pkt and pkt[DNS].qr == 1:
                domain = pkt[DNSRR].rrname.decode('utf-8').rstrip('.')
                ip = pkt[DNSRR].rdata
                ttl = pkt[DNSRR].ttl
                dns_batch.append((domain, ip, ttl))
                if len(dns_batch) >= 10:
                    with self.lock:
                        for d, i, t in dns_batch:
                            self.dns_resolutions[d]["ips"].append(i)
                            self.dns_resolutions[d]["ttls"].append(t)
                            self.dns_resolutions[d]["timestamps"].append(time.time())
                    dns_batch = []

        sniff(iface=os.environ.get("TARGET_INTERFACE", "wlo1"), filter="udp port 53", prn=process_dns, store=False)

    def start(self):
        threading.Thread(target=self.snapshot_loop, daemon=True).start()
        threading.Thread(target=self.print_status, daemon=True).start()
        logger.info(f"c2_beacon_hunter v3.0 started (Epic 1 mode: {MODE.upper()})")
        print(f"Output directory: {self.output_dir} | Ctrl+C to stop")
        try:
            while self.running:
                time.sleep(ANALYZE_INTERVAL)
                self.run_analysis()
        except KeyboardInterrupt:
            self.shutdown()
        except Exception as e:
            logger.critical(f"Main loop error: {e}")

    def snapshot_loop(self):
        while self.running:
            if USE_EBPF:
                self.snapshot_db()
            else:
                self.snapshot()
            time.sleep(SNAPSHOT_INTERVAL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="c2_beacon_hunter v3.0")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help="Output directory for logs/CSV/JSON")
    args = parser.parse_args()
    hunter = BeaconHunter(output_dir=args.output_dir)
    hunter.start()