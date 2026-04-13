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

# ====================== CONFIG ======================
config = configparser.ConfigParser()
config.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])

OUTPUT_DIR = config.get('general', 'output_dir', fallback='output')

# ====================== LOGGING ======================
logger = logging.getLogger("c2_beacon_hunter")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
file_handler = logging.handlers.RotatingFileHandler(
    f"{OUTPUT_DIR}/c2_beacon_hunter.log", maxBytes=20*1024*1024, backupCount=5
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

MODE = config.get('general', 'mode', fallback='host').strip().lower()
print(f"[v3.0] Operating in {MODE.upper()} mode")

USE_EBPF = config.getboolean('ebpf', 'enabled', fallback=False)
if USE_EBPF:
    try:
        sys.path.append('ebpf/src')
        from collector_factory import get_collector
    except ImportError:
        logger.warning("eBPF integration not available.")
        USE_EBPF = False

SNAPSHOT_INTERVAL = int(config.get('general', 'snapshot_interval', fallback=60))
ANALYZE_INTERVAL = int(config.get('general', 'analyze_interval', fallback=300))
SCORE_THRESHOLD = 72  # RAISED for FP reduction
MAX_FLOW_AGE = int(config.get('general', 'max_flow_age_hours', fallback=48)) * 3600
MAX_FLOWS = int(config.get('general', 'max_flows', fallback=5000))
ML_STD_THRESHOLD = float(config.get('ml', 'std_threshold', fallback=10.0))
ML_USE_DBSCAN = config.getboolean('ml', 'use_dbscan', fallback=True)
ML_USE_ISOLATION = config.getboolean('ml', 'use_isolation', fallback=True)
ML_MAX_SAMPLES = int(config.get('ml', 'max_samples', fallback=2000))
LONG_SLEEP_THRESHOLD = int(config.get('general', 'long_sleep_threshold', fallback=1800))
MIN_SAMPLES_SPARSE = int(config.get('general', 'min_samples_sparse', fallback=8))  # raised
USE_UEBA = config.getboolean('ml', 'use_ueba', fallback=True)
USE_ENHANCED_DNS = config.getboolean('ml', 'use_enhanced_dns', fallback=True)

BENIGN_PROCESSES = [p.strip().lower() for p in config.get('whitelist', 'benign_processes', fallback="").split(',') if p.strip()]
BENIGN_DESTINATIONS = [d.strip() for d in config.get('whitelist', 'benign_destinations', fallback="").split(',') if d.strip()]

IN_CONTAINER = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
TEST_MODE = os.environ.get('TEST_MODE', 'false').lower() == 'true'

DB_PATH = Path("data/baseline.db")
BASELINE_MODEL_PATH = Path("data/baseline_model.joblib")

baseline_model = None
if BASELINE_MODEL_PATH.exists():
    try:
        import joblib
        baseline_model = joblib.load(BASELINE_MODEL_PATH)
    except Exception as e:
        logger.warning(f"Failed to load baseline model: {e}")

if IN_CONTAINER:
    psutil.PROCFS_PATH = '/host/proc'

DETECTION_LOG = f"{OUTPUT_DIR}/detections.log"
ANOMALY_CSV = f"{OUTPUT_DIR}/anomalies.csv"
ANOMALY_JSONL = f"{OUTPUT_DIR}/anomalies.jsonl"

COMMON_PORTS = {53, 80, 443, 22, 25, 465, 587, 993, 995, 8080, 8443}
MITRE_MAP = {
    "beacon_periodic": ("TA0011", "T1071", "Application Layer Protocol"),
    "high_entropy": ("TA0011", "T1568.002", "Domain Generation Algorithms"),
    "unusual_port": ("TA0011", "T1090", "Proxy"),
    "suspicious_process": ("TA0002", "T1059", "Command and Scripting Interpreter"),
    "masquerade": ("TA0005", "T1036", "Masquerading"),
}
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
        self.dns_timestamps = []

        # DNS tracking for Fast Flux / DGA
        self.dns_resolutions = defaultdict(lambda: {"ips": [], "ttls": [], "timestamps": []})
        self.domain_cache = {}

        Path("data").mkdir(exist_ok=True)

        siem_endpoint = config.get('siem', 'endpoint', fallback='')
        self.shipper = SIEMShipper(endpoint_url=siem_endpoint)

        # DB init
        try:
            conn = sqlite3.connect(DB_PATH)
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
            logger.error(f"Failed to initialize database: {e}")

        self.ebpf_collector = None
        if USE_EBPF:
            logger.info(f"Starting eBPF collector in {MODE.upper()} mode...")
            self.ebpf_collector = get_collector()
            threading.Thread(target=self.ebpf_collector.run, daemon=True).start()

        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

        if SCAPY_AVAILABLE and USE_ENHANCED_DNS:
            threading.Thread(target=self._dns_sniffer, daemon=True).start()

    def shutdown(self, *args):
        self.running = False
        logger.info("Shutting down gracefully...")
        if self.ebpf_collector:
            self.ebpf_collector.stop()
        self.shipper.stop()
        self.export_all()
        sys.exit(0)

    def shannon_entropy(self, data):
        if not data:
            return 0.0
        counts = Counter(data)
        probs = [v / len(data) for v in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def get_process_tree(self, pid):
        tree = []
        try:
            current = psutil.Process(pid)
            while current:
                exe = current.exe() if hasattr(current, 'exe') and current.exe() else "unknown"
                tree.append((current.pid, current.name(), exe))
                current = current.parent()
        except:
            pass
        return tree[::-1]

    def _dns_sniffer(self):
        def pkt_handler(pkt):
            try:
                if DNSQR in pkt and DNSRR in pkt:
                    domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    ttl = pkt[DNSRR].ttl
                    ip = str(pkt[DNSRR].rdata) if hasattr(pkt[DNSRR], 'rdata') else None
                    if ip and domain:
                        self.domain_cache[ip] = domain
                        self.dns_resolutions[domain]["ips"].append(ip)
                        self.dns_resolutions[domain]["ttls"].append(ttl)
                        self.dns_resolutions[domain]["timestamps"].append(time.time())
                        for k in self.dns_resolutions[domain]:
                            if len(self.dns_resolutions[domain][k]) > 200:
                                self.dns_resolutions[domain][k] = self.dns_resolutions[domain][k][-200:]
            except:
                pass
        try:
            sniff(filter="udp port 53", prn=pkt_handler, store=0, timeout=0)
        except:
            pass

    def snapshot(self):
        ts = time.time()
        try:
            output = subprocess.check_output(["ss", "-tupn", "--numeric"], timeout=3).decode('utf-8', errors='ignore')
            lines = output.splitlines()
            if len(lines) > 0 and ("State" in lines[0] or "Netid" in lines[0]):
                lines = lines[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 5: continue
                state_idx = 0 if "ESTAB" in parts[0] else 1 if len(parts) > 1 and "ESTAB" in parts[1] else -1
                if state_idx == -1 or len(parts) < state_idx + 5: continue
                local_raw = parts[state_idx + 3]
                remote_raw = parts[state_idx + 4]
                remote_clean = remote_raw.split('%')[0]
                local_clean = local_raw.split('%')[0]
                if ':' not in remote_clean: continue
                try:
                    raddr, rport_str = remote_clean.rsplit(':', 1)
                    raddr = raddr.strip('[]')
                    rport = int(rport_str)
                except ValueError:
                    continue
                if not TEST_MODE and raddr in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue
                pid = 0
                if "pid=" in line:
                    try:
                        pid = int(line.split("pid=")[1].split(",")[0].split(")")[0])
                    except:
                        pass
                key = (local_clean, raddr, rport)
                is_outbound = rport > 1024
                try:
                    p = psutil.Process(pid)
                    proc = {
                        "name": p.name()[:50],
                        "cmd": " ".join(p.cmdline())[:200],
                        "entropy_cmd": self.shannon_entropy(" ".join(p.cmdline()))
                    }
                except:
                    proc = {"name": "unknown", "cmd": "", "entropy_cmd": 0.0}
                with self.lock:
                    if key not in self.flows:
                        self.flows[key] = {
                            "process": proc,
                            "dst_ip": raddr,
                            "dst_port": rport,
                            "pid": pid,
                            "intervals": [],
                            "last_seen": ts,
                            "count": 0,
                            "outbound_ratio": 0.0,
                            "packet_sizes": [],
                            "mitre_tactic": "Unknown"
                        }
                    flow = self.flows[key]
                    interval = ts - flow["last_seen"] if flow["count"] > 0 else 0
                    if interval > 0:
                        flow["intervals"].append(interval)
                    flow["last_seen"] = ts
                    flow["count"] += 1
                    flow["outbound_ratio"] = ((flow["outbound_ratio"] * (flow["count"] - 1)) + int(is_outbound)) / flow["count"]
                    flow["packet_sizes"].append(0)
                    if len(flow["intervals"]) > 500:
                        flow["intervals"].pop(0)
                    if len(flow["packet_sizes"]) > 500:
                        flow["packet_sizes"].pop(0)
        except Exception as e:
            logger.warning(f"ss snapshot failed ({e}), falling back to psutil")
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if (conn.status == psutil.CONN_ESTABLISHED and
                        conn.raddr and
                        (TEST_MODE or conn.raddr.ip not in ("127.0.0.1", "::1"))):
                        key = (str(conn.laddr), conn.raddr.ip, conn.raddr.port)
                        is_outbound = conn.raddr.port > 1024
                        try:
                            p = psutil.Process(conn.pid)
                            proc = {
                                "name": p.name()[:50],
                                "cmd": " ".join(p.cmdline())[:200],
                                "entropy_cmd": self.shannon_entropy(" ".join(p.cmdline()))
                            }
                        except:
                            proc = {"name": "unknown", "cmd": "", "entropy_cmd": 0.0}
                        with self.lock:
                            if key not in self.flows:
                                self.flows[key] = {
                                    "process": proc,
                                    "dst_ip": conn.raddr.ip,
                                    "dst_port": conn.raddr.port,
                                    "pid": conn.pid or 0,
                                    "intervals": [],
                                    "last_seen": ts,
                                    "count": 0,
                                    "outbound_ratio": 0.0,
                                    "packet_sizes": [],
                                    "mitre_tactic": "Unknown"
                                }
                            flow = self.flows[key]
                            interval = ts - flow["last_seen"] if flow["count"] > 0 else 0
                            if interval > 0:
                                flow["intervals"].append(interval)
                            flow["last_seen"] = ts
                            flow["count"] += 1
                            flow["outbound_ratio"] = ((flow["outbound_ratio"] * (flow["count"] - 1)) + int(is_outbound)) / flow["count"]
                            flow["packet_sizes"].append(0)
                            if len(flow["intervals"]) > 500:
                                flow["intervals"].pop(0)
                            if len(flow["packet_sizes"]) > 500:
                                flow["packet_sizes"].pop(0)
            except Exception as fb_e:
                logger.error(f"Both snapshot methods failed: {fb_e}")

        cutoff = ts - MAX_FLOW_AGE
        with self.lock:
            for k in list(self.flows.keys()):
                if self.flows[k]["last_seen"] < cutoff:
                    del self.flows[k]

    def snapshot_db(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                       packet_size_mean, packet_size_std, packet_size_min, packet_size_max, mitre_tactic,
                       pid, cmd_entropy
                FROM flows WHERE timestamp > ?
            """, (time.time() - MAX_FLOW_AGE,))
            rows = cursor.fetchall()
            conn.close()

            with self.lock:
                for row in rows:
                    proc, dst, interval, cv, out_ratio, entropy, size_mean, size_std, size_min, size_max, tactic, pid, cmd_entropy = row
                    flow_key = (proc, dst)
                    if flow_key not in self.flows:
                        self.flows[flow_key] = {
                            "process_name": proc,
                            "dst_ip": dst,
                            "pid": pid,
                            "intervals": [],
                            "last_seen": time.time(),
                            "count": 0,
                            "outbound_ratio": 0.0,
                            "packet_sizes": [],
                            "mitre_tactic": tactic,
                            "cmd_entropy": cmd_entropy
                        }
                    flow = self.flows[flow_key]
                    if interval > 0:
                        flow["intervals"].append(interval)
                    flow["last_seen"] = time.time()
                    flow["count"] += 1
                    flow["outbound_ratio"] = out_ratio
                    flow["entropy"] = entropy
                    flow["packet_sizes"].append(size_mean)
                    if len(flow["intervals"]) > 500:
                        flow["intervals"].pop(0)
                    if len(flow["packet_sizes"]) > 500:
                        flow["packet_sizes"].pop(0)
        except Exception as e:
            logger.error(f"Error reading baseline.db: {e}")

    def analyze_flow(self, key, flow):
        now = time.time()
        last = self.last_analyzed.get(key, 0)
        if flow["count"] < 8 or (now - last < 30):  # raised min_samples
            return None
        self.last_analyzed[key] = now

        proc_name = flow.get("process_name", flow.get("process", {}).get("name", "unknown")).lower()
        raddr = flow["dst_ip"]
        port = flow.get("dst_port", 0)

        if any(b in proc_name for b in BENIGN_PROCESSES):
            return None
        if port in COMMON_PORTS and not any(s in proc_name for s in ["python", "bash", "sh", "powershell", "cmd", "unknown", "java"]):
            return None
        if any(raddr.startswith(prefix) for prefix in BENIGN_DESTINATIONS):
            return None

        try:
            deltas = flow["intervals"]
            mean_delta = float(np.mean(deltas)) if deltas else 0
            cv = float(np.std(deltas) / mean_delta) if mean_delta > 0 else 0
            min_samples = MIN_SAMPLES_SPARSE if mean_delta > LONG_SLEEP_THRESHOLD else 8
            if len(deltas) < min_samples - 1:
                return None

            entropy_ip = self.shannon_entropy(raddr)
            avg_cmd_entropy = flow.get("cmd_entropy", 0.0)
            unusual_port = port not in COMMON_PORTS and port > 1024
            outbound_ratio = flow["outbound_ratio"]

            flow_entropy = flow.get("entropy", max(entropy_ip, avg_cmd_entropy))
            entropy_list = [flow_entropy] * len(deltas)

            # domain + TTL for BeaconML
            domain = self.domain_cache.get(raddr, None)
            ttl_list = self.dns_resolutions.get(domain, {}).get("ttls", None) if domain else None

            ml_result, ml_confidence = detect_beaconing_list(
                deltas,
                payload_entropies=entropy_list,
                dst_ips=[raddr] * len(deltas),
                domain=domain,
                ttls=ttl_list,
                std_threshold=ML_STD_THRESHOLD,
                min_samples=8,
                use_dbscan=ML_USE_DBSCAN,
                use_isolation=ML_USE_ISOLATION,
                n_jobs=-1,
                max_samples=ML_MAX_SAMPLES
            )

            score = 0
            reasons = []
            mitre = ("", "", "")

            if cv < 0.25 and mean_delta > 5:
                score += 30
                reasons.append("low_cv_periodic")

            if ml_result:
                score += 42 + (ml_confidence // 4)  # reduced bonus, stricter
                reasons.append(f"Advanced_ML: {ml_result} (conf:{ml_confidence})")
                mitre = MITRE_MAP["beacon_periodic"]

            if outbound_ratio > 0.8 and cv < 0.25:
                score += 20
                reasons.append("consistent_outbound_malleable")

            if max(entropy_ip, avg_cmd_entropy) > 3.8:
                score += 25
                reasons.append("high_entropy")
                mitre = MITRE_MAP["high_entropy"]

            if unusual_port:
                score += 15
                reasons.append("unusual_port")
                mitre = MITRE_MAP["unusual_port"]

            if avg_cmd_entropy > 4.5:
                score += 20
                reasons.append("suspicious_process")
                mitre = MITRE_MAP["suspicious_process"]

            if USE_UEBA:
                proc_name_full = proc_name
                self.process_baselines[proc_name_full].append(mean_delta)
                if len(self.process_baselines[proc_name_full]) > 20:
                    baseline_lite = np.array(self.process_baselines[proc_name_full][-20:])
                    deviation_lite = abs(mean_delta - np.mean(baseline_lite)) / (np.std(baseline_lite) + 1e-6)
                    if deviation_lite > 4.0:
                        score += 25
                        reasons.append("ueba_deviation_lite")

                if baseline_model:
                    prefix = ".".join(raddr.split('.')[:3]) + ".0"
                    dt = datetime.fromtimestamp(now)
                    baseline_key = f"{proc_name_full}|{prefix}|{dt.hour:02d}|{1 if dt.weekday() >= 5 else 0}"
                    if baseline_key in baseline_model.get("profiles", {}):
                        stats = baseline_model["profiles"][baseline_key]["stats"]
                        interval_dev = abs(mean_delta - stats["mean_interval"]) / (stats["mean_interval"] + 1e-6)
                        cv_dev = abs(cv - stats["mean_cv"])
                        out_dev = abs(outbound_ratio - stats["mean_outbound_ratio"])
                        if interval_dev > 0.5 or cv_dev > 0.2 or out_dev > 0.3:
                            score += 25
                            reasons.append(f"ueba_deviation_advanced (Int:{interval_dev:.2f}, CV:{cv_dev:.2f}, Out:{out_dev:.2f})")

            # FP suppressor: short-lived flow penalty
            observed_duration = sum(deltas)
            if observed_duration < 180:
                score -= 15
            if len(deltas) < 10:
                score -= 12

            pid = flow.get("pid", 0)
            tree = self.get_process_tree(pid)
            tree_str = " → ".join([f"{name}({pid})" for pid, name, _ in tree])
            masquerade = False
            if len(tree) > 1:
                leaf_name = tree[-1][1]
                leaf_exe = tree[-1][2]
                if leaf_exe and leaf_name != os.path.basename(leaf_exe) and not leaf_name.startswith('['):
                    masquerade = True
                    score += 25
                    reasons.append("process_masquerade")
                    mitre = MITRE_MAP["masquerade"]

            if score >= SCORE_THRESHOLD:
                anomaly = {
                    "timestamp": datetime.now().isoformat(),
                    "dst_ip": raddr,
                    "dst_port": port,
                    "process": proc_name,
                    "cmd_snippet": "",
                    "pid": int(pid),
                    "process_tree": tree_str,
                    "masquerade_detected": masquerade,
                    "avg_interval_sec": round(mean_delta, 2),
                    "cv": round(cv, 4),
                    "entropy": round(max(entropy_ip, avg_cmd_entropy), 3),
                    "outbound_ratio": round(outbound_ratio, 3),
                    "ml_result": ml_result,
                    "score": int(score),
                    "reasons": reasons,
                    "mitre_tactic": mitre[0],
                    "mitre_technique": mitre[1],
                    "mitre_name": mitre[2],
                    "description": f"C2 Beacon detected - {ml_result or 'Statistical match'}"
                }

                with open(DETECTION_LOG, "a") as f:
                    f.write(f"{datetime.now().isoformat()} [SCORE {score}] {anomaly['description']} → {raddr}:{port} ({anomaly['process']})\n")

                with open(ANOMALY_JSONL, "a") as f:
                    f.write(json.dumps(anomaly) + "\n")

                self.shipper.send(anomaly)

                return anomaly
            return None
        except Exception as e:
            logger.error(f"Flow analysis error: {e}")
            return None

    def run_analysis(self):
        with self.lock:
            current_flows = dict(self.flows)
        active_flows = {k: v for k, v in current_flows.items() if v["count"] >= 8}
        if len(active_flows) > 300:
            sorted_active = sorted(active_flows.items(), key=lambda item: item[1]["last_seen"], reverse=True)
            active_flows = dict(sorted_active[:300])

        new_anomalies = []
        for key, flow in active_flows.items():
            anomaly = self.analyze_flow(key, flow)
            if anomaly:
                new_anomalies.append(anomaly)
                self.detection_count += 1
                print(f"\033[91m[DETECTION #{self.detection_count}] {anomaly['description']}\033[0m")
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
        df = pd.DataFrame(self.anomalies)
        df.to_csv(ANOMALY_CSV, index=False)
        logger.info(f"Exported {len(self.anomalies)} anomalies to CSV in {self.output_dir}")

    def print_status(self):
        while self.running:
            with self.lock:
                active = len(self.flows)
            print(f"\r[MONITORING v3.0] Active flows: {active:5d} | Detections: {self.detection_count:4d} | "
                  f"Last: {datetime.now().strftime('%H:%M:%S')}", end="", flush=True)
            time.sleep(10)

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