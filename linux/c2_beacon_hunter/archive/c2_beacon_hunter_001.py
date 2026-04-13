#!/usr/bin/env python3
"""
c2_beacon_hunter - Linux C2 Beacon Detector
Author: Robert Weber
Integrates BeaconML.py for advanced K-Means/DBSCAN/Isolation Forest detection on time intervals, plus statistical heuristics and optional DNS monitoring.
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
from collections import defaultdict, deque, Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import psutil

# Optional DNS monitoring
try:
    from scapy.all import sniff, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Advanced ML module
from BeaconML import detect_beaconing_list

# ====================== CONFIG ======================
config = configparser.ConfigParser()
config.read('config.ini')

SNAPSHOT_INTERVAL = int(config.get('general', 'snapshot_interval', fallback=60))
ANALYZE_INTERVAL = int(config.get('general', 'analyze_interval', fallback=300))
SCORE_THRESHOLD = int(config.get('general', 'score_threshold', fallback=45))
MAX_FLOW_AGE = int(config.get('general', 'max_flow_age_hours', fallback=12)) * 3600
MAX_FLOWS = int(config.get('general', 'max_flows', fallback=5000))
OUTPUT_DIR = config.get('general', 'output_dir', fallback='output')

ML_STD_THRESHOLD = float(config.get('ml', 'std_threshold', fallback=10.0))
ML_USE_DBSCAN = config.getboolean('ml', 'use_dbscan', fallback=True)
ML_USE_ISOLATION = config.getboolean('ml', 'use_isolation', fallback=True)
ML_MAX_SAMPLES = int(config.get('ml', 'max_samples', fallback=2000))

Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# ====================== CONTAINER DETECTION ======================
IN_CONTAINER = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')

# ====================== LOGGING ======================
logger = logging.getLogger("c2_beacon_hunter")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.handlers.RotatingFileHandler(
    f"{OUTPUT_DIR}/c2_beacon_hunter.log", maxBytes=20*1024*1024, backupCount=5
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

if IN_CONTAINER:
    logger.info("=== RUNNING INSIDE DOCKER/PODMAN CONTAINER WITH HOST ACCESS ===")

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
        self.flows = defaultdict(lambda: deque(maxlen=300))   # memory-capped
        self.last_analyzed = {}
        self.anomalies = []
        self.running = True
        self.lock = threading.Lock()
        self.detection_count = 0
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        if SCAPY_AVAILABLE:
            threading.Thread(target=self._dns_sniffer, daemon=True).start()

    def shutdown(self, *args):
        self.running = False
        logger.info("Shutting down gracefully...")
        self.export_all()
        sys.exit(0)

    def shannon_entropy(self, data):
        if not data:
            return 0.0
        counts = Counter(data)
        probs = [v / len(data) for v in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def get_process_tree(self, pid):
        """Full parent chain for masquerading detection"""
        tree = []
        try:
            current = psutil.Process(pid)
            while current:
                exe = current.exe() if hasattr(current, 'exe') and current.exe() else "unknown"
                tree.append((current.pid, current.name(), exe))
                current = current.parent()
        except:
            pass
        return tree[::-1]  # root → leaf

    def _dns_sniffer(self):
        def pkt_handler(pkt):
            if DNSQR in pkt:
                domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                with self.lock:
                    if not hasattr(self, 'dns_queries'):
                        self.dns_queries = []
                    self.dns_queries.append((time.time(), domain))
        try:
            sniff(filter="udp port 53", prn=pkt_handler, store=0, timeout=0)
        except:
            pass

    def snapshot(self):
        """Primary: fast ss -tupn → fallback to psutil"""
        ts = time.time()
        try:
            output = subprocess.check_output(["ss", "-tupn", "--numeric"], timeout=3).decode('utf-8', errors='ignore')
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6 or "ESTAB" not in parts[0]:
                    continue
                local = parts[3]
                remote = parts[4]
                if ':' not in remote:
                    continue
                raddr, rport_str = remote.rsplit(':', 1)
                if raddr in ("127.0.0.1", "::1"):
                    continue
                rport = int(rport_str)
                pid = 0
                if len(parts) > 5 and "pid=" in parts[-1]:
                    try:
                        pid = int(parts[-1].split("pid=")[1].split(",")[0])
                    except:
                        pass
                key = (local, raddr, rport)
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
                    self.flows[key].append((ts, pid, proc))
        except Exception as e:
            logger.warning(f"ss snapshot failed ({e}), falling back to psutil")
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if (conn.status == psutil.CONN_ESTABLISHED and
                        conn.raddr and conn.raddr.ip not in ("127.0.0.1", "::1")):
                        key = (str(conn.laddr), conn.raddr.ip, conn.raddr.port)
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
                            self.flows[key].append((ts, conn.pid or 0, proc))
            except Exception as fb_e:
                logger.error(f"Both snapshot methods failed: {fb_e}")

        # Prune old data
        cutoff = ts - MAX_FLOW_AGE
        with self.lock:
            for k in list(self.flows.keys()):
                self.flows[k] = deque((e for e in self.flows[k] if e[0] > cutoff), maxlen=300)
            if len(self.flows) > MAX_FLOWS:
                sorted_keys = sorted(self.flows.keys(), key=lambda k: len(self.flows[k]), reverse=True)
                self.flows = defaultdict(lambda: deque(maxlen=300), {k: self.flows[k] for k in sorted_keys[:MAX_FLOWS]})

    def analyze_flow(self, key, events):
        now = time.time()
        last = self.last_analyzed.get(key, 0)
        if len(events) < 5 or (now - last < 30):
            return None
        self.last_analyzed[key] = now

        try:
            timestamps = np.array([e[0] for e in events])
            deltas = np.diff(np.sort(timestamps)).tolist()
            mean_delta = float(np.mean(deltas))
            cv = float(np.std(deltas) / mean_delta) if mean_delta > 0 else 0

            raddr = key[1]
            entropy_ip = self.shannon_entropy(raddr)
            avg_cmd_entropy = float(np.mean([e[2].get("entropy_cmd", 0) for e in events]))
            port = key[2]
            unusual_port = port not in COMMON_PORTS and port > 1024

            # Advanced ML (BeaconML with adaptive DBSCAN)
            ml_result = detect_beaconing_list(
                deltas,
                std_threshold=ML_STD_THRESHOLD,
                min_samples=3,
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
            if "Beaconing" in ml_result:
                score += 60
                reasons.append(f"Advanced_ML: {ml_result}")
                mitre = MITRE_MAP["beacon_periodic"]
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

            # Process tree + masquerading detection
            pid = events[0][1]
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
                    "dst_port": int(port),
                    "process": events[0][2].get("name", "unknown"),
                    "cmd_snippet": events[0][2].get("cmd", "")[:100],
                    "pid": int(pid),
                    "process_tree": tree_str,
                    "masquerade_detected": masquerade,
                    "avg_interval_sec": round(mean_delta, 2),
                    "cv": round(cv, 4),
                    "entropy": round(max(entropy_ip, avg_cmd_entropy), 3),
                    "ml_result": ml_result,
                    "score": int(score),
                    "reasons": reasons,
                    "mitre_tactic": mitre[0],
                    "mitre_technique": mitre[1],
                    "mitre_name": mitre[2],
                    "description": f"C2 Beacon detected - {ml_result or 'Statistical match'}"
                }
                with open(DETECTION_LOG, "a") as f:
                    f.write(f"{datetime.now().isoformat()} [SCORE {score}] {anomaly['description']} "
                            f"→ {raddr}:{port} ({anomaly['process']})\n")
                return anomaly
            return None
        except Exception as e:
            logger.error(f"Flow analysis error: {e}")
            return None

    def run_analysis(self):
        with self.lock:
            current_flows = dict(self.flows)
        new_anomalies = []
        for key, events in current_flows.items():
            if len(events) >= 5:
                anomaly = self.analyze_flow(key, list(events))
                if anomaly:
                    new_anomalies.append(anomaly)
                    self.detection_count += 1
                    print(f"\033[91m[DETECTION #{self.detection_count}] {anomaly['description']}\033[0m")
                    logger.info(f"DETECTION: {anomaly['description']} Score={anomaly['score']}")
        if new_anomalies:
            self.anomalies.extend(new_anomalies)
            self.export_all()

    def export_all(self):
        if not self.anomalies:
            return
        df = pd.DataFrame(self.anomalies)
        df.to_csv(ANOMALY_CSV, index=False)
        with open(ANOMALY_JSONL, "w") as f:
            for a in self.anomalies:
                f.write(json.dumps(a) + "\n")
        logger.info(f"Exported {len(self.anomalies)} anomalies to {self.output_dir}")

    def print_status(self):
        while self.running:
            with self.lock:
                active = len(self.flows)
            print(f"\r[MONITORING v2.3] Active flows: {active:5d} | Detections: {self.detection_count:4d} | "
                  f"Last: {datetime.now().strftime('%H:%M:%S')}", end="", flush=True)
            time.sleep(10)

    def start(self):
        threading.Thread(target=self.snapshot_loop, daemon=True).start()
        threading.Thread(target=self.print_status, daemon=True).start()
        logger.info("c2_beacon_hunter v2.3 started")
        print(f"Output directory: {self.output_dir} | Ctrl+C to stop")
        try:
            while self.running:
                self.run_analysis()
                time.sleep(ANALYZE_INTERVAL)
        except Exception as e:
            logger.critical(f"Main loop error: {e}")

    def snapshot_loop(self):
        while self.running:
            self.snapshot()
            time.sleep(SNAPSHOT_INTERVAL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="c2_beacon_hunter v2.3")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help="Output directory for logs/CSV/JSON")
    args = parser.parse_args()
    hunter = BeaconHunter(output_dir=args.output_dir)
    hunter.start()