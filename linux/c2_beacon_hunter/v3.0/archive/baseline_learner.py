#!/usr/bin/env python3
"""
baseline_learner.py - v3.0 Subnet Clustering Edition (Epic 3)
CIDR-based baselines (/24 IPv4, /64 IPv6) + subnet-level UEBA.
Author: Robert Weber
"""

import sqlite3
import time
import numpy as np
from pathlib import Path
from collections import defaultdict, Counter
import threading
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib
import queue
import ipaddress  # ← CIDR normalization

DB_PATH = Path("data/baseline.db")
MODEL_PATH = Path("data/baseline_model.joblib")

LEARNING_INTERVAL = 3600
RETENTION_DAYS = 30
BATCH_SIZE = 200
QUEUE_TIMEOUT = 1.0

class BaselineLearner:
    def __init__(self):
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL;')
        self.db.execute('PRAGMA synchronous=NORMAL;')
        self.db.execute('PRAGMA cache_size=-64000;')
        self._init_db()
        self._create_indexes()
        self.flow_queue = queue.Queue()
        self.running = True
        self.writer_thread = threading.Thread(target=self._queue_writer, daemon=True)
        self.writer_thread.start()

    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
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
                cmd_entropy REAL,
                suppressed INTEGER DEFAULT 0
            )
        """)
        try:
            self.db.execute("ALTER TABLE flows ADD COLUMN suppressed INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        self.db.commit()

    def _create_indexes(self):
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_process_dst ON flows(process_name, dst_ip)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)")
        self.db.commit()

    def _queue_writer(self):
        while self.running or not self.flow_queue.empty():
            batch = []
            try:
                while len(batch) < BATCH_SIZE and self.running:
                    item = self.flow_queue.get(timeout=QUEUE_TIMEOUT)
                    batch.append(item)
            except queue.Empty:
                pass
            if batch:
                try:
                    self.db.executemany("""
                        INSERT INTO flows (timestamp, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                                           packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                                           mitre_tactic, pid, cmd_entropy, suppressed)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """, batch)
                    self.db.commit()
                except Exception as e:
                    print(f"[ERROR] Batch insert failed: {e}")

    def record_flow(self, process_name, dst_ip, interval=0.0, cv=0.0, outbound_ratio=0.0,
                    entropy=0.0, packet_size_mean=0, packet_size_std=0,
                    packet_size_min=0, packet_size_max=0, mitre_tactic="C2_Beaconing",
                    pid=0, cmd_entropy=0.0):
        try:
            ts = time.time()
            self.flow_queue.put((ts, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                                 packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                                 mitre_tactic, pid, cmd_entropy))
        except Exception as e:
            print(f"[ERROR] Queue put failed: {e}")

    def _normalize_cidr(self, ip: str) -> str:
        """Robust CIDR normalization with fallback."""
        try:
            if ':' in ip:  # IPv6
                return str(ipaddress.IPv6Network(ip + '/64', strict=False))
            else:  # IPv4
                return str(ipaddress.IPv4Network(ip + '/24', strict=False))
        except Exception:
            return ip  # safe fallback

    def learn(self):
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT * FROM flows WHERE suppressed = 0")
            data = cursor.fetchall()

            model = {"version": 3, "profiles": {}}
            profiles = defaultdict(lambda: {
                "intervals": [], "cvs": [], "outbound_ratios": [], "entropies": [],
                "packet_means": [], "packet_stds": [], "packet_mins": [], "packet_maxs": [],
                "mitre_tactics": Counter()
            })

            for row in data:
                ts, process_name, dst_ip, interval, cv, outbound_ratio, entropy, p_mean, p_std, p_min, p_max, tactic, pid, cmd_entropy, suppressed = row
                cidr_key = self._normalize_cidr(dst_ip)
                event_dt = datetime.fromtimestamp(ts)
                hour = event_dt.hour
                is_weekend = event_dt.weekday() >= 5
                key = f"{cidr_key}|{hour:02d}|{'weekend' if is_weekend else 'weekday'}"

                prof = profiles[key]
                prof["intervals"].append(interval)
                prof["cvs"].append(cv)
                prof["outbound_ratios"].append(outbound_ratio)
                prof["entropies"].append(entropy)
                prof["packet_means"].append(p_mean)
                prof["packet_stds"].append(p_std)
                prof["packet_mins"].append(p_min)
                prof["packet_maxs"].append(p_max)
                prof["mitre_tactics"][tactic] += 1

            for key, prof in profiles.items():
                if len(prof["intervals"]) < 5: continue

                model["profiles"][key] = {
                    "stats": {
                        "mean_interval": float(np.mean(prof["intervals"])),
                        "mean_cv": float(np.mean(prof["cvs"])),
                        "mean_outbound_ratio": float(np.mean(prof["outbound_ratios"])),
                        "mean_entropy": float(np.mean(prof["entropies"])),
                        "mean_packet_mean": float(np.mean(prof["packet_means"])),
                        "top_mitre": prof["mitre_tactics"].most_common(1)[0][0] if prof["mitre_tactics"] else "Unknown"
                    }
                }

                training_data = np.column_stack((
                    prof["intervals"], prof["cvs"], prof["entropies"]
                ))
                clf = IsolationForest(contamination=0.05, random_state=42)
                clf.fit(training_data)
                model["profiles"][key]["isolation_forest"] = clf

                # Stability suppression at subnet level
                stability = 1.0 - (np.std(prof["intervals"]) / (np.mean(prof["intervals"]) + 1e-6))
                if stability > 0.85:
                    cursor.execute("UPDATE flows SET suppressed = 1 WHERE dst_ip LIKE ? AND timestamp > ?",
                                   (key.split('|')[0] + '%', time.time() - 86400))
                    self.db.commit()

            joblib.dump(model, MODEL_PATH)
            print(f"[{datetime.now()}] Subnet baseline updated with {len(model['profiles'])} CIDR profiles")

        except Exception as e:
            print(f"[ERROR] Subnet learning failed: {e}")

    def cleanup_old_data(self):
        try:
            cutoff = time.time() - 86400 * RETENTION_DAYS
            self.db.execute("DELETE FROM flows WHERE timestamp < ?", (cutoff,))
            self.db.commit()
        except Exception as e:
            print(f"[ERROR] Cleanup failed: {e}")

    def run(self):
        while self.running:
            try:
                self.learn()
                self.cleanup_old_data()
            except Exception as e:
                print(f"[ERROR] Learn cycle failed: {e}")
            time.sleep(LEARNING_INTERVAL)

    def stop(self):
        self.running = False
        self.writer_thread.join(timeout=3)


if __name__ == "__main__":
    learner = BaselineLearner()
    try:
        learner.run()
    except KeyboardInterrupt:
        learner.stop()