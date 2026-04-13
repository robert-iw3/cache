#!/usr/bin/env python3
"""
baseline_learner.py - v3.0 Subnet Clustering Edition
CIDR-based baselines (/24 IPv4, /64 IPv6) + subnet-level UEBA.
Dual-backend support (SQLite or Postgres).
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
import configparser
import psycopg2
import psycopg2.pool
from BeaconML import _normalize_cidr

DB_TYPE = "sqlite"  # default
DB_PATH = Path("data/baseline.db")
MODEL_PATH = Path("data/baseline_model.joblib")

LEARNING_INTERVAL = 3600
RETENTION_DAYS = 30
BATCH_SIZE = 500  # 500 for high-volume environments
QUEUE_TIMEOUT = 1.0

class BaselineLearner:
    def __init__(self):
        self.db = None
        self.db_type = None
        self.db_conn_params = None
        self.pool = None
        self._load_config()
        self._connect_db()
        self._init_db()
        self._create_indexes()
        self.flow_queue = queue.Queue()
        self.running = True
        self.writer_thread = threading.Thread(target=self._queue_writer, daemon=True)
        self.writer_thread.start()

    def _load_config(self):
        """Robust config loading for backend type."""
        try:
            parser = configparser.ConfigParser()
            parser.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])
            self.db_type = parser.get('database', 'type', fallback='sqlite').lower()
            if self.db_type == 'postgres':
                self.db_conn_params = {
                    "dbname": parser.get('postgres', 'dbname', fallback='c2_beacon_hunter'),
                    "user": parser.get('postgres', 'user', fallback='user'),
                    "password": parser.get('postgres', 'password', fallback='password'),
                    "host": parser.get('postgres', 'host', fallback='localhost'),
                    "port": parser.get('postgres', 'port', fallback=5432)
                }
            print(f"[BaselineLearner] Using {self.db_type.upper()} backend")
        except Exception as e:
            print(f"[WARNING] Config error: {e} — defaulting to SQLite")
            self.db_type = 'sqlite'

    def _connect_db(self):
        """Connect to selected backend with error handling."""
        try:
            if self.db_type == 'postgres':
                self.pool = psycopg2.pool.SimpleConnectionPool(1, 10, **self.db_conn_params)
                self.db = self.pool.getconn()
            else:
                self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
                self.db.execute('PRAGMA journal_mode=WAL;')
        except Exception as e:
            print(f"[ERROR] DB connection failed: {e}")
            raise

    def _get_cursor(self):
        if self.db_type == 'postgres':
            return self.db.cursor()
        return self.db.cursor()

    def _commit_and_return_conn(self):
        if self.db_type == 'postgres':
            self.db.commit()
            self.pool.putconn(self.db)
            self.db = self.pool.getconn()  # Get fresh conn from pool
        else:
            self.db.commit()

    def _init_db(self):
        cursor = self._get_cursor()
        if self.db_type == 'postgres':
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id SERIAL PRIMARY KEY,
                    timestamp DOUBLE PRECISION,
                    process_name TEXT,
                    dst_ip TEXT,
                    interval DOUBLE PRECISION,
                    cv DOUBLE PRECISION,
                    outbound_ratio DOUBLE PRECISION,
                    entropy DOUBLE PRECISION,
                    packet_size_mean DOUBLE PRECISION,
                    packet_size_std DOUBLE PRECISION,
                    packet_size_min DOUBLE PRECISION,
                    packet_size_max DOUBLE PRECISION,
                    mitre_tactic TEXT,
                    pid INTEGER,
                    cmd_entropy DOUBLE PRECISION,
                    suppressed INTEGER DEFAULT 0
                )
            """)
        else:
            cursor.execute("""
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
                    cmd_entropy REAL,
                    suppressed INTEGER DEFAULT 0
                )
            """)
        self._commit_and_return_conn()

    def _create_indexes(self):
        cursor = self._get_cursor()
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON flows (dst_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows (timestamp)")
        self._commit_and_return_conn()

    def record_flow(self, **kwargs):
        self.flow_queue.put(kwargs)

    def _queue_writer(self):
        while self.running or not self.flow_queue.empty():
            batch = []
            while len(batch) < BATCH_SIZE and (item := self.flow_queue.get(timeout=QUEUE_TIMEOUT)):
                batch.append((
                    time.time(),
                    item.get('process_name', 'unknown'),
                    item.get('dst_ip', '0.0.0.0'),
                    item.get('interval', 0.0),
                    item.get('cv', 0.0),
                    item.get('outbound_ratio', 0.0),
                    item.get('entropy', 0.0),
                    item.get('packet_size_mean', 0.0),
                    item.get('packet_size_std', 0.0),
                    item.get('packet_size_min', 0.0),
                    item.get('packet_size_max', 0.0),
                    item.get('mitre_tactic', 'Unknown'),
                    item.get('pid', 0),
                    item.get('cmd_entropy', 0.0),
                    item.get('suppressed', 0)
                ))

            if batch:
                cursor = self._get_cursor()
                try:
                    cursor.executemany("""
                        INSERT INTO flows (timestamp, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                                           packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                                           mitre_tactic, pid, cmd_entropy, suppressed)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    self._commit_and_return_conn()
                except Exception as e:
                    print(f"[ERROR] Batch insert failed: {e}")

    def learn(self):
        try:
            cursor = self._get_cursor()
            cursor.execute("SELECT * FROM flows WHERE timestamp > ?", (time.time() - 86400,))
            rows = cursor.fetchall()

            profiles = defaultdict(lambda: {
                "intervals": [], "cvs": [], "outbound_ratios": [], "entropies": [], "packet_means": [],
                "mitre_tactics": Counter()
            })

            for row in rows:
                timestamp, process_name, dst_ip, interval, cv, outbound_ratio, entropy, \
                packet_size_mean, packet_size_std, packet_size_min, packet_size_max, \
                mitre_tactic, pid, cmd_entropy, suppressed = row

                cidr = _normalize_cidr(dst_ip)
                key = f"{cidr}|{process_name}"

                profiles[key]["intervals"].append(interval)
                profiles[key]["cvs"].append(cv)
                profiles[key]["outbound_ratios"].append(outbound_ratio)
                profiles[key]["entropies"].append(entropy)
                profiles[key]["packet_means"].append(packet_size_mean)
                profiles[key]["mitre_tactics"][mitre_tactic] += 1

            model = {"profiles": {}}
            for key, prof in profiles.items():
                # Early exit for low-data profiles (<5 samples) with debug log
                if len(prof["intervals"]) < 5:
                    print(f"[DEBUG] Skipped low-data profile: {key} ({len(prof['intervals'])} samples)")
                    continue

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
                    self._commit_and_return_conn()

            joblib.dump(model, MODEL_PATH)
            print(f"[{datetime.now()}] Subnet baseline updated with {len(model['profiles'])} CIDR profiles")

        except Exception as e:
            print(f"[ERROR] Subnet learning failed: {e}")

    def cleanup_old_data(self):
        try:
            cursor = self._get_cursor()
            cutoff = time.time() - 86400 * RETENTION_DAYS
            cursor.execute("DELETE FROM flows WHERE timestamp < ?", (cutoff,))
            self._commit_and_return_conn()
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
        if self.pool:
            self.pool.closeall()

if __name__ == "__main__":
    learner = BaselineLearner()
    try:
        learner.run()
    except KeyboardInterrupt:
        learner.stop()