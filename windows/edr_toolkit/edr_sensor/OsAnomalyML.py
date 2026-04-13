"""
==============================================================================================
SYSTEM:          Deep Sensor - Host Behavioral & ETW Telemetry Engine
COMPONENT:       OsAnomalyML.py (Behavioral Outlier Detection Daemon)
VERSION:         2.0
AUTHOR:          Robert Weber

DESCRIPTION:
An advanced mathematical engine designed to identify anomalous operating system
behavior, obfuscation, and zero-day persistence mechanisms that evade static
signatures. Operates as a headless daemon, communicating with the primary
Orchestrator via high-speed, lock-free STDIN/STDOUT Inter-Process Communication (IPC).

ALGORITHMIC APPROACH:
Host telemetry (registry writes, process spawns) is inherently sporadic, rendering
temporal clustering ineffective. This engine utilizes Isolation Forests (scikit-learn)
to evaluate host activity as multidimensional outliers against a rolling baseline.

AREAS OF FOCUS:
1. Cryptographic Entropy (T1027): Calculates Shannon Entropy on command lines
   and registry values to mathematically detect encrypted payloads.
2. Parent-Child Tuple Scoring: Evaluates the historical rarity of process execution
   chains (e.g., "winword.exe -> powershell.exe") dynamically for the specific host.
3. Ransomware Burst Detection: Stateful frequency tracking of I/O operations per PID
   to detect high-entropy mass file encryption bursts in under 1.0 seconds.
4. UEBA Baselining: Maintains persistent per-process rule frequency and entropy
   histograms in SQLite to enable adaptive suppression of repetitive false positives
   while preserving maximum visibility.

ARCHITECTURAL SAFETY:
Strictly enforces single-threaded execution for underlying C-libraries (OpenMP, MKL,
OpenBLAS) to prevent OS-level thread deadlocks during piped background execution.
The SQLite database is stored in the host Temp directory using Write-Ahead Logging (WAL)
to ensure maximum concurrency and evade the Orchestrator's strict folder-level DACL lockdowns.
==============================================================================================
"""

import sys
import os
import json
import math
import time
import warnings
import sqlite3
import re
import hashlib
from datetime import datetime
from collections import Counter, defaultdict
from sklearn.ensemble import IsolationForest
import numpy as np

# Suppress threading and warnings to maintain a clean STDOUT IPC pipe
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
warnings.filterwarnings("ignore")

def shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon Entropy of a given string.
    High entropy typically correlates with encrypted, packed, or obfuscated data.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    probs = [v / len(data) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def generate_structural_hash(parent: str, process: str, cmd: str, rule: str):
    """
    Dimensionality Expansion
    Strips dynamic elements (GUIDs, Hex, Timestamps, Temp paths) to identify the
    underlying structural behavior of a command, regardless of execution variance.
    """
    cmd_clean = cmd or ""
    # Strip GUIDs
    cmd_clean = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<GUID>', cmd_clean)
    # Strip Hex Addresses / Pointers
    cmd_clean = re.sub(r'\b0x[0-9a-fA-F]+\b', '<HEX>', cmd_clean)
    # Strip long numeric strings (Timestamps/PIDs)
    cmd_clean = re.sub(r'\b\d{6,}\b', '<NUM>', cmd_clean)
    # Normalize common temp directories to prevent bypassing via AppData randomization
    cmd_clean = re.sub(r'(?i)c:\\users\\[^\\]+\\appdata\\local\\temp\\[^\\]+', '<TEMP>', cmd_clean)

    raw_context = f"{parent}|{process}|{cmd_clean}|{rule}".lower()
    ctx_hash = hashlib.md5(raw_context.encode()).hexdigest()

    return ctx_hash, cmd_clean

class BehavioralEngine:
    def __init__(self):
        self.event_count = 0
        self.trusted_binaries = set()
        self.fit_counter = 0
        # Isolation Forest is initialized with a 1% contamination expectation
        self.clf = IsolationForest(n_estimators=50, contamination=0.01, random_state=42)
        self.history = []

        # Tuple rarity cache and PID state trackers
        self.tuple_freq = Counter()
        self.pid_io_tracker = {}

        # UEBA: persistent baselining parameters
        self.learning_events = 0
        self.learning_threshold = 800
        # Memory state now tracks full temporal statistics
        # Dict format: ctx_hash -> { count, last_seen, mean_delta, m2_delta, rule, process }
        self.ueba_baseline = {}
        # Thresholds
        self.suppression_count_min = 8
        self.decay_days = 14.0

        # GLOBAL RULE DEGRADATION: Tracks unique processes triggered per rule
        self.rule_process_map = defaultdict(set)

        secure_dir = r"C:\ProgramData\DeepSensor\Data"
        os.makedirs(secure_dir, exist_ok=True)
        self.db_path = os.path.join(secure_dir, "DeepSensor_UEBA.db")
        self.ueba_log_path = os.path.join(secure_dir, "DeepSensor_UEBA_Diagnostic.log")

        try:
            self.conn = sqlite3.connect(self.db_path)
            # WAL mode prevents database locking exceptions during high-frequency ETW ingestion.
            self.conn.execute("PRAGMA journal_mode = WAL;")
            self._init_db()
            self._load_baselines()
            # MUST print to stderr to prevent breaking PowerShell's JSON STDOUT pipe
            print(f"[UEBA] Database ready → {self.db_path}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[UEBA CRITICAL] Disk DB locked. Falling back to RAM: {e}", file=sys.stderr, flush=True)
            self.conn = sqlite3.connect(":memory:")
            self.conn.execute("PRAGMA journal_mode = WAL;")
            self._init_db()

    def _init_db(self):
        """Schema for Context Hashing and Welford's Algorithm data."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ueba_temporal_baselines (
                context_hash TEXT PRIMARY KEY,
                parent_process TEXT,
                process TEXT,
                rule TEXT,
                cmd_structure TEXT,
                event_count INTEGER DEFAULT 1,
                last_seen REAL,
                mean_delta REAL DEFAULT 0.0,
                m2_delta REAL DEFAULT 0.0
            )
        ''')
        self.conn.commit()

    def _load_baselines(self):
        """Loads and processes Time-Decay during startup."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT context_hash, process, rule, event_count, last_seen, mean_delta, m2_delta FROM ueba_temporal_baselines")

        now = time.time()
        for row in cursor.fetchall():
            ctx_hash, proc, rule, count, last_seen, mean_delta, m2_delta = row

            # DECAY LOGIC: If unseen for 14 days, reduce count or wipe it
            days_unseen = (now - last_seen) / 86400.0
            if days_unseen > self.decay_days:
                # Decay the count by half for every 14 days unseen
                decay_factor = int(days_unseen / self.decay_days)
                count = max(0, count - (4 * decay_factor))

            if count > 0:
                self.ueba_baseline[ctx_hash] = {
                    "count": count, "last_seen": last_seen,
                    "mean_delta": mean_delta, "m2_delta": m2_delta,
                    "rule": rule, "process": proc
                }
                self.rule_process_map[rule].add(proc)
            else:
                # Completely prune dead rules from the database
                self.conn.cursor().execute("DELETE FROM ueba_temporal_baselines WHERE context_hash = ?", (ctx_hash,))
                self.conn.commit()

    def _save_baseline(self, ctx_hash, parent, proc, rule, cmd_struct, data):
        """Persist updated temporal statistics to SQLite."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO ueba_temporal_baselines
                (context_hash, parent_process, process, rule, cmd_structure, event_count, last_seen, mean_delta, m2_delta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(context_hash) DO UPDATE SET
                    event_count = excluded.event_count,
                    last_seen = excluded.last_seen,
                    mean_delta = excluded.mean_delta,
                    m2_delta = excluded.m2_delta
            """, (ctx_hash, parent, proc, rule, cmd_struct, data["count"], data["last_seen"], data["mean_delta"], data["m2_delta"]))
            #self.conn.commit()
        except Exception as e:
            print(f"[UEBA SAVE ERROR] {e}", file=sys.stderr, flush=True)

    def _log_ueba_audit(self, action, proc, rule, count, std_dev=0.0):
        try:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            log_entry = f"[{ts}] [{action.ljust(12)}] PROC: {proc.ljust(20)} | RULE: {rule} | CNT: {count} | STDEV: {round(std_dev, 2)}s\n"
            with open(self.ueba_log_path, 'a') as f:
                f.write(log_entry)
        except Exception:
            pass

    def extract_features(self, event):
        """
        Translates raw ETW JSON events into a structured numerical feature array.
        """
        text_data = event.get("Cmd", "") + event.get("Path", "")
        entropy = shannon_entropy(text_data)

        proc_name = event.get("Process", "unknown").lower()
        parent_name = event.get("Parent", "unknown").lower()

        # Parent-Child Lineage Scoring (Tuple Hashing)
        # Replaces flat LOLBin flags with dynamic, host-specific lineage rarity
        pc_tuple = f"{parent_name}->{proc_name}" if parent_name else f"unknown->{proc_name}"
        self.tuple_freq[pc_tuple] += 1

        # Inverse frequency: 1.0 for newly seen, approaches 0 for common host behavior
        tuple_score = 1.0 / self.tuple_freq[pc_tuple]

        path_depth = float(event.get("Path", "").count("\\"))
        return [entropy, tuple_score, path_depth]

    def evaluate_batch(self, events, pressure=0):
        if not events:
            return []

        features = []
        valid_events = []
        alerts = []

        for evt in events:
            # Intercept Orchestrator Health Check
            if evt.get("Type") == "Synthetic_Health_Check":
                alerts.append({"process": "System", "pid": 0, "tid": 0, "score": 1.0, "reason": "HEALTH_OK"})
                continue

            pid = evt.get("PID", 0)
            evt_type = evt.get("Type", "")

            # === THRESHOLD OVERRIDE ===
            # These are real attack TTPs. NEVER baselined. Instant high-confidence alerts.
            if evt_type in ["ProcessStart", "RegistryWrite", "FileIOCreate"]:
                cmd = (evt.get("Cmd") or "").lower()
                proc = (evt.get("Process") or "").lower()

                # 1. LSASS Credential Dumping
                lsass_dump_keywords = [
                    "procdump.*-ma.*lsass", "procdump.*-mm.*lsass",          # ProcDump classic
                    "comsvcs.dll.*minidump", "rundll32.*comsvcs.*minidump",  # comsvcs LOLBin
                    "mimikatz", "sekurlsa::", "lsadump::",                   # Mimikatz family
                    "nanodump", "dumpert", "handlekatz", "ppldump", "lsassy", "sharpdump",
                    "createdump.exe", "out-minidump"
                ]
                if any(k in cmd for k in lsass_dump_keywords):
                    alerts.append({
                        "process": proc, "pid": pid, "tid": evt.get("TID", 0),
                        "score": 10.0,
                        "reason": "CRITICAL: LSASS Credential Dumping (Static Override)"
                    })
                    continue

                # 2. Reflective / Process Injection in high-value system processes
                if proc in ["svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe", "services.exe"]:
                    injection_keywords = [
                        "virtualalloc", "createremotethread", "writeprocessmemory",
                        "reflective", "manualmap", "processhollow", "inject.*dll",
                        "dllinject", "sharpinjector"
                    ]
                    if any(k in cmd for k in injection_keywords):
                        alerts.append({
                            "process": proc, "pid": pid, "tid": evt.get("TID", 0),
                            "score": 10.0,
                            "reason": "CRITICAL: Reflective Code Injection (Static Override)"
                        })
                        continue

                # 3. High-confidence Lateral Movement & Post-Exploitation
                lateral_keywords = [
                    "psexec", "wmiexec", "invoke-mimikatz", "invoke-bloodhound",
                    "sharpwmi", "crackmapexec", "smbexec", "invoke-mimikatz"
                ]
                if any(k in cmd for k in lateral_keywords):
                    alerts.append({
                        "process": proc, "pid": pid, "tid": evt.get("TID", 0),
                        "score": 10.0,
                        "reason": "CRITICAL: Known Lateral Movement / Credential TTP (Static Override)"
                    })
                    continue

            # Ransomware / Wiper Burst Detection
            if evt_type in ["FileIOCreate", "FileIOWrite"]:
                now = time.time()
                path_entropy = shannon_entropy(evt.get("Path", ""))

                if pid not in self.pid_io_tracker:
                    self.pid_io_tracker[pid] = {"count": 1, "start_time": now, "entropy_sum": path_entropy}
                else:
                    tracker = self.pid_io_tracker[pid]
                    tracker["count"] += 1
                    tracker["entropy_sum"] += path_entropy

                    elapsed = now - tracker["start_time"]
                    if elapsed > 1.0:
                        # Reset the rolling 1-second window
                        tracker["count"] = 1
                        tracker["start_time"] = now
                        tracker["entropy_sum"] = path_entropy
                    else:
                        # If >50 I/O operations occur in <1 second with avg entropy > 5.2
                        if tracker["count"] > 50:
                            avg_entropy = tracker["entropy_sum"] / tracker["count"]
                            if avg_entropy > 5.2:
                                alerts.append({
                                    "process": evt.get("Process", "Unknown"),
                                    "pid": pid,
                                    "tid": evt.get("TID", 0),
                                    "score": round(avg_entropy, 2),
                                    "reason": f"Ransomware/Wiper Burst: {tracker['count']} I/O ops/sec (Entropy: {round(avg_entropy, 2)})"
                                })
                                tracker["count"] = 1 # Prevent alert flooding

            # ML Feature Extraction
            f = self.extract_features(evt)
            if f:
                features.append(f)
                valid_events.append(evt)

                entropy_score = f[0]
                proc_name = evt.get("Process", "Unknown")

                # ---------------------------------------------------------
                # MULTI-TIERED ENTROPY EVALUATION
                # ---------------------------------------------------------
                # Ensure JSON nulls (Python None) are safely cast to empty strings
                cmd_str = evt.get("Cmd") or ""
                path_str = evt.get("Path") or ""
                text_len = len(cmd_str + path_str)

                # DEVELOPER NOTE: Strings under 50 characters lack sufficient data
                # points for reliable Shannon Entropy baselining and are ignored
                # for static alerting (but still passed to the Isolation Forest).
                if text_len > 50:

                    # 1. CRITICAL TIER (> 5.5): Cryptographic Randomness
                    if entropy_score > 5.5:
                        # Restrict to execution/persistence to avoid ZIP/7z File I/O False Positives
                        if evt_type in ["ProcessStart", "RegistryWrite"]:
                            alerts.append({
                                "process": proc_name, "pid": pid, "tid": evt.get("TID", 0), "score": round(entropy_score, 2),
                                "reason": f"Critical Entropy: Highly random/encrypted data detected in {evt_type}"
                            })

                    # 2. HIGH TIER (5.2 - 5.5): Base64 & Packed Payloads
                    elif entropy_score > 5.2:
                        if evt_type in ["ProcessStart", "RegistryWrite"]:
                            alerts.append({
                                "process": proc_name, "pid": pid, "tid": evt.get("TID", 0), "score": round(entropy_score, 2),
                                "reason": f"T1027: Suspicious packed/encoded payload in {evt_type}"
                            })

                # 3. MODERATE TIER (4.0 - 5.2):
                # We do not fire static alerts here. Instead, we let the Isolation
                # Forest (clf.predict) evaluate this entropy score against the
                # historical Tuple Lineage. If the process is rare AND the entropy
                # is moderate, the ML engine will naturally flag it as an anomaly below.

            # UEBA: Route StaticAlerts through the temporal baselining engine
            if evt.get("Category") == "StaticAlert":
                self.learning_events += 1
                proc = evt.get("Process", "unknown").lower()
                parent = evt.get("Parent", "unknown").lower()
                cmd = evt.get("Cmd", "")
                details = evt.get("Details", "")
                evt_type = evt.get("Type", "StaticAlert")
                pid = evt.get("PID", 0)
                tid = evt.get("TID", 0)

                rule = "UnknownRule"
                if "Rule:" in details:
                    rule = details.split("Rule:")[1].split("[")[0].strip()
                elif "Match:" in details:
                    rule = details.split("Match:")[1].strip()
                else:
                    rule = evt_type

                # --- GLOBAL DEGRADATION CHECK ---
                self.rule_process_map[rule].add(proc)
                spread_count = len(self.rule_process_map[rule])
                if spread_count >= 5:
                    alerts.append({
                        "process": "GLOBAL", "pid": 0, "tid": 0, "score": -2.0, "reason": rule
                    })
                    continue

                # --- Time-Series Velocity Tracking ---
                ctx_hash, cmd_struct = generate_structural_hash(parent, proc, cmd, rule)
                now = time.time()

                if ctx_hash not in self.ueba_baseline:
                    # First time seeing this exact structural execution
                    self.ueba_baseline[ctx_hash] = {
                        "count": 1, "last_seen": now,
                        "mean_delta": 0.0, "m2_delta": 0.0,
                        "rule": rule, "process": proc
                    }
                    self._log_ueba_audit("LEARNING", proc, rule, 1)
                    alerts.append({
                        "process": proc, "pid": pid, "tid": tid, "score": 0.0,
                        "reason": f"{evt_type}: {rule} (New Context Hash)"
                    })
                    continue

                # Welford's Online Algorithm for Time Delta Variance
                b_data = self.ueba_baseline[ctx_hash]
                delta_t = now - b_data["last_seen"]

                b_data["count"] += 1
                b_data["last_seen"] = now

                # Update running variance
                count = b_data["count"]
                delta_mean = delta_t - b_data["mean_delta"]
                b_data["mean_delta"] += delta_mean / count
                delta_mean2 = delta_t - b_data["mean_delta"]
                b_data["m2_delta"] += delta_mean * delta_mean2

                # Calculate Standard Deviation of Execution Intervals
                variance = b_data["m2_delta"] / (count - 1) if count > 1 else 0.0
                std_dev = math.sqrt(variance)

                # Pass the baseline update to the SQLite engine immediately.
                # The actual disk write is safely batched/flushed by the outer event loop.
                self._save_baseline(ctx_hash, parent, proc, rule, cmd_struct, b_data)

                # --- HIGH-FIDELITY SUPPRESSION DECISION ---
                # To suppress, it must meet the minimum occurrence count AND exhibit predictable behavior.
                # If standard deviation is low (< 300 seconds variance), it's highly automated.
                # If variance is high (human-driven), we demand a much higher count (e.g., 20) before trusting it.

                is_automated = std_dev < 300.0
                trust_threshold = self.suppression_count_min if is_automated else (self.suppression_count_min * 2.5)

                if count < trust_threshold:
                    self._log_ueba_audit("LEARNING", proc, rule, count, std_dev)
                    alerts.append({
                        "process": proc, "pid": pid, "tid": tid, "score": 0.0,
                        "reason": f"{evt_type}: {rule} (Learning: {count}/{int(trust_threshold)})"
                    })
                elif count == int(trust_threshold):
                    self._log_ueba_audit("THRESHOLD", proc, rule, count, std_dev)
                    alerts.append({
                        "process": proc, "pid": pid, "tid": tid, "score": -1.0,
                        "reason": f"UEBA SECURED: {rule} | Mode: {'Automated' if is_automated else 'Manual'} Baseline."
                    })
                else:
                    self._log_ueba_audit("SUPPRESSED", proc, rule, count, std_dev)

                continue

        # Accrue initial baseline before applying predictions
        if len(features) < 10 and len(self.history) < 50:
            self.history.extend(features)
            return alerts

        X = np.array(features)
        try:
            # Only re-fit the model periodically to prevent IPC freezing
            if not hasattr(self, 'fit_counter'): self.fit_counter = 0

            # DYNAMIC BURST THROTTLE
            # If queue pressure > 10k events, we delay the CPU-heavy re-fit
            # until 50k events to prioritize ingestion speed.
            fit_threshold = 50000 if pressure > 10000 else 10000

            self.fit_counter += len(features)
            if self.fit_counter >= fit_threshold or len(self.history) < 100:
                self.clf.fit(np.array(self.history + features))
                self.fit_counter = 0 # Reset counter

            predictions = self.clf.predict(X)
            scores = self.clf.decision_function(X)
        except Exception as e:
            return alerts

        # Maintain rolling window of 5000 executions
        self.history.extend(features)
        if len(self.history) > 5000:
            self.history = self.history[-5000:]

        alerts = []
        for i, pred in enumerate(predictions):
            # Only process mathematical outliers
            if pred == -1 and scores[i] < -0.10:
                evt = valid_events[i]
                proc = evt.get("Process", "Unknown").lower()

                # A. Convert raw Isolation Forest score to a 0-100% Confidence Metric
                # More negative scores = higher anomaly confidence.
                raw_score = float(scores[i])
                confidence = min(100.0, round(abs(raw_score) * 450, 1))

                # B. Map Confidence to Severity Tiers
                if confidence >= 90:
                    severity = "CRITICAL"
                elif confidence >= 75:
                    severity = "HIGH"
                elif confidence >= 50:
                    severity = "WARNING"
                else:
                    severity = "AUDIT"

                # C. Contextual Downgrading (The "Noise Filter")
                # If a trusted system binary is the source, we downgrade it to prevent auto-isolation.
                if proc in self.trusted_binaries:
                    if severity == "CRITICAL":
                        severity = "HIGH"
                        details = f"Behavioral Outlier (Trusted Context): Anomalous {evt.get('Type')} chain by {proc}"
                    else:
                        severity = "AUDIT"
                        details = f"Known Noise: Anomalous {evt.get('Type')} chain by {proc}"
                else:
                    details = f"Behavioral Lineage Outlier: Anomalous {evt.get('Type')} chain by {proc}"

                alerts.append({
                    "process": proc,
                    "pid": evt.get("PID", 0),
                    "tid": evt.get("TID", 0),
                    "score": round(raw_score, 3),
                    "confidence": confidence,
                    "severity": severity,
                    "reason": details
                })

        return alerts

if __name__ == "__main__":
    engine = BehavioralEngine()
    engine.event_count = 0 # Initialize micro-batch counter
    engine.trusted_binaries = set() # Initialize dynamic trust list

    # 1. IPC Authentication (Blocking)
    first_line = sys.stdin.readline().strip()
    if not first_line.startswith("AUTH:"):
        sys.exit(1)

    # 2. IPC Configuration Ingestion (Blocking)
    config_line = sys.stdin.readline().strip()
    if config_line.startswith("CONFIG:"):
        try:
            config_data = json.loads(config_line[7:])
            engine.trusted_binaries = set(config_data.get("trusted_binaries", []))
        except Exception:
            pass

    # 3. Signal Readiness (Safe to proceed now that both sides are synced)
    print(f"[PYTHON_PID] {os.getpid()}", file=sys.stderr, flush=True)

    # 4. Lock-Free Evaluation Loop
    while True:
        line = sys.stdin.readline()

        # Shutdown Sequence
        if not line or line.strip() == "QUIT":
            if hasattr(engine, 'conn') and engine.conn:
                try:
                    engine.conn.commit() # Final flush to disk
                    engine.conn.close()
                except Exception:
                    pass
            break

        if not line.strip():
            continue

        try:
            payload = json.loads(line)

            # A. Strict Schema Extraction
            events = payload.get("events", [])
            pressure_level = payload.get("pressure", 0)

            # B. Single-Pass Evaluation (Resolves CPU Thrashing Bug)
            results = engine.evaluate_batch(events, pressure_level)

            # C. Micro-Batch DB Flush (Writes to disk only once every 50 batches)
            engine.event_count += 1
            if engine.event_count % 50 == 0:
                engine.conn.commit()

            # D. Return Alerts to Orchestrator
            print(json.dumps({"alerts": results}), flush=True)

        except Exception as e:
            print(json.dumps({"daemon_error": str(e)}), flush=True)