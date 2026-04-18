/*=============================================================================================
 * SYSTEM:          Deep Visibility Sensor v2.1
 * COMPONENT:       lib.rs (Native FFI Behavioral ML Engine)
 * AUTHOR:          Robert Weber
 *
 * DESCRIPTION:
 * Compiled as a C-compatible Dynamic Link Library (cdylib). This allows the C# ETW
 * sensor to bypass standard IO pipes entirely and directly map the Rust behavioral
 * math engine into its memory space via [DllImport].
 *============================================================================================*/

use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use md5::{Md5, Digest};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use extended_isolation_forest::{Forest, ForestOptions};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, Arc, RwLock};
use std::panic;
use std::backtrace::Backtrace;
use std::fs::OpenOptions;
use std::io::Write;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Deserialize, Debug, Clone)]
struct IncomingEvent {
    #[serde(alias = "Type", default)]
    event_type: String,
    #[serde(alias = "Category", default)]
    category: String,
    #[serde(alias = "Process", default)]
    process: String,
    #[serde(alias = "Parent", default)]
    parent: String,
    #[serde(alias = "Cmd", default)]
    cmd: String,
    #[serde(alias = "Path", default)]
    path: String,
    #[serde(alias = "Details", default)]
    details: String,
    #[serde(alias = "Destination", default)]
    destination: String,
    #[serde(alias = "Port", default)]
    port: i32,
    #[serde(alias = "PID", default)]
    pid: i32,
    #[serde(alias = "TID", default)]
    tid: i32,
}

#[derive(Serialize, Debug, Clone)]
pub struct Alert {
    pub process: String,
    pub parent: String,
    pub cmd: String,
    pub destination: String,
    pub port: i32,
    pub pid: i32,
    pub tid: i32,
    pub score: f64,
    pub confidence: f64,
    pub severity: String,
    pub reason: String,
}

// ARCHITECTURAL CLEANUP: Helper function for rapid alert generation
impl Alert {
    fn new(evt: &IncomingEvent, score: f64, confidence: f64, severity: &str, reason: String) -> Self {
        Alert {
            process: evt.process.clone(),
            parent: evt.parent.clone(),
            cmd: evt.cmd.clone(),
            destination: evt.destination.clone(),
            port: evt.port,
            pid: evt.pid,
            tid: evt.tid,
            score,
            confidence,
            severity: severity.to_string(),
            reason,
        }
    }
}

#[derive(Serialize, Debug)]
struct OutgoingResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<Vec<Alert>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_error: Option<String>,
}

struct UebaBaseline {
    count: i32,
    last_seen: f64,
    mean_delta: f64,
    m2_delta: f64,
}

struct IoTracker {
    count: i32,
    start_time: f64,
    entropy_sum: f64,
}

// ============================================================================
// BEHAVIORAL ENGINE
// ============================================================================

pub struct BehavioralEngine {
    trusted_binaries: HashSet<String>,
    tuple_freq: HashMap<String, i32>,
    pid_io_tracker: HashMap<i32, IoTracker>,
    ueba_baseline: HashMap<String, UebaBaseline>,
    rule_process_map: HashMap<String, HashSet<String>>,
    conn: Connection,
    history: Vec<[f64; 3]>,
    fit_counter: usize,
    cached_forest: Arc<RwLock<Option<Forest<f64, 3>>>>,
    is_training: Arc<RwLock<bool>>,
    suppression_count_min: i32,
    decay_days: f64,
    regex_guid: Regex,
    regex_hex: Regex,
    regex_num: Regex,
    regex_temp: Regex,
    regex_pipe: Regex,
    regex_hash: Regex,
}

impl BehavioralEngine {
    fn new() -> Self {
        let secure_dir = r"C:\ProgramData\DeepSensor\Data";
        std::fs::create_dir_all(secure_dir).unwrap_or_default();
        let db_path = format!(r"{}\DeepSensor_UEBA.db", secure_dir);

        let conn = Connection::open(&db_path).unwrap_or_else(|_| Connection::open_in_memory().unwrap());
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -64000;
            PRAGMA mmap_size = 3000000000;
            PRAGMA wal_autocheckpoint = 1000;
        ").expect("Failed to optimize SQLite DB pragmas");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ueba_temporal_baselines (
                context_hash TEXT PRIMARY KEY,
                parent_process TEXT,
                process TEXT,
                rule TEXT,
                target_struct TEXT,
                event_count INTEGER DEFAULT 1,
                last_seen REAL,
                mean_delta REAL DEFAULT 0.0,
                m2_delta REAL DEFAULT 0.0
            )",
            [],
        ).unwrap();

        let _ = conn.execute_batch("
            PRAGMA wal_checkpoint(FULL);
            PRAGMA optimize;
            VACUUM;
        ");

        let mut engine = BehavioralEngine {
            trusted_binaries: HashSet::new(),
            tuple_freq: HashMap::new(),
            pid_io_tracker: HashMap::new(),
            ueba_baseline: HashMap::new(),
            rule_process_map: HashMap::new(),
            conn,
            history: Vec::new(),
            fit_counter: 0,
            cached_forest: Arc::new(RwLock::new(None)),
            is_training: Arc::new(RwLock::new(false)),
            suppression_count_min: 8,
            decay_days: 14.0,
            regex_guid: Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
            regex_hex: Regex::new(r"(?i)\b0x[0-9a-f]+\b").unwrap(),
            regex_num: Regex::new(r"\b\d{6,}\b").unwrap(),
            regex_temp: Regex::new(r"(?i)c:\\users\\[^\\]+\\appdata\\local\\temp\\[^\\]+").unwrap(),
            regex_pipe: Regex::new(r"(?i)\\\\.\\pipe\\[\w.-]+").unwrap(),
            regex_hash: Regex::new(r"(?i)\b[a-f0-9]{16,64}\b").unwrap(),
        };

        engine.load_baselines();

        // Add known benign noise directly to trust
        let default_trust = ["svchost.exe", "wmiprvse.exe", "taskhostw.exe", "dllhost.exe", "msedge.exe", "chrome.exe"];
        for proc in default_trust.iter() {
            engine.trusted_binaries.insert(proc.to_string());
        }

        engine
    }

    fn load_baselines(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let mut stmt = self.conn.prepare("SELECT context_hash, process, rule, event_count, last_seen, mean_delta, m2_delta FROM ueba_temporal_baselines").unwrap();

        let baselines: Vec<_> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, i32>(3)?, row.get::<_, f64>(4)?, row.get::<_, f64>(5)?, row.get::<_, f64>(6)?))
        }).unwrap().filter_map(Result::ok).collect();

        for (ctx_hash, proc, rule, mut count, last_seen, mean_delta, m2_delta) in baselines {
            let days_unseen = (now - last_seen) / 86400.0;
            if days_unseen > self.decay_days {
                let decay_factor = (days_unseen / self.decay_days) as i32;
                count = std::cmp::max(0, count - (4 * decay_factor));
            }

            if count > 0 {
                self.ueba_baseline.insert(ctx_hash, UebaBaseline { count, last_seen, mean_delta, m2_delta });
                self.rule_process_map.entry(rule).or_insert_with(HashSet::new).insert(proc);
            } else {
                self.conn.execute("DELETE FROM ueba_temporal_baselines WHERE context_hash = ?", params![ctx_hash]).unwrap();
            }
        }
    }

    fn shannon_entropy(data: &str) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = HashMap::new();
        for c in data.chars() {
            *counts.entry(c).or_insert(0) += 1;
        }
        let len = data.len() as f64;
        counts.values().fold(0.0, |acc, &count| {
            let p = count as f64 / len;
            acc - (p * p.log2())
        })
    }

    fn generate_structural_hash(&self, parent: &str, process: &str, target_data: &str, rule: &str) -> (String, String) {
        let mut clean = self.regex_guid.replace_all(target_data, "<GUID>").to_string();
        clean = self.regex_hex.replace_all(&clean, "<HEX>").to_string();
        clean = self.regex_num.replace_all(&clean, "<NUM>").to_string();
        clean = self.regex_temp.replace_all(&clean, "<TEMP>").to_string();
        clean = self.regex_pipe.replace_all(&clean, "<PIPE>").to_string();
        clean = self.regex_hash.replace_all(&clean, "<HASH>").to_string();

        let raw_context = format!("{}|{}|{}|{}", parent, process, clean, rule).to_lowercase();
        let hash = hex::encode(Md5::digest(raw_context.as_bytes()));
        (hash, clean)
    }

    // UEBA Audit Logging
    fn log_ueba_audit(action: &str, proc: &str, rule: &str, count: i32, std_dev: f64) {
        let log_path = r"C:\ProgramData\DeepSensor\Data\DeepSensor_UEBA_Diagnostic.log";
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let entry = format!("[{}] [{:<12}] PROC: {:<20} | RULE: {} | CNT: {} | STDEV: {:.2}s",
                            ts, action, proc, rule, count, std_dev);

        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
            use std::io::Write;
            let _ = writeln!(file, "{}", entry);
        }
    }

    fn evaluate_single(&mut self, evt: IncomingEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

        if evt.event_type == "Synthetic_Health_Check" {
            alerts.push(Alert { process: "System".to_string(), parent: "".to_string(), cmd: "".to_string(), destination: "".to_string(), port: 0, pid: 0, tid: 0, score: 1.0, confidence: 100.0, severity: "INFO".to_string(), reason: "HEALTH_OK".to_string() });
            return alerts;
        }

        let cmd_lower = evt.cmd.to_lowercase();
        let proc_lower = evt.process.to_lowercase();

        // Static overrides
        if evt.event_type == "ProcessStart" || evt.event_type == "RegistryWrite" || evt.event_type == "FileIOCreate" {
            let lsass_keywords = ["procdump", "comsvcs", "mimikatz", "sekurlsa::", "lsadump::", "nanodump", "dumpert"];
            if lsass_keywords.iter().any(|&k| cmd_lower.contains(k)) {
                alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", "[T1003.001] CRITICAL: LSASS Credential Dumping (Static Override)".to_string()));
                return alerts;
            }

            if ["svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe", "services.exe"].contains(&proc_lower.as_str()) {
                let injection_keywords = ["virtualalloc", "createremotethread", "writeprocessmemory", "reflective", "processhollow", "inject"];
                if injection_keywords.iter().any(|&k| cmd_lower.contains(k)) {
                    alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", "[T1055] CRITICAL: Reflective Code Injection (Static Override)".to_string()));
                    return alerts;
                }
            }
        }

        // Ransomware burst detection
        if evt.event_type == "FileIOCreate" || evt.event_type == "FileIOWrite" {
            let path_entropy = Self::shannon_entropy(&evt.path);
            let tracker = self.pid_io_tracker.entry(evt.pid).or_insert(IoTracker { count: 0, start_time: now, entropy_sum: 0.0 });

            tracker.count += 1;
            tracker.entropy_sum += path_entropy;

            if now - tracker.start_time > 1.0 {
                tracker.count = 1;
                tracker.start_time = now;
                tracker.entropy_sum = path_entropy;
            } else if tracker.count > 50 {
                let avg_entropy = tracker.entropy_sum / tracker.count as f64;
                if avg_entropy > 5.2 {
                    alerts.push(Alert::new(&evt, avg_entropy, 95.0, "CRITICAL", format!("[T1486] Ransomware/Wiper Burst: {} I/O ops/sec (Entropy: {:.2})", tracker.count, avg_entropy)));
                    tracker.count = 0;
                    tracker.entropy_sum = 0.0;
                }
            }
        }

        // Route ALL orchestrated alerts (Sigma, TTPs) into the UEBA Temporal Baselining Engine
        if evt.category != "RawEvent" {
            let rule = if evt.details.contains("Rule:") {
                evt.details.split("Rule:").nth(1).unwrap_or("").split('[').next().unwrap_or("").trim().to_string()
            } else if !evt.details.is_empty() {
                evt.details.clone()
            } else {
                evt.event_type.clone()
            };

            // Dynamically assign severity based on the incoming MITRE tag / Category
            let initial_severity = if evt.category.contains("T15") || evt.category.contains("T10") { "CRITICAL" } else { "HIGH" };

            self.rule_process_map.entry(rule.clone()).or_insert_with(HashSet::new).insert(proc_lower.clone());
            if self.rule_process_map.get(&rule).unwrap().len() >= 5 {
                alerts.push(Alert { process: "GLOBAL".to_string(), parent: "".to_string(), cmd: "".to_string(), destination: "".to_string(), port: 0, pid: 0, tid: 0, score: -2.0, confidence: 100.0, severity: "INFO".to_string(), reason: rule });
                return alerts;
            }

            // Unifies OS and Network Telemetry
            let target_data = if !evt.destination.is_empty() {
                format!("{}:{}", evt.destination, evt.port)
            } else if !evt.cmd.is_empty() {
                evt.cmd.clone()
            } else {
                evt.path.clone()
            };

            let (ctx_hash, target_struct) = self.generate_structural_hash(&evt.parent, &proc_lower, &target_data, &rule);

            let b_data = self.ueba_baseline.entry(ctx_hash.clone()).or_insert(UebaBaseline {
                count: 0, last_seen: now, mean_delta: 0.0, m2_delta: 0.0
            });

            let delta_t = now - b_data.last_seen;
            b_data.count += 1;
            b_data.last_seen = now;

            let count_f = b_data.count as f64;
            let delta_mean = delta_t - b_data.mean_delta;
            b_data.mean_delta += delta_mean / count_f;
            let delta_mean2 = delta_t - b_data.mean_delta;
            b_data.m2_delta += delta_mean * delta_mean2;

            let variance = if b_data.count > 1 { b_data.m2_delta / (count_f - 1.0) } else { 0.0 };
            let std_dev = variance.sqrt();

            self.conn.execute(
                "INSERT INTO ueba_temporal_baselines (context_hash, parent_process, process, rule, target_struct, event_count, last_seen, mean_delta, m2_delta)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(context_hash) DO UPDATE SET event_count=excluded.event_count, last_seen=excluded.last_seen, mean_delta=excluded.mean_delta, m2_delta=excluded.m2_delta",
                params![ctx_hash, evt.parent, proc_lower, rule, target_struct, b_data.count, b_data.last_seen, b_data.mean_delta, b_data.m2_delta]
            ).unwrap_or_default();

            let is_automated = std_dev < 300.0;
            let trust_threshold = if is_automated { self.suppression_count_min } else { (self.suppression_count_min as f64 * 2.5) as i32 };

            // UEBA Audit Logging & Alert Routing
            if b_data.count == 1 {
                Self::log_ueba_audit("LEARNING", &proc_lower, &rule, 1, 0.0);
            }

            if b_data.count < trust_threshold {
                Self::log_ueba_audit("LEARNING", &proc_lower, &rule, b_data.count, std_dev);
                alerts.push(Alert::new(&evt, 0.0, 50.0, initial_severity, format!("{}: {} (Learning: {}/{})", evt.category, rule, b_data.count, trust_threshold)));
            } else if b_data.count == trust_threshold {
                Self::log_ueba_audit("THRESHOLD", &proc_lower, &rule, b_data.count, std_dev);
                alerts.push(Alert::new(&evt, -1.0, 100.0, "INFO", format!("UEBA SECURED: {} | Mode: {} Baseline.", rule, if is_automated { "Automated" } else { "Manual" })));
            } else {
                Self::log_ueba_audit("SUPPRESSED", &proc_lower, &rule, b_data.count, std_dev);
            }
            return alerts;
        }

        // ML feature extraction + scoring
        let text_data = format!("{}{}", evt.cmd, evt.path);
        let entropy = Self::shannon_entropy(&text_data);
        // Track the Parent->Child execution tuple for anomaly scoring
        let pc_tuple = format!("{}->{}", evt.parent.to_lowercase(), proc_lower);
        let tuple_count = self.tuple_freq.entry(pc_tuple).or_insert(0);
        *tuple_count += 1;
        let tuple_score = 1.0 / *tuple_count as f64;
        let path_depth = evt.path.chars().filter(|&c| c == '\\').count() as f64;

        // ML TUNING: Bypass the static T1027 entropy override if the command line contains structured JSON/Telemetry markers
        let is_structured_telemetry = cmd_lower.contains("telemetrysession") ||
                                      cmd_lower.contains("{\"") ||
                                      cmd_lower.contains("appinsights") ||
                                      cmd_lower.contains("xmlns=");

        // Only flag T1027 if entropy is high AND it doesn't look like standard developer telemetry
        if text_data.len() > 50 && entropy > 5.2 && !is_structured_telemetry && (evt.event_type == "ProcessStart" || evt.event_type == "RegistryWrite") {
            let severity_str = if entropy > 5.5 { "CRITICAL" } else { "HIGH" };
            alerts.push(Alert::new(
                &evt,
                entropy,
                85.0,
                severity_str,
                format!("[T1027] Suspicious packed/encoded payload in {} (Entropy {:.2})", evt.event_type, entropy)
            ));
        }

        let current_feat = [entropy, tuple_score, path_depth];

        if self.history.len() < 5000 {
            self.history.push(current_feat);
        } else {
            self.history.remove(0);
            self.history.push(current_feat);
        }

        self.fit_counter = self.fit_counter.saturating_add(1);

        // Asynchronous Forest Rebuild
        let needs_rebuild = {
            let forest_read = self.cached_forest.read().unwrap();
            self.history.len() > 200
                && (forest_read.is_none() || self.fit_counter > 20000)
                && !*self.is_training.read().unwrap()
        };

        if needs_rebuild {
            let mut is_training = self.is_training.write().unwrap();
            if !*is_training {
                *is_training = true;
                self.fit_counter = 0; // Reset immediately to prevent multiple spawns

                let history_clone = self.history.clone();
                let forest_arc = Arc::clone(&self.cached_forest);
                let training_flag = Arc::clone(&self.is_training);

                std::thread::spawn(move || {
                    let options = ForestOptions {
                        n_trees: 50,
                        sample_size: std::cmp::min(256, history_clone.len()),
                        max_tree_depth: None,
                        extension_level: 1,
                    };

                    if let Ok(forest) = Forest::from_slice(&history_clone, &options) {
                        let mut w_forest = forest_arc.write().unwrap();
                        *w_forest = Some(forest);
                    }
                    *training_flag.write().unwrap() = false;
                });
            }
        }

        // Safely read from the RwLock for scoring
        if let Some(forest) = &*self.cached_forest.read().unwrap() {
            let score = forest.score(&current_feat);

            if score > 0.55 {
                let severity = if score > 0.65 || entropy > 5.5 { "CRITICAL" } else { "HIGH" };
                let confidence = score * 100.0;

                let (final_severity, details) = if self.trusted_binaries.contains(&proc_lower) {
                    if severity == "CRITICAL" {
                        ("HIGH".to_string(), format!("Behavioral Outlier (Trusted Context): Anomalous chain by {}", proc_lower))
                    } else {
                        ("INFO".to_string(), format!("Known Noise: Anomalous chain by {}", proc_lower))
                    }
                } else {
                    (severity.to_string(), format!("Behavioral Lineage Outlier: Anomalous chain by {}", proc_lower))
                };

                alerts.push(Alert::new(
                    &evt,
                    score,
                    confidence,
                    &final_severity,
                    details
                ));
            }
        }
        alerts
    }
}

// ============================================================================
// NATIVE C-FFI BOUNDARY
// ============================================================================

#[no_mangle]
pub extern "C" fn init_engine() -> *mut Mutex<BehavioralEngine> {
    panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::force_capture();
        let msg = match panic_info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Unknown Rust Panic",
            }
        };

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("C:\\ProgramData\\DeepSensor\\Logs\\Rust_Fatal.log") {
            let _ = writeln!(file, "PANIC: {}\nLOCATION: {:?}\nBACKTRACE:\n{}", msg, panic_info.location(), backtrace);
        }
    }));

    let engine = BehavioralEngine::new();
    Box::into_raw(Box::new(Mutex::new(engine)))
}

#[no_mangle]
pub extern "C" fn evaluate_telemetry(
    engine_ptr: *mut Mutex<BehavioralEngine>,
    json_payload: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || json_payload.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(json_payload) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Parse an array of events instead of a single object
    let events: Vec<IncomingEvent> = match serde_json::from_str(json_str) {
            Ok(evts) => evts,
            Err(e) => {
                let err_msg = format!("JSON Parse Error: {}", e);
                let response = OutgoingResponse { alerts: None, daemon_error: Some(err_msg) };

                match serde_json::to_string(&response) {
                    Ok(safe_json) => return CString::new(safe_json).unwrap().into_raw(),
                    Err(_) => return std::ptr::null_mut(),
                }
            }
        };

    let engine_mutex = unsafe { &*engine_ptr };

    let result = std::panic::catch_unwind(|| {
        let mut engine = match engine_mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        };

        let mut batch_alerts = Vec::new();
        for evt in events {
            batch_alerts.extend(engine.evaluate_single(evt));
        }
        batch_alerts
    });

    match result {
        Ok(alerts) if !alerts.is_empty() => {
            let response = OutgoingResponse { alerts: Some(alerts), daemon_error: None };
            match serde_json::to_string(&response) {
                Ok(resp_str) => CString::new(resp_str)
                    .unwrap_or_else(|_| CString::new(r#"{"daemon_error":"serialize_failed"}"#).unwrap())
                    .into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); }
    }
}

#[no_mangle]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<BehavioralEngine>) {
    if !engine_ptr.is_null() {
        unsafe {
            let engine_box = Box::from_raw(engine_ptr);
            let engine = match engine_box.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    eprintln!("[ML TEARDOWN] Mutex was poisoned - recovering");
                    poisoned.into_inner()
                }
            };
            let _ = engine.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }
}