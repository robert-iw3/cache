/*=============================================================================================
 * SYSTEM:          C2 Beacon Sensor v1
 * COMPONENT:       lib.rs (Native FFI Behavioral ML Engine)
 * AUTHOR:          Robert Weber
 * DESCRIPTION:
 * Compiled as a C-compatible Dynamic Link Library (cdylib). Replaces the legacy Python
 * STDIN/STDOUT daemon. Achieves 100% mathematical parity with V6, natively executing
 * DBSCAN, 4D K-Means, Fast-Flux, and DGA heuristics via the C-ABI boundary.
 *============================================================================================*/

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

// Linfa Machine Learning Imports
use linfa::traits::{Fit, Predict, Transformer};
use linfa::Dataset;
use linfa_clustering::{Dbscan, KMeans};
use linfa_nn::distance::L2Dist;
use ndarray::{Array2, ArrayBase, OwnedRepr, Dim, Axis};
use rand::thread_rng;

// Heuristics Imports
use regex::Regex;

// Diagnostic Logging
use std::panic;
use std::backtrace::Backtrace;
use std::fs::OpenOptions;
use std::io::Write;

// ============================================================================
// DATA STRUCTURES (FFI BOUNDARY CONTRACTS)
// ============================================================================

#[derive(Deserialize, Debug, Clone)]
pub struct IncomingTelemetry {
    pub key: String,
    pub intervals: Vec<f64>,
    pub domain: Option<String>,
    pub dst_ips: Vec<String>,
    pub packet_sizes: Vec<f64>,
    pub ttls: Option<Vec<i32>>,
    pub asns: Option<Vec<i32>>,
    pub payload_entropies: Option<Vec<f64>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct OutgoingAlert {
    pub key: String,
    pub alert_reason: String,
    pub confidence: f64,
}

#[derive(Serialize, Debug)]
struct OutgoingResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<Vec<OutgoingAlert>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_error: Option<String>,
}

// ============================================================================
// HEURISTICS ENGINE (DGA, ENTROPY, FAST-FLUX)
// ============================================================================

pub struct ThreatHeuristics {
    regex_trailing_digits: Regex,
    regex_hex_pattern: Regex,
}

impl ThreatHeuristics {
    pub fn new() -> Self {
        ThreatHeuristics {
            regex_trailing_digits: Regex::new(r"[a-z]{6,}[0-9]{2,5}$").unwrap(),
            regex_hex_pattern: Regex::new(r"^[a-f0-9]+$").unwrap(),
        }
    }

    pub fn shannon_entropy(data: &str) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts: HashMap<char, usize> = HashMap::new();
        for c in data.chars() { *counts.entry(c).or_insert(0) += 1; }
        let total_chars = counts.values().sum::<usize>() as f64;
        counts.values().fold(0.0, |acc, &count| {
            let p = count as f64 / total_chars;
            acc - (p * p.log2())
        })
    }

    pub fn detect_dga(&self, domain: &str) -> (bool, f64, String) {
        if domain.is_empty() || domain.len() < 6 { return (false, 0.0, String::new()); }

        let domain_lower = domain.to_lowercase();
        let parts: Vec<&str> = domain_lower.split('.').collect();
        let label = if parts.len() > 1 { parts[0] } else { &domain_lower };

        let entropy = Self::shannon_entropy(label);
        let length = label.len();

        let consonant_count = label.chars().filter(|c| c.is_ascii_alphabetic() && !"aeiou".contains(*c)).count();
        let cons_ratio = consonant_count as f64 / std::cmp::max(1, length) as f64;
        let hyphen_count = label.chars().filter(|&c| c == '-').count();

        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();

        if entropy > 3.8 { score += 45.0; reasons.push(format!("high_entropy({:.2})", entropy)); }
        if cons_ratio > 0.75 { score += 30.0; reasons.push("consonant_heavy".to_string()); }
        if entropy < 3.6 && length >= 15 {
            if hyphen_count >= 2 { score += 55.0; reasons.push(format!("dict_dga_hyphens({})", hyphen_count)); }
            if self.regex_trailing_digits.is_match(label) { score += 40.0; reasons.push("dict_dga_trailing_digits".to_string()); }
        }
        if self.regex_hex_pattern.is_match(label) && length >= 12 { score += 60.0; reasons.push("hex_dga_pattern".to_string()); }

        let is_dga = score >= 65.0;
        (is_dga, score.min(95.0), reasons.join("; "))
    }

    pub fn normalize_cidr(ip: &str) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]) // IPv4 /24
        } else {
            ip.to_string() // Fallback IPv6
        }
    }

    pub fn detect_fast_flux(ips: &[String], ttls: Option<&[i32]>, asns: Option<&[i32]>) -> (bool, f64, String) {
        if ips.len() < 3 { return (false, 0.0, "insufficient_data".to_string()); }

        let unique_ips: Vec<_> = ips.iter().cloned().collect::<std::collections::HashSet<_>>().into_iter().collect();
        let unique_count = unique_ips.len();

        let avg_ttl = ttls.map(|t| if !t.is_empty() { t.iter().sum::<i32>() as f64 / t.len() as f64 } else { 300.0 }).unwrap_or(300.0);

        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();

        if unique_count >= 3 { score += 35.0; reasons.push(format!("high_churn({})", unique_count)); }
        if avg_ttl < 200.0 { score += 20.0; reasons.push(format!("low_ttl({:.0}s)", avg_ttl)); }

        if let Some(asn_list) = asns {
            let unique_asns: std::collections::HashSet<_> = asn_list.iter().cloned().collect();
            let asn_diversity = unique_asns.len() as f64 / unique_count as f64;
            if unique_asns.len() >= 3 && asn_diversity > 0.25 {
                score += 55.0; reasons.push(format!("botnet_asn_dispersion({}_ASNs)", unique_asns.len()));
            } else if unique_asns.len() <= 2 && unique_count > 6 {
                score -= 35.0; reasons.push("likely_cdn_infrastructure".to_string());
            }
        } else {
            let mut unique_subnets = Vec::new();
            for ip in ips {
                let subnet = Self::normalize_cidr(ip);
                if !unique_subnets.contains(&subnet) { unique_subnets.push(subnet); }
            }
            if unique_subnets.len() >= 2 {
                score += 45.0; reasons.push("multi_subnet_dispersion".to_string());
            }
        }

        let is_ff = score >= 55.0;
        (is_ff, score.clamp(0.0, 95.0), reasons.join("; "))
    }
}

// ============================================================================
// MATHEMATICAL CLUSTERING ENGINE (4D K-Means & DBSCAN)
// ============================================================================

pub struct MathEngine;

impl MathEngine {
    pub fn calculate_mean_std(data: &[f64]) -> (f64, f64) {
        if data.is_empty() { return (0.0, 0.0); }
        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let variance = data.iter().map(|value| {
            let diff = mean - *value;
            diff * diff
        }).sum::<f64>() / data.len() as f64;
        (mean, variance.sqrt())
    }

    pub fn standard_scaler(matrix: &mut Array2<f64>) {
        // Native Z-Score normalization replicating sklearn.preprocessing.StandardScaler
        for mut column in matrix.columns_mut() {
            // Collect directly into a Vec to bypass non-contiguous memory slicing failures
            let vec: Vec<f64> = column.iter().cloned().collect();
            let (mean, std_dev) = Self::calculate_mean_std(&vec);
            if std_dev > 0.0 {
                column.mapv_inplace(|x| (x - mean) / std_dev);
            } else {
                column.mapv_inplace(|x| x - mean);
            }
        }
    }

    fn euclidean_distance(a: &ArrayBase<OwnedRepr<f64>, Dim<[usize; 1]>>, b: &ArrayBase<OwnedRepr<f64>, Dim<[usize; 1]>>) -> f64 {
        let mut sum = 0.0;
        for i in 0..a.len() {
            let diff = a[i] - b[i];
            sum += diff * diff;
        }
        sum.sqrt()
    }

    // Identical to sklearn.metrics.silhouette_score
    pub fn compute_silhouette(dataset: &Array2<f64>, labels: &[usize], k: usize) -> f64 {
        let n_samples = dataset.nrows();
        if n_samples < 2 || k < 2 || k >= n_samples { return -1.0; }

        let mut silhouette_sum = 0.0;
        for i in 0..n_samples {
            let point = dataset.row(i).to_owned();
            let label_i = labels[i];

            let mut a_sum = 0.0;
            let mut a_count = 0;
            let mut cluster_dists = vec![(0.0, 0_usize); k];

            for j in 0..n_samples {
                if i == j { continue; }
                let dist = Self::euclidean_distance(&point, &dataset.row(j).to_owned());
                let label_j = labels[j];

                if label_i == label_j {
                    a_sum += dist; a_count += 1;
                } else {
                    cluster_dists[label_j].0 += dist; cluster_dists[label_j].1 += 1;
                }
            }

            let a_i = if a_count > 0 { a_sum / a_count as f64 } else { 0.0 };
            let mut b_min = f64::MAX;

            for c in 0..k {
                if c != label_i && cluster_dists[c].1 > 0 {
                    let mean_dist = cluster_dists[c].0 / cluster_dists[c].1 as f64;
                    if mean_dist < b_min { b_min = mean_dist; }
                }
            }

            let s_i = if a_i < b_min { 1.0 - (a_i / b_min) }
                      else if a_i > b_min { (b_min / a_i) - 1.0 }
                      else { 0.0 };
            silhouette_sum += s_i;
        }
        silhouette_sum / n_samples as f64
    }

    pub fn calculate_dynamic_eps(dataset: &Array2<f64>, k_neighbors: usize) -> f64 {
        // Brute force K-NN to find the 90th percentile distance to the k-th nearest neighbor
        let n_samples = dataset.nrows();
        if n_samples == 0 { return 0.1; }

        let mut kth_distances = Vec::with_capacity(n_samples);
        for i in 0..n_samples {
            let point = dataset.row(i).to_owned();
            let mut dists = Vec::with_capacity(n_samples);
            for j in 0..n_samples {
                if i == j { continue; }
                dists.push(Self::euclidean_distance(&point, &dataset.row(j).to_owned()));
            }
            dists.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let k_idx = std::cmp::min(k_neighbors, dists.len().saturating_sub(1));
            kth_distances.push(dists[k_idx]);
        }

        kth_distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p90_idx = (kth_distances.len() as f64 * 0.90) as usize;
        let eps = kth_distances[std::cmp::min(p90_idx, kth_distances.len().saturating_sub(1))];
        eps.max(0.1) // Minimum floor
    }
}

// ============================================================================
// CORE BEHAVIORAL ENGINE
// ============================================================================

pub struct BehavioralEngine {
    conn: Connection,
    heuristics: ThreatHeuristics,
    last_groom_time: f64,
}

impl BehavioralEngine {
    fn new() -> Self {
        let secure_dir = r"C:\ProgramData\C2Sensor\Data";
        let _ = std::fs::create_dir_all(secure_dir);
        let db_path = format!(r"{}\C2Sensor_State.db", secure_dir);

        // Safely fallback to memory if the DB is locked by a previous deadlocked session
        let conn = match Connection::open(&db_path) {
            Ok(c) => c,
            Err(_) => Connection::open_in_memory().unwrap_or_else(|_| Connection::open_in_memory().expect("In-memory DB failed")),
        };

        let _ = conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;      -- Keep temp tables and indices in RAM
            PRAGMA mmap_size = 268435456;    -- 256MB memory map for zero-copy I/O
            PRAGMA cache_size = -64000;      -- 64MB page cache
            PRAGMA busy_timeout = 5000;      -- Prevent lock contention during FFI bursts
        ");
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS temporal_flow_state (
                context_hash TEXT PRIMARY KEY, destination_ip TEXT, domain TEXT,
                packet_sizes TEXT, timestamps TEXT, last_seen REAL
            )", []
        );

        BehavioralEngine {
            conn,
            heuristics: ThreatHeuristics::new(),
            last_groom_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        }
    }

    pub fn evaluate_flow(&mut self, flow: IncomingTelemetry) -> Option<OutgoingAlert> {
        // Prevent ML panics by requiring a minimum viable dataset for 4D clustering
        if flow.intervals.len() < 8 || flow.packet_sizes.len() < 8 {
            return None;
        }

        // Prevent NaN/Infinity crashes in standard deviation calculations
        let has_invalid_math = flow.intervals.iter().any(|&x| x.is_nan() || x.is_infinite()) ||
                               flow.packet_sizes.iter().any(|&x| x.is_nan() || x.is_infinite());

        if has_invalid_math {
            return None;
        }

        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Index Maintenance
        if now_sec - self.last_groom_time > 3600.0 {
            // Drop flows older than 72 hours
            let stale_threshold = now_sec - (72.0 * 3600.0);
            let _ = self.conn.execute(
                "DELETE FROM temporal_flow_state WHERE last_seen < ?1",
                params![stale_threshold],
            );

            // Analyze tables and update query planning statistics
            let _ = self.conn.execute_batch("PRAGMA optimize;");

            self.last_groom_time = now_sec;
        }

        let dest_ip = flow.dst_ips.last().cloned().unwrap_or_default();
        let domain = flow.domain.clone().unwrap_or_default();
        let packet_sizes_str = serde_json::to_string(&flow.packet_sizes).unwrap_or_else(|_| "[]".to_string());
        let intervals_str = serde_json::to_string(&flow.intervals).unwrap_or_else(|_| "[]".to_string());
        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO temporal_flow_state
            (context_hash, destination_ip, domain, packet_sizes, timestamps, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![&flow.key, dest_ip, domain, packet_sizes_str, intervals_str, last_seen],
        );

        let n_intervals = flow.intervals.len();
        if n_intervals < 8 { return None; }

        let mut flags = Vec::new();
        let (mean_int, std_int) = MathEngine::calculate_mean_std(&flow.intervals);
        let observed_duration: f64 = flow.intervals.iter().sum();

        // 1. Base Jitter Heuristic
        if std_int < 1.5_f64.max(0.3 * mean_int) {
            if observed_duration > 180.0 {
                flags.push(format!("ML Sustained Beaconing (Jittered: {:.2}s ±{:.2})", mean_int, std_int));
            } else {
                flags.push(format!("ML Short-Burst Beaconing (Jittered: {:.2}s ±{:.2})", mean_int, std_int));
            }
        }

        let mut flux_score = 0.0;
        let mut dga_score = 0.0;

        // 2. Fast Flux Detection
        if flow.dst_ips.len() >= 3 {
            let (is_ff, f_score, ff_reason) = ThreatHeuristics::detect_fast_flux(
                &flow.dst_ips, flow.ttls.as_deref(), flow.asns.as_deref()
            );
            flux_score = f_score;
            if is_ff { flags.push(format!("FAST_FLUX: {}", ff_reason)); }
        }

        // 3. DGA Detection
        if let Some(domain) = &flow.domain {
            let (is_dga, d_score, dga_reason) = self.heuristics.detect_dga(domain);
            dga_score = d_score;
            if is_dga { flags.push(format!("DGA: {}", dga_reason)); }
        }

        // 4–6. 4D Feature Matrix + K-Means + DBSCAN
        let mut features: Vec<Array2<f64>> = Vec::new();

        if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), flow.intervals.clone()) { features.push(arr); }

        if let Some(entropies) = &flow.payload_entropies {
            if entropies.len() == n_intervals {
                if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), entropies.clone()) { features.push(arr); }
            }
        }
        if flow.packet_sizes.len() == n_intervals {
            if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), flow.packet_sizes.clone()) { features.push(arr); }
        }

        let mut subnet_score = 12.0;
        if flow.dst_ips.len() == n_intervals {
            let mut unique_subnets = Vec::new();
            for ip in &flow.dst_ips {
                let subnet = ThreatHeuristics::normalize_cidr(ip);
                if !unique_subnets.contains(&subnet) { unique_subnets.push(subnet); }
            }
            let diversity_ratio = unique_subnets.len() as f64 / n_intervals as f64;
            if unique_subnets.len() > 1 {
                subnet_score = (diversity_ratio * 75.0 + unique_subnets.len() as f64 * 5.5).min(88.0);
            }
        }
        if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), vec![subnet_score; n_intervals]) { features.push(arr); }

        if features.is_empty() { return None; }

        let views: Vec<_> = features.iter().map(|a| a.view()).collect();
        let mut dataset = ndarray::concatenate(Axis(1), &views).unwrap_or_else(|_| features[0].clone());

        // ========================================================================
        // KD-Tree requires contiguous rows. Concatenating columns creates column-major arrays.
        // Rebuilding from the iterator forces the array into standard C-layout.
        // ========================================================================
        let c_contiguous_data: Vec<f64> = dataset.iter().cloned().collect();
        dataset = Array2::from_shape_vec((dataset.nrows(), dataset.ncols()), c_contiguous_data)
            .unwrap_or(dataset);

        MathEngine::standard_scaler(&mut dataset);

        // NaN/Inf guard
        let mut has_valid_data = true;
        for &v in dataset.iter() {
            if v.is_nan() || v.is_infinite() {
                has_valid_data = false;
                break;
            }
        }

        if has_valid_data {
            // K-Means
            let rng = thread_rng();
            let max_k = std::cmp::min(4, dataset.nrows().saturating_sub(1));
            let mut best_score = -1.0;
            let mut best_k = 0;

            if max_k > 1 {
                for k in 2..=max_k {
                    let dataset_wrapped = Dataset::from(dataset.clone());
                    if let Ok(model) = KMeans::params_with(k, rng.clone(), L2Dist).max_n_iterations(100).fit(&dataset_wrapped) {
                        let labels = model.predict(dataset.view());
                        if let Some(targets) = labels.targets.as_slice() {
                            let score = MathEngine::compute_silhouette(&dataset, targets, k);
                            if score > 0.45 && score > best_score {
                                best_score = score; best_k = k;
                            }
                        }
                    }
                }
            }

            if best_k > 0 {
                flags.push(format!("ML Multi-Cluster Beaconing (K={})", best_k));
            }

            // DBSCAN
            if dataset.nrows() >= 8 {
                let k_neighbors = std::cmp::min(8, dataset.nrows() - 1);
                let dynamic_eps = MathEngine::calculate_dynamic_eps(&dataset, k_neighbors);

                let dataset_wrapped = Dataset::from(dataset.clone());
                if let Ok(labels_dataset) = Dbscan::params(k_neighbors).tolerance(dynamic_eps).transform(dataset_wrapped) {
                    let dbscan_targets = &labels_dataset.targets;

                    let mut unique_clusters: Vec<usize> = dbscan_targets.iter().filter_map(|&l| l).collect();
                    unique_clusters.sort_unstable();
                    unique_clusters.dedup();

                    for c in unique_clusters {
                        let cluster_intervals: Vec<f64> = flow.intervals.iter().enumerate()
                            .filter_map(|(i, &val)| if dbscan_targets[i] == Some(c) { Some(val) } else { None })
                            .collect();
                        if cluster_intervals.len() >= 8 {
                            let (_, c_std) = MathEngine::calculate_mean_std(&cluster_intervals);
                            if c_std <= 10.0 {
                                flags.push(format!("ML 4D DBSCAN Beaconing (Core StdDev: {:.2})", c_std));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if flags.is_empty() { return None; }

        // Confidence Math
        let mut base_conf = 45.0;
        if observed_duration < 180.0 && std_int > 2.0 { base_conf -= 15.0; }

        let mut confidence = base_conf + (flags.len() as f64 * 20.0) + (flux_score * 0.45) + (dga_score * 0.35);
        confidence = confidence.min(98.0);

        if confidence > 70.0 && flags.len() == 1 && flux_score < 30.0 && dga_score < 30.0 {
            confidence -= 15.0;
        }

        Some(OutgoingAlert {
            key: flow.key,
            alert_reason: flags.join("; "),
            confidence: confidence.round(),
        })
    }
}

// ============================================================================
// NATIVE C-FFI BOUNDARY
// ============================================================================
fn setup_custom_panic_hook() {
    // Force Rust to resolve memory symbols for the backtrace
    std::env::set_var("RUST_BACKTRACE", "1");

    panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::force_capture();

        // Safely extract the panic payload
        let payload = panic_info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown ML Engine internal panic (Likely KD-Tree Zero-Variance)".to_string()
        };

        // Get the exact file and line number where the math failed
        let location = if let Some(loc) = panic_info.location() {
            format!("{}:{}", loc.file(), loc.line())
        } else {
            "unknown location".to_string()
        };

        let log_entry = format!(
            "\n================================================================\n\
             [RUST ML ENGINE FATAL PANIC]\n\
             Timestamp: {:?}\n\
             Location: {}\n\
             Error: {}\n\
             Backtrace:\n{}\n\
             ================================================================\n",
            std::time::SystemTime::now(), location, msg, backtrace
        );

        // Bypass the FFI and write directly to the PowerShell orchestrator's log
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(r"C:\ProgramData\C2Sensor\Logs\C2Sensor_Diagnostic.log")
        {
            let _ = write!(file, "{}", log_entry);
        }
    }));
}

#[no_mangle]
pub extern "C" fn init_engine() -> *mut Mutex<BehavioralEngine> {
    setup_custom_panic_hook();

    // Map the Behavioral Engine into memory
    let result = std::panic::catch_unwind(|| {
        Box::into_raw(Box::new(Mutex::new(BehavioralEngine::new())))
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn evaluate_telemetry(engine_ptr: *mut Mutex<BehavioralEngine>, json_payload: *const c_char) -> *mut c_char {
    if engine_ptr.is_null() || json_payload.is_null() {
        return make_error_response("FFI: Null pointer received");
    }

    let c_str = unsafe { CStr::from_ptr(json_payload) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return make_error_response("FFI: Invalid UTF-8 in payload"),
    };

    let events: Vec<IncomingTelemetry> = match serde_json::from_str(json_str) {
        Ok(e) => e,
        Err(e) => return make_error_response(&format!("JSON parse error: {}", e)),
    };

    let engine_mutex = unsafe { &*engine_ptr };

    let result = std::panic::catch_unwind(|| {
        let mut engine = match engine_mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut batch_alerts = Vec::new();

        for evt in events {
            if let Some(alert) = engine.evaluate_flow(evt) {
                batch_alerts.push(alert);
            }
        }
        batch_alerts
    });

    match result {
        Ok(alerts) if !alerts.is_empty() => {
            let response = OutgoingResponse { alerts: Some(alerts), daemon_error: None };
            match serde_json::to_string(&response) {
                Ok(resp_str) => {
                    // Strip ETW null-byte poisoning before crossing the C-ABI
                    let clean_str = resp_str.replace('\0', "");
                    CString::new(clean_str).unwrap_or_else(|_| CString::new("{}").unwrap()).into_raw()
                },
                Err(e) => make_error_response(&format!("Serialization error: {}", e)),
            }
        }
        Ok(_) => std::ptr::null_mut(),
        Err(panic_info) => {
            let msg = match panic_info.downcast_ref::<String>() {
                Some(s) => s.clone(),
                None => match panic_info.downcast_ref::<&str>() {
                    Some(s) => s.to_string(),
                    None => "Unknown panic (kdtree / linfa error)".to_string(),
                },
            };
            make_error_response(&format!("Rust panic: {}", msg))
        }
    }
}

// Helper to always return a proper error JSON
fn make_error_response(msg: &str) -> *mut c_char {
    let response = OutgoingResponse {
        alerts: None,
        daemon_error: Some(msg.replace('\0', "")),
    };
    match serde_json::to_string(&response) {
        Ok(s) => {
            let clean_str = s.replace('\0', "");
            CString::new(clean_str).unwrap_or_else(|_| CString::new("{\"daemon_error\": \"Critical serialization failure\"}").unwrap()).into_raw()
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}

#[no_mangle]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<BehavioralEngine>) {
    if !engine_ptr.is_null() {
        unsafe {
            let engine_box = Box::from_raw(engine_ptr);
            let engine = match engine_box.lock() { Ok(guard) => guard, Err(p) => p.into_inner() };
            // Execute PRAGMAs individually to prevent batch-abort on result rows
            let _ = engine.conn.execute("PRAGMA optimize;", []);
            // Force the Write-Ahead Log to commit to the main DB and shrink to 0 bytes
            let _ = engine.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);", []);
        }
    }
}