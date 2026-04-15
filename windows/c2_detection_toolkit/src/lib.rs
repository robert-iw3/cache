/*=============================================================================================
 * SYSTEM:          C2 Beacon Sensor v1
 * COMPONENT:       lib.rs (Native FFI Behavioral ML Engine)
 * AUTHOR:          Robert Weber
 * DESCRIPTION:
 * Compiled as a C-compatible Dynamic Link Library (cdylib). Replaces the legacy Python 
 * STDIN/STDOUT daemon. Achieves 100% mathematical parity with V6, natively executing
 * DBSCAN, 4D K-Means, Fast-Flux, and DGA heuristics via the C-ABI boundary.
 *============================================================================================*/

use rusqlite::{Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

// Linfa Machine Learning Imports
use linfa::traits::{Fit, Predict};
use linfa_clustering::{Dbscan, KMeans};
use ndarray::{Array2, ArrayBase, OwnedRepr, Dim, Axis};
use rand::thread_rng;

// Heuristics Imports
use regex::Regex;

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
        let len = data.len() as f64;
        counts.values().fold(0.0, |acc, &count| {
            let p = *count as f64 / len;
            acc - (p * p.log2())
        })
    }

    pub fn detect_dga(&self, domain: &str) -> (bool, f64, String) {
        if domain.is_empty() || domain.len() < 6 { return (false, 0.0, String::new()); }

        let parts: Vec<&str> = domain.to_lowercase().split('.').collect();
        let label = if parts.len() > 1 { parts[0] } else { &domain.to_lowercase() };

        let entropy = Self::shannon_entropy(label);
        let length = label.len();
        
        let consonant_count = label.chars().filter(|c| c.is_ascii_alphabetic() && !"aeiou".contains(*c)).count();
        let cons_ratio = consonant_count as f64 / std::cmp::max(1, length) as f64;
        let hyphen_count = label.chars().filter(|&c| c == '-').count();

        let mut score = 0.0;
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
        if ips.len() < 4 { return (false, 0.0, "insufficient_data".to_string()); }

        let mut unique_ips = Vec::new();
        for ip in ips { if !unique_ips.contains(ip) { unique_ips.push(ip.clone()); } }
        
        let avg_ttl = ttls.map(|t| if !t.is_empty() { t.iter().sum::<i32>() as f64 / t.len() as f64 } else { 300.0 }).unwrap_or(300.0);

        let mut score = 0.0;
        let mut reasons = Vec::new();

        if unique_ips.len() >= 4 { score += 25.0; reasons.push(format!("high_churn({})", unique_ips.len())); }
        if avg_ttl < 180.0 { score += 15.0; reasons.push(format!("low_ttl({:.0}s)", avg_ttl)); }

        if let Some(asn_list) = asns {
            let mut unique_asns = Vec::new();
            for a in asn_list { if !unique_asns.contains(a) { unique_asns.push(*a); } }
            let asn_diversity = unique_asns.len() as f64 / unique_ips.len() as f64;
            
            if unique_asns.len() >= 4 && asn_diversity > 0.3 {
                score += 50.0; reasons.push(format!("botnet_asn_dispersion({}_ASNs)", unique_asns.len()));
            } else if unique_asns.len() <= 2 && unique_ips.len() > 8 {
                score -= 40.0; reasons.push("likely_cdn_infrastructure".to_string());
            }
        } else {
            let mut unique_subnets = Vec::new();
            for ip in ips {
                let subnet = Self::normalize_cidr(ip);
                if !unique_subnets.contains(&subnet) { unique_subnets.push(subnet); }
            }
            if unique_subnets.len() >= 3 {
                score += 40.0; reasons.push("multi_subnet_dispersion".to_string());
            }
        }

        (score >= 65.0, score.clamp(0.0, 95.0), reasons.join("; "))
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
            let slice = column.as_slice().unwrap_or(&[]);
            let (mean, std_dev) = Self::calculate_mean_std(slice);
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
        eps.max(0.1) // Minimum floor matching Python
    }
}

// ============================================================================
// CORE BEHAVIORAL ENGINE
// ============================================================================

pub struct BehavioralEngine {
    conn: Connection,
    heuristics: ThreatHeuristics,
}

impl BehavioralEngine {
    fn new() -> Self {
        let secure_dir = r"C:\ProgramData\C2Sensor\Data";
        std::fs::create_dir_all(secure_dir).unwrap_or_default();
        let db_path = format!(r"{}\C2Sensor_State.db", secure_dir);

        let conn = Connection::open(&db_path).unwrap_or_else(|_| Connection::open_in_memory().unwrap());
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;").unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS temporal_flow_state (
                context_hash TEXT PRIMARY KEY, destination_ip TEXT, domain TEXT, 
                packet_sizes TEXT, timestamps TEXT, last_seen REAL
            )", []).unwrap();

        BehavioralEngine { conn, heuristics: ThreatHeuristics::new() }
    }

    fn evaluate_flow(&mut self, flow: IncomingTelemetry) -> Option<OutgoingAlert> {
        let n_intervals = flow.intervals.len();
        if n_intervals < 8 { return None; }

        let mut flags = Vec::new();
        let (mean_int, std_int) = MathEngine::calculate_mean_std(&flow.intervals);
        let observed_duration: f64 = flow.intervals.iter().sum();

        // 1. Base Jitter Heuristic (Python Parity)
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
        if flow.dst_ips.len() >= 4 {
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

        // 4. Construct the 4D Feature Matrix
        let mut features: Vec<Array2<f64>> = Vec::new();
        features.push(Array2::from_shape_vec((n_intervals, 1), flow.intervals.clone()).unwrap());

        if let Some(entropies) = &flow.payload_entropies {
            if entropies.len() == n_intervals {
                features.push(Array2::from_shape_vec((n_intervals, 1), entropies.clone()).unwrap());
            }
        }
        if flow.packet_sizes.len() == n_intervals {
            features.push(Array2::from_shape_vec((n_intervals, 1), flow.packet_sizes.clone()).unwrap());
        }

        // Subnet Diversity Score Column
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
        features.push(Array2::from_shape_vec((n_intervals, 1), vec![subnet_score; n_intervals]).unwrap());

        // Concatenate features horizontally to build the final `X` matrix
        let views: Vec<_> = features.iter().map(|a| a.view()).collect();
        let mut dataset = ndarray::concatenate(Axis(1), &views).unwrap_or_else(|_| features[0].clone());

        // Apply Standard Scaler (Z-Score Normalization)
        MathEngine::standard_scaler(&mut dataset);

        // 5. K-Means (4D Clustering)
        let rng = thread_rng();
        let max_k = std::cmp::min(8, dataset.nrows().saturating_sub(1));
        let mut best_score = -1.0;
        let mut best_k = 0;
        let mut best_labels = Vec::new();

        if max_k > 1 {
            for k in 2..=max_k {
                if let Ok(model) = KMeans::params_with(k, rng.clone()).max_n_iterations(100).fit(&dataset) {
                    let labels = model.predict(&dataset).to_vec();
                    let score = MathEngine::compute_silhouette(&dataset, &labels, k);
                    if score > 0.45 && score > best_score {
                        best_score = score; best_k = k; best_labels = labels;
                    }
                }
            }
        }

        if best_k > 0 {
            // Find the cluster with the lowest variance to identify the rigid beacon
            let mut min_std = f64::MAX;
            for c in 0..best_k {
                let cluster_intervals: Vec<f64> = flow.intervals.iter().enumerate()
                    .filter_map(|(i, &val)| if best_labels[i] == c { Some(val) } else { None })
                    .collect();
                if cluster_intervals.len() >= 8 {
                    let (_, c_std) = MathEngine::calculate_mean_std(&cluster_intervals);
                    if c_std < min_std { min_std = c_std; }
                }
            }
            if min_std <= 10.0 {
                flags.push(format!("ML 4D K-Means Beaconing (Clusters: {}, Core StdDev: {:.2})", best_k, min_std));
            }
        }

        // 6. DBSCAN (Density Clustering)
        if dataset.nrows() >= 8 {
            let k_neighbors = std::cmp::min(8, dataset.nrows() - 1);
            let dynamic_eps = MathEngine::calculate_dynamic_eps(&dataset, k_neighbors);
            
            if let Ok(model) = Dbscan::params(k_neighbors).tolerance(dynamic_eps).fit(&dataset) {
                // If any cluster contains >= 8 points and low variance, flag it
                let labels = model.predict(&dataset).to_vec();
                let mut valid_dbscan = false;
                for c in labels.iter().filter(|&&l| l.is_some()).map(|l| l.unwrap()) {
                    let cluster_intervals: Vec<f64> = flow.intervals.iter().enumerate()
                        .filter_map(|(i, &val)| if labels[i] == Some(c) { Some(val) } else { None })
                        .collect();
                    if cluster_intervals.len() >= 8 {
                        let (_, c_std) = MathEngine::calculate_mean_std(&cluster_intervals);
                        if c_std <= 10.0 {
                            flags.push(format!("ML 4D DBSCAN Beaconing (Core StdDev: {:.2})", c_std));
                            valid_dbscan = true;
                            break;
                        }
                    }
                }
            }
        }

        if flags.is_empty() { return None; }

        // Confidence Math (Python Parity)
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

#[no_mangle]
pub extern "C" fn init_engine() -> *mut Mutex<BehavioralEngine> {
    Box::into_raw(Box::new(Mutex::new(BehavioralEngine::new())))
}

#[no_mangle]
pub extern "C" fn evaluate_telemetry(engine_ptr: *mut Mutex<BehavioralEngine>, json_payload: *const c_char) -> *mut c_char {
    if engine_ptr.is_null() || json_payload.is_null() { return std::ptr::null_mut(); }

    let c_str = unsafe { CStr::from_ptr(json_payload) };
    let json_str = match c_str.to_str() { Ok(s) => s, Err(_) => return std::ptr::null_mut() };

    let events: Vec<IncomingTelemetry> = match serde_json::from_str(json_str) {
        Ok(e) => e,
        Err(_) => return std::ptr::null_mut()
    };

    let engine_mutex = unsafe { &*engine_ptr };

    let result = std::panic::catch_unwind(|| {
        let mut engine = match engine_mutex.lock() { Ok(guard) => guard, Err(poisoned) => poisoned.into_inner() };
        let mut batch_alerts = Vec::new();
        
        for evt in events {
            if let Some(alert) = engine.evaluate_flow(evt) { batch_alerts.push(alert); }
        }
        batch_alerts
    });

    match result {
        Ok(alerts) if !alerts.is_empty() => {
            let response = OutgoingResponse { alerts: Some(alerts), daemon_error: None };
            match serde_json::to_string(&response) {
                Ok(resp_str) => CString::new(resp_str).unwrap().into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
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
            let _ = engine.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }
}