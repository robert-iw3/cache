"""
BeaconML.py
Advanced ML-based beaconing detection using Multi-Dimensional Clustering.
Daemonized Version: Listens on STDIN for continuous stream processing.

Author: Robert Weber
Version: 5.0

Description:
Core mathematical engine for detecting Command and Control (C2) beaconing.
Supports modern stealthy TTPs including jitter, malleable payloads,
sparse/long-sleep beacons, high-entropy encryption, Fast Flux, and DGA.

Architecture Overview:
This daemon ingests 4D telemetry arrays (Intervals, Packet Sizes, Subnet Diversity, Entropy)
forwarded by the C# Kernel ETW engine. It utilizes DBSCAN and K-Means clustering to
mathematically identify robotic periodicity, bypassing the need for static IOCs.
"""

import sys
import os

# Architecturally critical: Restricts underlying C-libraries (OpenMP/MKL) from attempting multi-threaded
# parallelization. Prevents OS-level thread deadlocks when running as a headless piped daemon.
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAX_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import json
import numpy as np
import math
import re
import warnings
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
import logging
import ipaddress
from collections import Counter, defaultdict

# Architecturally critical: Suppress ML library warnings from polluting STDOUT
# and crashing the PowerShell JSON parser.
warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(message)s')

# ====================== UTILITY FUNCTIONS ======================

def compute_silhouette(k, X):
    """Evaluates cluster separation quality using K-Means."""
    if len(X) < k:
        return k, -1, None, None
    try:
        # Constrains centroid initializations to prevent geometric compute
        # inflation across thousands of concurrent operating system flows.
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=1)
        labels = kmeans.fit_predict(X)
        n_labels = len(np.unique(labels))
        n_samples = len(X)
        if 1 < n_labels < n_samples:
            score = silhouette_score(X, labels)
            return k, score, kmeans, labels
    except Exception:
        pass
    return k, -1, None, None

def _normalize_cidr(ip: str) -> str:
    """Normalizes raw IPs into /24 (IPv4) or /64 (IPv6) subnets for diversity tracking."""
    try:
        if ':' in ip:
            return str(ipaddress.IPv6Network(ip + '/64', strict=False))
        else:
            return str(ipaddress.IPv4Network(ip + '/24', strict=False))
    except Exception:
        return ip

def shannon_entropy(data: str) -> float:
    """Calculates randomness of a string. High entropy often indicates DGA or encrypted payloads."""
    if not data:
        return 0.0
    counts = Counter(data)
    probs = [v / len(data) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


# ====================== THREAT MODULES ======================

def detect_dga(domain: str) -> tuple:
    """
    Evaluates domains for Domain Generation Algorithm (DGA) characteristics.
    Uses Shannon entropy, consonant ratios, and regex pattern matching.
    """
    if not domain or len(domain) < 6:
        return False, 0, ""

    parts = domain.lower().split('.')
    label = parts[0] if len(parts) > 1 else domain.lower()

    entropy = shannon_entropy(label)
    length = len(label)
    cons_ratio = sum(1 for c in label if c.isalpha() and c not in 'aeiou') / max(1, length)
    hyphen_count = label.count('-')

    score = 0
    reasons = []

    if entropy > 3.8:
        score += 45; reasons.append(f"high_entropy({entropy:.2f})")
    if cons_ratio > 0.75:
        score += 30; reasons.append("consonant_heavy")
    if entropy < 3.6 and length >= 15:
        if hyphen_count >= 2:
            score += 55; reasons.append(f"dict_dga_hyphens({hyphen_count})")
        if re.search(r'[a-z]{6,}[0-9]{2,5}$', label):
            score += 40; reasons.append("dict_dga_trailing_digits")
    if re.match(r'^[a-f0-9]+$', label) and length >= 12:
        score += 60; reasons.append("hex_dga_pattern")

    is_dga = score >= 65
    return is_dga, min(95, score), "; ".join(reasons)


def detect_fast_flux(ips: list, ttls: list = None, asns: list = None) -> tuple:
    """
    Detects Fast-Flux infrastructure by analyzing IP rotation, Subnet dispersion, and ASN diversity.
    Includes logic to suppress false positives from legitimate Cloud/CDN load balancing.
    """
    if len(ips) < 4:
        return False, 0, "insufficient_data"

    unique_ips = len(set(ips))
    avg_ttl = np.mean(ttls) if ttls and len(ttls) > 0 else 300

    score = 0
    reasons = []

    if unique_ips >= 4:
        score += 25; reasons.append(f"high_churn({unique_ips})")
    if avg_ttl < 180:
        score += 15; reasons.append(f"low_ttl({avg_ttl:.0f}s)")

    if asns and len(asns) > 0:
        unique_asns = len(set(asns))
        asn_diversity_ratio = unique_asns / unique_ips
        if unique_asns >= 4 and asn_diversity_ratio > 0.3:
            score += 50; reasons.append(f"botnet_asn_dispersion({unique_asns}_ASNs)")
        elif unique_asns <= 2 and unique_ips > 8:
            score -= 40; reasons.append("likely_cdn_infrastructure")
    else:
        normalized_cidrs = [_normalize_cidr(ip) for ip in ips]
        if len(set(normalized_cidrs)) >= 3:
            score += 40; reasons.append("multi_subnet_dispersion")

    is_ff = score >= 65
    return is_ff, max(0, min(95, score)), "; ".join(reasons)


# ====================== CORE CLUSTERING ENGINE ======================

def detect_beaconing_list(data):
    """
    The primary 4D mathematical engine.
    Constructs a normalized feature matrix and attempts to find tight clusters
    (indicating robotic periodicity) within the data noise.
    """
    intervals = data.get("intervals", [])
    domain = data.get("domain")
    dst_ips = data.get("dst_ips", [])
    ttls = data.get("ttls", [])
    asns = data.get("asns", [])
    payload_entropies = data.get("payload_entropies", [])
    packet_sizes = data.get("packet_sizes", [])

    if not intervals or len(intervals) < 8:
        return None, 0

    intervals = intervals[-2000:]
    if packet_sizes: packet_sizes = packet_sizes[-2000:]
    if dst_ips: dst_ips = dst_ips[-2000:]

    flags = []
    intervals_arr = np.array(intervals, dtype=float)
    std_int = np.std(intervals_arr)
    mean_int = float(np.mean(intervals_arr))
    observed_duration = sum(intervals)

    if std_int < max(1.5, 0.3 * mean_int):
        if observed_duration > 180:
            flags.append(f"ML Sustained Beaconing (Jittered: {mean_int:.2f}s ±{std_int:.2f})")
        else:
            flags.append(f"ML Short-Burst Beaconing (Jittered: {mean_int:.2f}s ±{std_int:.2f})")

    flux_score = dga_score = 0
    if dst_ips and len(set(dst_ips)) >= 4:
        is_ff, flux_score, ff_reason = detect_fast_flux(dst_ips, ttls, asns)
        if is_ff: flags.append(f"FAST_FLUX: {ff_reason}")

    if domain:
        is_dga, dga_score, dga_reason = detect_dga(domain)
        if is_dga: flags.append(f"DGA: {dga_reason}")

    features = [intervals_arr]
    if payload_entropies and len(payload_entropies) == len(intervals):
        features.append(np.array(payload_entropies, dtype=float))
    if packet_sizes and len(packet_sizes) == len(intervals):
        features.append(np.array(packet_sizes, dtype=float))

    subnet_score = 12.0
    if dst_ips and len(dst_ips) == len(intervals):
        normalized_cidrs = [_normalize_cidr(ip) for ip in dst_ips]
        unique_subnets = len(set(normalized_cidrs))
        diversity_ratio = unique_subnets / len(normalized_cidrs)
        subnet_score = min(88.0, diversity_ratio * 75 + unique_subnets * 5.5) if unique_subnets > 1 else 12.0
    features.append(np.full(len(intervals), subnet_score))

    features_matrix = np.column_stack(features)
    X = StandardScaler().fit_transform(features_matrix)

    max_k = min(8, len(X) - 1)
    if max_k > 1:
        results = [compute_silhouette(k, X) for k in range(2, max_k + 1)]
        best_k, best_score, _, best_labels = max(((k, score, km, lbl) for k, score, km, lbl in results if score > 0.45), default=(0, 0, None, None))
        if best_k > 0:
            valid_stds = [np.std(intervals_arr[np.where(best_labels == i)[0]]) for i in range(best_k) if len(np.where(best_labels == i)[0]) >= 8]
            if valid_stds:
                min_std = min(valid_stds)
                if min_std <= 10.0:
                    flags.append(f"ML 4D K-Means Beaconing (Clusters: {best_k}, Core StdDev: {min_std:.2f})")

    if len(X) >= 8:
        try:
            nn = NearestNeighbors(n_neighbors=min(8, len(X)-1))
            distances = nn.fit(X).kneighbors(X)[0]
            eps = max(0.1, np.percentile(distances[:, -1], 90))
            if eps > 0:
                labels = DBSCAN(eps=eps, min_samples=min(8, len(X)-1)).fit_predict(X)
                for label in set(labels):
                    if label != -1:
                        idx = np.where(labels == label)[0]
                        if len(idx) >= 8 and np.std(intervals_arr[idx]) <= 10.0:
                            flags.append(f"ML 4D DBSCAN Beaconing (Core StdDev: {np.std(intervals_arr[idx]):.2f})")
                            break
        except Exception:
            pass

    if not flags:
        return None, 0

    base_conf = 45
    if observed_duration < 180 and std_int > 2.0:
        base_conf -= 15

    confidence = min(98, base_conf + len(flags) * 20 + int(flux_score * 0.45) + int(dga_score * 0.35))

    if confidence > 70 and len(flags) == 1 and flux_score < 30 and dga_score < 30:
        confidence -= 15

    return "; ".join(flags), confidence


# ====================== DAEMON I/O LOOP ======================

def process_batch(payload):
    """
    Routes incoming JSON payloads to the detection logic and packages alerts.
    Includes comprehensive runtime telemetry for orchestrator visibility.
    """
    results = {}
    flows_evaluated = 0
    alerts_generated = 0

    for key, data in payload.items():
        flows_evaluated += 1
        try:
            flag, conf = detect_beaconing_list(data)
            if flag and conf >= 60:
                results[key] = {"alert": flag, "confidence": conf}
                alerts_generated += 1
        except Exception as e:
            results[key] = {"error": str(e)}

    # Surface internal processing metrics for external lifecycle validation
    results["_health_metrics"] = {
        "flows_evaluated": flows_evaluated,
        "alerts_generated": alerts_generated
    }
    return results

if __name__ == "__main__":
    while True:
        # Unbuffered sequential read architecture neutralizes IPC chunking deadlocks
        # inherent to the standard Python sys.stdin iterable generator on Windows.
        line = sys.stdin.readline()

        if not line:
            break

        line = line.strip()
        if not line:
            continue

        if line == "QUIT":
            break

        try:
            payload = json.loads(line)
            alerts = process_batch(payload)
            print(json.dumps(alerts), flush=True)
        except Exception as e:
            print(json.dumps({"daemon_error": str(e)}), flush=True)