"""
BeaconML.py
Advanced ML-based beaconing detection using Multi-Dimensional Clustering.

Author: Robert Weber
Version: 3.0

Description:
Core mathematical engine for detecting Command and Control (C2) beaconing.
Supports modern stealthy TTPs including jitter, malleable payloads,
sparse/long-sleep beacons, high-entropy encryption, Fast Flux, and DGA.

Key Capabilities:
- 4D Feature Space (interval + entropy + packet-size + subnet diversity)
- ASN-aware Fast Flux detection (CDN suppression)
- Dual-engine DGA detection (entropy + dictionary/combinatorial patterns)
- Campaign-level correlation across flows and DNS
- Refined confidence scoring with false-positive suppression
- Zero heavy dependencies

Improvements (aligned with c2_beacon_hunter.py):
- Explicit early-exit for low-sample flows (<8) with debug logging
- Consistent threshold naming with hunter's MIN_SAMPLES_SPARSE
"""

import sys
import json
import argparse
import numpy as np
import math
import re
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
from joblib import Parallel, delayed
import logging
import ipaddress
from collections import Counter, defaultdict

logging.basicConfig(level=logging.INFO, format='%(message)s')


# ====================== SILHOUETTE HELPER ======================
# Computes optimal cluster count using silhouette score for K-Means
def compute_silhouette(k, X):
    if len(X) < k:
        return k, -1, None, None
    try:
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = kmeans.fit_predict(X)
        n_labels = len(np.unique(labels))
        n_samples = len(X)
        if 1 < n_labels < n_samples:
            score = silhouette_score(X, labels)
            return k, score, kmeans, labels
    except Exception:
        pass
    return k, -1, None, None


# ====================== CIDR NORMALIZER ======================
# Converts any IP to standardized CIDR block for subnet diversity scoring
def _normalize_cidr(ip: str) -> str:
    try:
        if ':' in ip:
            return str(ipaddress.IPv6Network(ip + '/64', strict=False))
        else:
            return str(ipaddress.IPv4Network(ip + '/24', strict=False))
    except Exception:
        return ip


# ====================== SHANNON ENTROPY ======================
# Calculates Shannon entropy for strings (used in DGA and payload analysis)
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    probs = [v / len(data) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


# ====================== DGA DETECTION ENGINE ======================
# Dual-engine detection for high-entropy DGAs and modern dictionary/combinatorial patterns
def detect_dga(domain: str) -> tuple:
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
        score += 45
        reasons.append(f"high_entropy({entropy:.2f})")
    if cons_ratio > 0.75:
        score += 30
        reasons.append("consonant_heavy")
    if entropy < 3.6 and length >= 15:
        if hyphen_count >= 2:
            score += 55
            reasons.append(f"dict_dga_hyphens({hyphen_count})")
        if re.search(r'[a-z]{6,}[0-9]{2,5}$', label):
            score += 40
            reasons.append("dict_dga_trailing_digits")
    if re.match(r'^[a-f0-9]+$', label) and length >= 12:
        score += 60
        reasons.append("hex_dga_pattern")

    is_dga = score >= 65
    return is_dga, min(95, score), "; ".join(reasons)


# ====================== FAST FLUX DETECTION ======================
# ASN-aware detection that distinguishes botnets from legitimate CDNs
def detect_fast_flux(ips: list, ttls: list = None, asns: list = None) -> tuple:
    if len(ips) < 5:
        return False, 0, "insufficient_data"

    unique_ips = len(set(ips))
    avg_ttl = np.mean(ttls) if ttls and len(ttls) > 0 else 300

    score = 0
    reasons = []

    if unique_ips >= 8:
        score += 15
        reasons.append(f"high_churn({unique_ips})")
    if avg_ttl < 180:
        score += 15
        reasons.append(f"low_ttl({avg_ttl:.0f}s)")

    if asns and len(asns) > 0:
        unique_asns = len(set(asns))
        asn_diversity_ratio = unique_asns / unique_ips
        if unique_asns >= 4 and asn_diversity_ratio > 0.3:
            score += 50
            reasons.append(f"botnet_asn_dispersion({unique_asns}_ASNs)")
        elif unique_asns <= 2 and unique_ips > 8:
            score -= 40
            reasons.append("likely_cdn_infrastructure")
    else:
        normalized_cidrs = [_normalize_cidr(ip) for ip in ips]
        if len(set(normalized_cidrs)) >= 4:
            score += 35
            reasons.append("multi_subnet_dispersion")

    is_ff = score >= 65
    return is_ff, max(0, min(95, score)), "; ".join(reasons)


# ====================== SINGLE-FLOW BEACON DETECTION ======================
# Core engine supporting both legacy parameter calls and new dict API
def detect_beaconing_list(*args, **kwargs):
    # Handle both calling styles (list of intervals or full metrics dict)
    if args and isinstance(args[0], (list, np.ndarray)):
        intervals = args[0]
        data = {
            "intervals": intervals,
            "payload_entropies": kwargs.get("payload_entropies"),
            "packet_sizes": kwargs.get("packet_sizes"),
            "dst_ips": kwargs.get("dst_ips"),
            "domain": kwargs.get("domain"),
            "ttls": kwargs.get("ttls"),
            "asns": kwargs.get("asns")
        }
    else:
        data = args[0] if args else kwargs

    intervals = data.get("intervals", [])
    domain = data.get("domain")
    dst_ips = data.get("dst_ips", [])
    ttls = data.get("ttls", [])
    asns = data.get("asns", [])
    payload_entropies = data.get("payload_entropies", [])
    packet_sizes = data.get("packet_sizes", [])

    # Early exit for low-sample flows (aligns with hunter's MIN_SAMPLES_SPARSE=8)
    if not intervals or len(intervals) < 8:
        if len(intervals) > 0:
            logging.debug(f"[BeaconML] Skipped low-sample flow ({len(intervals)} intervals) — below threshold")
        return None, 0

    print(f"[BeaconML] Analyzing {len(intervals)} intervals | domain: {domain}")

    # Truncate to prevent memory issues on long-lived flows
    intervals = intervals[-2000:]
    if payload_entropies: payload_entropies = payload_entropies[-2000:]
    if packet_sizes: packet_sizes = packet_sizes[-2000:]
    if dst_ips: dst_ips = dst_ips[-2000:]

    flags = []
    intervals_arr = np.array(intervals, dtype=float)
    std_int = np.std(intervals_arr)
    mean_int = float(np.mean(intervals_arr))
    observed_duration = sum(intervals)

    # Fast-path detection with duration gating
    if std_int < max(1.5, 0.3 * mean_int):
        if payload_entropies and len(payload_entropies) == len(intervals):
            mean_ent = float(np.mean(payload_entropies))
            if mean_ent > 0.88 and observed_duration > 300:
                flags.append(f"ML Fast-Path High-Entropy Beacon (Jittered: {mean_int:.2f}s)")
                return "; ".join(flags), 68
        if observed_duration > 180:
            flags.append(f"ML Fast-Path Beaconing (Jittered: {mean_int:.2f}s ±{std_int:.2f})")
            return "; ".join(flags), 55

    # Infrastructure heuristics (Fast Flux + DGA)
    flux_score = dga_score = 0
    if dst_ips and len(set(dst_ips)) >= 5:
        is_ff, flux_score, ff_reason = detect_fast_flux(dst_ips, ttls, asns)
        if is_ff and observed_duration > 120:
            flags.append(f"FAST_FLUX: {ff_reason}")
    if domain:
        is_dga, dga_score, dga_reason = detect_dga(domain)
        if is_dga:
            flags.append(f"DGA: {dga_reason}")

    # 4D Feature Space construction (interval + entropy + packet size + subnet diversity)
    features = [intervals_arr]
    if payload_entropies and len(payload_entropies) == len(intervals):
        features.append(np.array(payload_entropies, dtype=float))
    if packet_sizes and len(packet_sizes) == len(intervals):
        features.append(np.array(packet_sizes, dtype=float))

    # Dynamic subnet diversity score (campaign indicator)
    subnet_score = 12.0
    if dst_ips and len(dst_ips) == len(intervals):
        normalized_cidrs = [_normalize_cidr(ip) for ip in dst_ips]
        unique_subnets = len(set(normalized_cidrs))
        diversity_ratio = unique_subnets / len(normalized_cidrs)
        subnet_score = min(88.0, diversity_ratio * 75 + unique_subnets * 5.5) if unique_subnets > 1 else 12.0
    features.append(np.full(len(intervals), subnet_score))

    X = StandardScaler().fit_transform(np.column_stack(features))

    # K-Means clustering with silhouette optimization
    max_k = min(8, len(X) - 1)
    if max_k > 1:
        results = Parallel(n_jobs=-1)(delayed(compute_silhouette)(k, X) for k in range(2, max_k + 1))
        best_k, best_score, _, best_labels = max(((k, score, km, lbl) for k, score, km, lbl in results if score > 0.45), default=(0, 0, None, None))
        if best_k > 0:
            min_std = min(np.std(intervals_arr[np.where(best_labels == i)[0]])
                         for i in range(best_k) if len(np.where(best_labels == i)[0]) >= 8)
            if min_std <= 10.0:
                flags.append(f"ML 4D K-Means Beaconing (Clusters: {best_k}, Core StdDev: {min_std:.2f})")

    # DBSCAN clustering with adaptive epsilon
    if len(X) >= 8:
        try:
            nn = NearestNeighbors(n_neighbors=8)
            distances = nn.fit(X).kneighbors(X)[0]
            eps = np.percentile(distances[:, -1], 90)
            if eps > 0:
                labels = DBSCAN(eps=eps, min_samples=8).fit_predict(X)
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

    # Refined confidence scoring with duration and signal-strength penalties
    base_conf = 38
    if observed_duration < 180:
        base_conf -= 22
    if len(intervals) < 10:
        return None, 0

    confidence = min(95, base_conf + len(flags) * 23 + int(flux_score * 0.45) + int(dga_score * 0.35))
    if confidence > 70 and len(flags) == 1 and flux_score < 30 and dga_score < 30:
        confidence -= 18

    result = "; ".join(flags)
    print(f"[BeaconML Debug] Final: {result} | Confidence: {confidence} (duration={observed_duration:.0f}s)")
    return result, confidence


# ====================== CAMPAIGN CORRELATION ENGINE ======================
# Analyzes all active flows and DNS resolutions for coordinated multi-flow / Fast-Flux campaigns
def detect_advanced_c2(flows: dict, dns_resolutions: dict = None):
    print(f"[BeaconML Campaign] Analyzing {len(flows)} flows + DNS context")
    flags = []
    global_conf = 0

    # Group flows by process and detect multiple beacons from same parent
    proc_groups = defaultdict(list)
    for flow in flows.values():
        proc = flow.get("process", {}).get("name", "unknown")
        proc_groups[proc].append(flow)

    for proc, flist in proc_groups.items():
        if len(flist) >= 3:
            beacon_count = sum(1 for f in flist if len(f.get("intervals", [])) >= 8 and np.std(f["intervals"]) / (np.mean(f["intervals"]) + 1e-6) < 0.28)
            if beacon_count >= 2:
                flags.append(f"MULTI-FLOW_CAMPAIGN: {proc} ({beacon_count} beacons)")
                global_conf += 35

    # Correlate DNS resolutions with Fast Flux / DGA
    if dns_resolutions:
        for dom, data in dns_resolutions.items():
            ips = data.get("ips", [])
            if len(ips) >= 5:
                is_ff, ff_s, _ = detect_fast_flux(ips, data.get("ttls", []))
                is_dga, dga_s, _ = detect_dga(dom)
                if (is_ff or is_dga) and sum(data.get("timestamps", [0])) > 180:
                    flags.append(f"ADVANCED_C2: {dom} (Flux:{ff_s} DGA:{dga_s})")
                    global_conf += 42

    result = "; ".join(flags) if flags else None
    return result, min(94, global_conf)


# ====================== COMMAND-LINE INTERFACE ======================
# Allows standalone testing of single-flow detection
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BeaconML v3.0 - Advanced C2 Beacon Detection")
    parser.add_argument("data_file", help="Path to JSON file containing flow metrics")
    args = parser.parse_args()

    try:
        with open(args.data_file, 'r') as f:
            data = json.load(f)
        result, conf = detect_beaconing_list(data)
        if result:
            print(f"\n[!] DETECTION: {result}")
            print(f"[!] CONFIDENCE: {conf}/100")
        else:
            print("\n[-] No advanced beaconing detected.")
    except Exception as e:
        print(f"Error executing BeaconML: {e}")