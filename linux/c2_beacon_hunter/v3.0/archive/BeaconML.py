"""

BeaconML.py
Advanced ML-based beaconing detection using Multi-Dimensional Subnet Clustering.

Author: Robert Weber
Version: 3.0

Description:
Core mathematical engine for detecting Command and Control (C2) beaconing.
Upgraded for modern stealthy TTPs including jitter, malleable payloads,
sparse/long-sleep beacons, and high-entropy encryption.

Key Capabilities:
- 3D Feature Space (interval + entropy + packet-size CV)
- Adaptive jitter tolerance
- Confidence scoring (0-100)
- Zero heavy dependencies (astropy removed)

- v3.0 Subnet Clustering Edition
3D+ clustering (interval + entropy + subnet_score) with flow metadata.
Fast Flux + DGA + Campaign Correlation + Refined Confidence Scoring for FP suppression.
"""

import sys
import json
import argparse
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
from joblib import Parallel, delayed
import logging
import ipaddress
from collections import defaultdict, Counter
import math

logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    if len(X) < k:
        return k, -1, None, None
    try:
        kmeans = KMeans(n_clusters=k, random_state=0, n_init=10)
        labels = kmeans.fit_predict(X)
        n_labels = len(np.unique(labels))
        n_samples = len(X)
        if 1 < n_labels < n_samples:
            score = silhouette_score(X, labels)
            return k, score, kmeans, labels
    except:
        pass
    return k, -1, None, None

def _normalize_cidr(ip: str) -> str:
    try:
        if ':' in ip:
            return str(ipaddress.IPv6Network(ip + '/64', strict=False))
        else:
            return str(ipaddress.IPv4Network(ip + '/24', strict=False))
    except:
        return ip

def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(str(data))
    probs = [v / len(data) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def detect_dga(domain: str) -> tuple:
    if not domain or len(domain) < 6:
        return False, 0, ""
    domain = domain.lower().split('.')[0]
    entropy = shannon_entropy(domain)
    length = len(domain)
    cons_ratio = sum(1 for c in domain if c.isalpha() and c not in 'aeiou') / max(1, length)
    score = 0
    reasons = []
    if entropy > 3.7: score += 45; reasons.append("high_entropy")
    if length > 18: score += 25; reasons.append("long_label")
    if cons_ratio > 0.65: score += 30; reasons.append("consonant_heavy")
    is_dga = score >= 65
    return is_dga, min(92, score), "; ".join(reasons)

def detect_fast_flux(ips: list, ttls: list = None, domain: str = None) -> tuple:
    if len(ips) < 5:
        return False, 0, "insufficient_data"
    unique_ips = len(set(ips))
    normalized_cidrs = [_normalize_cidr(ip) for ip in ips]
    unique_cidrs = len(set(normalized_cidrs))
    diversity = unique_cidrs / unique_ips
    avg_ttl = np.mean(ttls) if ttls and len(ttls) > 0 else 300
    score = 0
    reasons = []
    if unique_ips >= 8: score += 35; reasons.append(f"high_churn({unique_ips})")
    if diversity > 0.55: score += 40; reasons.append(f"multi_subnet({unique_cidrs})")
    if avg_ttl < 180: score += 25; reasons.append(f"low_ttl({avg_ttl:.0f}s)")
    if domain:
        is_dga, dga_s, _ = detect_dga(domain)
        if is_dga: score += dga_s // 3
    is_ff = score >= 68
    return is_ff, min(90, score), "; ".join(reasons)

def detect_beaconing_list(intervals, timestamps=None, payload_entropies=None,
                          packet_sizes=None, dst_ips=None, domain=None, ttls=None,
                          std_threshold=10.0, min_samples=8, use_dbscan=True,
                          use_isolation=True, n_jobs=-1, max_samples=2000):
    print(f"[BeaconML v3.0] {len(intervals)} intervals | domain: {domain} | ips: {len(dst_ips) if dst_ips else 0}")

    if not intervals or len(intervals) < min_samples:
        return None, 0

    intervals = intervals[-max_samples:]
    if dst_ips: dst_ips = dst_ips[-max_samples:]
    if ttls: ttls = ttls[-max_samples:]

    flags = []
    intervals_arr = np.array(intervals, dtype=float)
    std_int = np.std(intervals_arr)
    mean_int = float(np.mean(intervals_arr))
    observed_duration = sum(intervals) if intervals else 0

    # Refined fast-path (stricter)
    if std_int < max(1.5, 0.3 * mean_int):
        if payload_entropies and len(payload_entropies) == len(intervals):
            mean_ent = float(np.mean(payload_entropies))
            if mean_ent > 0.88 and observed_duration > 300:
                flags.append(f"ML Fast-Path High-Entropy Beacon (Jittered: {mean_int:.2f}s)")
                return "; ".join(flags), 68
        if observed_duration > 180:
            flags.append(f"ML Fast-Path Beaconing (Jittered Timing: {mean_int:.2f}s ±{std_int:.2f})")
            return "; ".join(flags), 55
        return None, 0

    # === Fast Flux & DGA (disparate dataset) ===
    flux_score = dga_score = 0
    if dst_ips and len(set(dst_ips)) >= 5:
        is_ff, flux_score, ff_reason = detect_fast_flux(dst_ips, ttls, domain)
        if is_ff and observed_duration > 120:
            flags.append(f"FAST_FLUX: {ff_reason}")
    if domain:
        is_dga, dga_score, dga_reason = detect_dga(domain)
        if is_dga:
            flags.append(f"DGA: {dga_reason}")

    # 3D+ Feature Space with dynamic subnet scoring
    is_multidimensional = payload_entropies and len(payload_entropies) == len(intervals)
    subnet_score = 0.0
    if is_multidimensional:
        features = [intervals]
        if payload_entropies:
            features.append(payload_entropies)
        if packet_sizes and len(packet_sizes) == len(intervals):
            size_cv = np.std(packet_sizes) / (np.mean(packet_sizes) + 1e-6)
            features.append([size_cv] * len(intervals))
        if dst_ips and len(dst_ips) == len(intervals):
            normalized_subnets = [_normalize_cidr(ip) for ip in dst_ips]
            unique_subnets = len(set(normalized_subnets))
            total = len(normalized_subnets)
            diversity_ratio = unique_subnets / total
            subnet_score = min(88.0, diversity_ratio * 75 + unique_subnets * 5.5) if unique_subnets > 1 else 12.0
        features.append([subnet_score] * len(intervals))
        X = StandardScaler().fit_transform(np.column_stack(features))
    else:
        X = intervals_arr.reshape(-1, 1)

    # K-Means
    max_k = min(10, len(X) - 1)
    if max_k > 1:
        results = Parallel(n_jobs=n_jobs)(delayed(compute_silhouette)(k, X) for k in range(2, max_k + 1))
        best_k, best_score, _, best_labels = max(((k, score, km, lbl) for k, score, km, lbl in results if score > 0.5), default=(0, 0, None, None))
        if best_k > 0:
            min_std = min(np.std(np.array(intervals)[np.where(best_labels == i)[0]])
                         for i in range(best_k) if len(np.where(best_labels == i)[0]) >= min_samples)
            if min_std <= std_threshold:
                flags.append(f"ML 3D K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, Subnet: {subnet_score:.1f})")

    # DBSCAN
    if use_dbscan and len(X) >= min_samples:
        try:
            nn = NearestNeighbors(n_neighbors=min_samples)
            distances = nn.fit(X).kneighbors(X)[0]
            eps = np.percentile(distances[:, -1], 90)
            if eps > 0:
                labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(X)
                for label in set(labels):
                    if label != -1:
                        idx = np.where(labels == label)[0]
                        if len(idx) >= min_samples and np.std(np.array(intervals)[idx]) <= std_threshold:
                            flags.append(f"ML 3D Adaptive DBSCAN Beaconing (Core StdDev: {np.std(np.array(intervals)[idx]):.2f})")
                            break
        except:
            pass

    # Isolation Forest
    if use_isolation and len(X) >= min_samples:
        try:
            preds = IsolationForest(contamination=0.05, random_state=42).fit_predict(X)
            if (preds == -1).mean() > 0.05:
                flags.append(f"ML 3D Isolation Beaconing (Anomaly Ratio: {(preds == -1).mean():.2f})")
        except:
            pass

    if not flags:
        return None, 0

    # === REFINED CONFIDENCE SCORING (FP suppression) ===
    base_conf = 38
    if len(intervals) < 10:
        return None, 0
    if observed_duration < 180:
        base_conf -= 22
    if len(flags) == 1 and "Fast-Path" not in str(flags[0]):
        base_conf -= 12

    confidence = min(95, base_conf + len(flags) * 23 + int(flux_score * 0.45) + int(dga_score * 0.35))

    # Extra penalty for single weak signal
    if confidence > 70 and len(flags) == 1 and flux_score < 30 and dga_score < 30:
        confidence -= 18

    result = "; ".join(flags)
    print(f"[BeaconML Debug] Final: {result} | Confidence: {confidence} (duration={observed_duration:.0f}s)")
    return result, confidence


def detect_advanced_c2(flows: dict, dns_resolutions: dict = None):
    print(f"[BeaconML v3.0 Campaign] Analyzing {len(flows)} flows + DNS")
    flags = []
    global_conf = 0

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

    if dns_resolutions:
        for dom, data in dns_resolutions.items():
            ips = data.get("ips", [])
            if len(ips) >= 5:
                is_ff, ff_s, _ = detect_fast_flux(ips, data.get("ttls", []), dom)
                is_dga, dga_s, _ = detect_dga(dom)
                if (is_ff or is_dga) and sum(data.get("timestamps", [0])) > 180:
                    flags.append(f"ADVANCED_C2: {dom} (Flux:{ff_s} DGA:{dga_s})")
                    global_conf += 42

    result = "; ".join(flags) if flags else None
    return result, min(94, global_conf)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BeaconML v3.0 - Refined Confidence")
    parser.add_argument("intervals_file", help="Path to intervals JSON file")
    args = parser.parse_args()
    result, conf = detect_beaconing_list(json.load(open(args.intervals_file)))
    print(result)