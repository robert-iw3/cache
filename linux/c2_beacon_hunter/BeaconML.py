"""
BeaconML.py
Advanced ML-based beaconing detection using Multi-Dimensional Clustering.

Author: Robert Weber
Version: 2.8.2 (UEBA False-Positive Suppression Edition)

Description:
Core mathematical engine for detecting Command and Control (C2) beaconing.
Upgraded for modern stealthy TTPs including jitter, malleable payloads,
sparse/long-sleep beacons, and high-entropy encryption.

Key Capabilities:
- 3D Feature Space (interval + entropy + packet-size CV)
- Adaptive jitter tolerance
- Confidence scoring (0-100)
- Zero heavy dependencies (astropy removed)
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

logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    if len(X) < k:
        return k, -1, None, None
    kmeans = KMeans(n_clusters=k, random_state=0, n_init=10)
    labels = kmeans.fit_predict(X)
    n_labels = len(np.unique(labels))
    n_samples = len(X)
    if 1 < n_labels < n_samples:
        score = silhouette_score(X, labels)
        return k, score, kmeans, labels
    return k, -1, None, None


def detect_beaconing_list(intervals, timestamps=None, payload_entropies=None,
                          packet_sizes=None, std_threshold=10.0,
                          min_samples=3, use_dbscan=True, use_isolation=True,
                          n_jobs=-1, max_samples=2000):
    print(f"[BeaconML Debug] Received {len(intervals)} intervals | entropy: {bool(payload_entropies)} | packet sizes: {bool(packet_sizes)}")

    if not intervals or len(intervals) < min_samples:
        print("[BeaconML Debug] Too few samples")
        return None, 0

    intervals = intervals[-max_samples:]
    if payload_entropies:
        payload_entropies = payload_entropies[-max_samples:]
    if packet_sizes:
        packet_sizes = packet_sizes[-max_samples:]

    flags = []
    intervals_arr = np.array(intervals)
    std_int = np.std(intervals_arr)
    mean_int = float(np.mean(intervals_arr))

    if std_int < max(1.5, 0.3 * mean_int):
        if payload_entropies and len(payload_entropies) == len(intervals):
            mean_ent = float(np.mean(payload_entropies))
            if mean_ent > 0.85:
                flags.append(f"ML 2D Fast-Path Beaconing (Jittered Timing: {mean_int:.2f}s ±{std_int:.2f}, High Entropy)")
                return "; ".join(flags), 92
        flags.append(f"ML Fast-Path Beaconing (Jittered Timing: {mean_int:.2f}s ±{std_int:.2f})")
        return "; ".join(flags), 78

    is_multidimensional = payload_entropies and len(payload_entropies) == len(intervals)
    if is_multidimensional:
        features = [intervals]
        if payload_entropies:
            features.append(payload_entropies)
        if packet_sizes and len(packet_sizes) == len(intervals):
            size_cv = np.std(packet_sizes) / (np.mean(packet_sizes) + 1e-6)
            features.append([size_cv] * len(intervals))
        X = StandardScaler().fit_transform(np.column_stack(features))
    else:
        X = intervals_arr.reshape(-1, 1)

    max_k = min(10, len(X) - 1)
    if max_k > 1:
        results = Parallel(n_jobs=n_jobs)(delayed(compute_silhouette)(k, X) for k in range(2, max_k + 1))
        best_k, best_score, _, best_labels = max(((k, score, km, lbl) for k, score, km, lbl in results if score > 0.5), default=(0, 0, None, None))
        if best_k > 0:
            min_std = min(np.std(np.array(intervals)[np.where(best_labels == i)[0]])
                         for i in range(best_k) if len(np.where(best_labels == i)[0]) >= min_samples)
            if min_std <= std_threshold:
                flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f})")

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
                            flags.append(f"ML Adaptive DBSCAN Beaconing (Core StdDev: {np.std(np.array(intervals)[idx]):.2f})")
                            break
        except:
            pass

    if use_isolation and len(X) >= min_samples:
        try:
            preds = IsolationForest(contamination=0.05, random_state=42).fit_predict(X)
            if (preds == -1).mean() > 0.05:
                flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {(preds == -1).mean():.2f})")
        except:
            pass

    result = "; ".join(flags) if flags else None
    confidence = min(95, 40 + len(flags) * 18) if flags else 0
    print(f"[BeaconML Debug] Final result: {result} | Confidence: {confidence}")
    return result, confidence


def detect_beaconing(intervals_file, **kwargs):
    try:
        with open(intervals_file, 'r') as f:
            intervals = json.load(f)
    except Exception as e:
        return f"Error: {e}", 0
    return detect_beaconing_list(intervals, **kwargs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Beaconing Detection v2.9")
    parser.add_argument("intervals_file", help="Path to intervals JSON file")
    args = parser.parse_args()
    result, conf = detect_beaconing(args.intervals_file)
    print(result)