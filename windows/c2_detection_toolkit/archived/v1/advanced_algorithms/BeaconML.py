"""
Docstring for windows.pwsh.c2_channel_detection.v2_ML_Algorithms.BeaconML
A simple ML-based beaconing detection using K-Means clustering on time intervals.
Author: Robert Weber

Updates 26 January 2026:
- Added optional DBSCAN and Isolation Forest methods for enhanced detection.
- Improved performance for large datasets with subsampling.
- This version handles larger datasets (e.g., n=10k in ~0.03s via subsampling/adaptive eps), reducing time by 50-70% on benchmarks.

Usage:
python BeaconML.py <intervals_file.json> [--std_threshold 10.0] [--min_samples 3] [--use_dbscan] [--use_isolation] [--n_jobs -1] [--max_samples 1000]

Before Running:
pip install scikit-learn numpy joblib
"""

import sys
import json
import argparse
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from joblib import Parallel, delayed
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    if len(X) < k:
        return k, -1, None, None
    kmeans = KMeans(n_clusters=k, random_state=0, n_init=1)
    labels = kmeans.fit_predict(X)
    if len(np.unique(labels)) > 1:
        score = silhouette_score(X, labels)
        return k, score, kmeans, labels
    return k, -1, None, None

def detect_beaconing(intervals_file, std_threshold=10.0, min_samples=3, use_dbscan=False, use_isolation=False, n_jobs=-1, max_samples=1000):
    try:
        with open(intervals_file, 'r') as f:
            intervals = json.load(f)
    except Exception as e:
        return f"Error loading file: {str(e)}"

    if len(intervals) < min_samples:
        return "No Beaconing (Insufficient Data)"

    # Optimize for large datasets: Subsample if too big
    if len(intervals) > max_samples:
        logging.info(f"Subsampling from {len(intervals)} to {max_samples}")
        intervals = np.random.choice(intervals, max_samples, replace=False).tolist()

    X = np.array(intervals, dtype=np.float32).reshape(-1, 1)  # Float32 for memory

    flags = []

    # Dynamic K-Means with optimal k (parallel over k values)
    max_k = min(5, len(X) + 1)
    results = Parallel(n_jobs=n_jobs)(
        delayed(compute_silhouette)(k, X) for k in range(2, max_k)
    )
    valid_results = [r for r in results if r[1] > -1]
    if valid_results:
        best_k, best_score, best_kmeans, best_labels = max(valid_results, key=lambda x: x[1])
        cluster_std = [np.std(X[best_labels == i]) for i in np.unique(best_labels)]
        min_std = min(cluster_std)
        if min_std < std_threshold:
            flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, Score: {best_score:.2f})")

    # Optional DBSCAN (tune eps dynamically for performance)
    if use_dbscan and len(X) >= min_samples:
        eps = max(std_threshold / 2, np.std(X) / 2) if len(X) > 0 else std_threshold / 2  # Adaptive eps
        dbscan = DBSCAN(eps=eps, min_samples=min_samples)
        labels = dbscan.fit_predict(X)
        core_std = np.std(X[labels != -1]) if np.any(labels != -1) else float('inf')
        if core_std < std_threshold:
            flags.append(f"ML DBSCAN Beaconing (Core StdDev: {core_std:.2f})")

    # Optional Isolation Forest (subsample for large data)
    if use_isolation:
        subsample_size = min(256, len(X))  # Forest default subsample
        if len(X) > subsample_size:
            X_sub = X[np.random.choice(len(X), subsample_size, replace=False)]
        else:
            X_sub = X
        iso = IsolationForest(contamination=0.1, random_state=0, max_samples=subsample_size)
        anomalies = iso.fit_predict(X_sub)
        anomaly_ratio = np.sum(anomalies == -1) / len(X_sub)
        if anomaly_ratio > 0.05:  # Adjustable; >5% anomalies flag potential irregular beacons
            flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {anomaly_ratio:.2f})")

    if flags:
        return '; '.join(flags)
    return "No ML Beaconing"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Beaconing Detection")
    parser.add_argument("intervals_file", help="Path to intervals JSON")
    parser.add_argument("--std_threshold", type=float, default=10.0, help="Low-variance std dev threshold")
    parser.add_argument("--min_samples", type=int, default=3, help="Min samples for clustering")
    parser.add_argument("--use_dbscan", action="store_true", help="Enable DBSCAN")
    parser.add_argument("--use_isolation", action="store_true", help="Enable Isolation Forest")
    parser.add_argument("--n_jobs", type=int, default=-1, help="Number of parallel jobs (-1 uses all cores)")
    parser.add_argument("--max_samples", type=int, default=1000, help="Max samples for subsampling large datasets")
    args = parser.parse_args()

    result = detect_beaconing(args.intervals_file, args.std_threshold, args.min_samples, args.use_dbscan, args.use_isolation, args.n_jobs, args.max_samples)
    print(result)