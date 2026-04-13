"""
BeaconML.py
Advanced ML-based beaconing detection using K-Means clustering, Adaptive DBSCAN,
Isolation Forest, AND Lomb-Scargle spectral analysis for jitter-resistant detection.

Author: Robert Weber
Version: 2.5

This module provides a comprehensive approach to detect beaconing patterns in network traffic
by analyzing intervals between events. It combines multiple machine learning techniques to
identify potential beaconing behavior, including:
- K-Means clustering with silhouette analysis to find tight clusters of intervals.
- Adaptive DBSCAN to identify dense clusters without needing a fixed epsilon.
- Isolation Forest to detect anomalous intervals that may indicate beaconing.
- Lomb-Scargle periodogram analysis to detect periodicity in event timestamps, even with jitter.
"""

import sys
import json
import argparse
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors
from joblib import Parallel, delayed
from astropy.timeseries import LombScargle
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    """Helper to compute silhouette score for a specific k."""
    if len(X) < k:
        return k, -1, None, None

    kmeans = KMeans(n_clusters=k, random_state=0, n_init=10)
    labels = kmeans.fit_predict(X)

    n_labels = len(np.unique(labels))
    n_samples = len(X)

    if 1 < n_labels < n_samples:
        try:
            score = silhouette_score(X, labels)
            return k, score, kmeans, labels
        except Exception:
            return k, -1, None, None
    return k, -1, None, None

def adaptive_eps_kdist(X, k_percent=5.0):
    """Calculates adaptive EPS for DBSCAN using k-distance elbow."""
    if len(X) < 10:
        return 1.0

    n_neighbors = max(2, int(len(X) * k_percent / 100) + 1)
    neigh = NearestNeighbors(n_neighbors=n_neighbors)
    nbrs = neigh.fit(X)
    distances, _ = nbrs.kneighbors(X)
    dist = np.sort(distances[:, -1])

    if len(dist) > 0:
        return float(np.percentile(dist, 90))
    return 1.0


def detect_lombscargle_beaconing(timestamps, power_threshold=0.20, circ_var_threshold=0.45,
                                 min_events=8, min_period=5.0, max_period=7200.0):
    """Lomb-Scargle periodogram + circular phase clustering for jittered beacons."""
    if len(timestamps) < min_events:
        return None
    try:
        t = np.sort(np.array(timestamps, dtype=float))
        ls = LombScargle(t, np.ones(len(t)), normalization='standard')

        freqs, powers = ls.autopower(
            minimum_frequency=1.0 / max_period,
            maximum_frequency=1.0 / min_period,
            samples_per_peak=10
        )
        if len(powers) == 0:
            return None

        best_idx = np.argmax(powers)
        best_power = powers[best_idx]
        best_freq = freqs[best_idx]
        if best_freq <= 0:
            return None

        best_period = 1.0 / best_freq
        phases = (t % best_period) / best_period
        angles = 2 * np.pi * phases
        R = np.sqrt(np.mean(np.cos(angles))**2 + np.mean(np.sin(angles))**2)
        circ_var = 1.0 - R

        if best_power > power_threshold and circ_var < circ_var_threshold:
            return f"LombScargle Jittered Beacon (Period: {best_period:.1f}s, Power: {best_power:.2f}, CircVar: {circ_var:.3f})"
    except Exception:
        pass
    return None


def detect_beaconing_list(intervals, timestamps=None, std_threshold=10.0, min_samples=3,
                          use_dbscan=True, use_isolation=True, n_jobs=-1, max_samples=2000):
    """Main detection entry point (timestamps enables Lomb-Scargle)."""
    if not intervals or len(intervals) < min_samples:
        return None

    X = np.array(intervals).reshape(-1, 1)
    if len(X) > max_samples:
        np.random.seed(42)
        indices = np.random.choice(len(X), max_samples, replace=False)
        X_sub = X[indices]
    else:
        X_sub = X

    flags = []

    # 1. K-Means
    max_k = min(5, len(X_sub) - 1)
    if max_k >= 2:
        results = Parallel(n_jobs=n_jobs)(
            delayed(compute_silhouette)(k, X_sub) for k in range(2, max_k + 1)
        )
        valid = [r for r in results if r[1] > -1]
        valid.sort(key=lambda x: x[1], reverse=True)
        if valid:
            best_k, best_score, _, best_labels = valid[0]
            if best_score > 0.6:
                unique, counts = np.unique(best_labels, return_counts=True)
                largest = unique[np.argmax(counts)]
                std_dev = np.std(X_sub[best_labels == largest])
                if std_dev < std_threshold:
                    flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {std_dev:.2f}, Score: {best_score:.2f})")

    # 2. Adaptive DBSCAN
    if use_dbscan:
        try:
            eps = max(adaptive_eps_kdist(X_sub), 0.5)
            db = DBSCAN(eps=eps, min_samples=min_samples).fit(X_sub)
            labels = db.labels_
            for label in set(labels) - {-1}:
                cluster = X_sub[labels == label]
                if len(cluster) >= min_samples and np.std(cluster) < std_threshold:
                    flags.append(f"ML Adaptive DBSCAN Beaconing (Core StdDev: {np.std(cluster):.2f}, eps={eps:.3f})")
                    break
        except Exception:
            pass

    # 3. Isolation Forest
    if use_isolation and len(X_sub) >= 10:
        iso = IsolationForest(contamination=0.1, random_state=42, n_jobs=n_jobs)
        anomalies = iso.fit_predict(X_sub)
        ratio = np.sum(anomalies == -1) / len(X_sub)
        if 0.05 < ratio < 0.40:
            flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {ratio:.2f})")

    # 4. Lomb-Scargle (new in v2.5)
    if timestamps is not None and len(timestamps) >= 8:
        lomb = detect_lombscargle_beaconing(timestamps)
        if lomb:
            flags.append(lomb)

    return '; '.join(flags) if flags else None


def detect_beaconing(intervals_file, std_threshold=10.0, min_samples=3, use_dbscan=True,
                     use_isolation=True, n_jobs=-1, max_samples=2000):
    """Original file-based wrapper (unchanged API)."""
    try:
        with open(intervals_file, 'r') as f:
            intervals = json.load(f)
    except Exception as e:
        return f"Error loading file: {str(e)}"
    return detect_beaconing_list(intervals, None, std_threshold, min_samples, use_dbscan, use_isolation, n_jobs, max_samples)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Beaconing Detection v2.5")
    parser.add_argument("intervals_file", help="Path to intervals JSON file")
    parser.add_argument("--std_threshold", type=float, default=10.0, help="StdDev threshold for tight clusters")
    parser.add_argument("--min_samples", type=int, default=3, help="Min samples for DBSCAN/Clusters")
    parser.add_argument("--use_dbscan", action="store_true", help="Enable DBSCAN")
    parser.add_argument("--use_isolation", action="store_true", help="Enable Isolation Forest")
    parser.add_argument("--n_jobs", type=int, default=-1, help="Parallel jobs (-1 for all cores)")

    args = parser.parse_args()
    result = detect_beaconing(args.intervals_file, args.std_threshold, args.min_samples,
                              args.use_dbscan, args.use_isolation, args.n_jobs)
    print(f"BEACON DETECTED: {result}" if result else "No beaconing detected.")