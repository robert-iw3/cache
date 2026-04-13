#!/bin/bash

# Configuration
VENV_NAME="beacon_venv"
PYTHON_SCRIPT="beacon_validation.py"

# Function to handle cleanup on exit or interruption
cleanup() {
    echo ""
    echo "========================================"
    echo "[-] Cleaning up resources..."
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        deactivate 2>/dev/null
    fi
    if [ -d "$VENV_NAME" ]; then
        rm -rf "$VENV_NAME"
    fi
    if [ -f "$PYTHON_SCRIPT" ]; then
        rm -f "$PYTHON_SCRIPT"
    fi
    echo "[*] Done."
    echo "========================================"
}
trap cleanup EXIT INT TERM

echo "========================================"
echo "[+] Starting Beacon Validation Wrapper (Fix Applied)"
echo "========================================"

# 1. Create the Python file
echo "[+] Generating $PYTHON_SCRIPT..."

cat << 'EOF' > "$PYTHON_SCRIPT"
import math
import time
import warnings
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.exceptions import ConvergenceWarning

# Suppress Warnings
warnings.filterwarnings("ignore", category=ConvergenceWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# Parameters
MIN_CONNECTIONS_FOR_BEACON = 3
MAX_INTERVAL_VARIANCE_SECONDS = 10
VOLUME_THRESHOLD = 50
BEACON_WINDOW_MINUTES = 60
ACF_THRESHOLD = 0.5
JITTER_RATIO_THRESHOLD = 0.2
PERIOD_POWER_THRESHOLD = 0.5
MAX_HISTORY_KEYS = 1000
MAX_SAMPLES = 1000

# In-memory history
connection_history = {}
connection_volume = {}

def add_connection(key, timestamp):
    if key not in connection_history:
        connection_history[key] = []
    connection_history[key].append(timestamp)
    if key not in connection_volume:
        connection_volume[key] = 0
    connection_volume[key] += 1

def prune_history(now):
    keys_to_remove = []
    for key in list(connection_history.keys()):
        connection_history[key] = [t for t in connection_history[key] if t > now - (BEACON_WINDOW_MINUTES * 60)]
        if not connection_history[key]:
            keys_to_remove.append(key)
    for key in keys_to_remove:
        connection_history.pop(key, None)
        connection_volume.pop(key, None)
    if len(connection_history) > MAX_HISTORY_KEYS:
        sorted_keys = sorted(connection_history.keys(), key=lambda k: max(connection_history[k]))
        oldest_keys = sorted_keys[:len(connection_history) - MAX_HISTORY_KEYS]
        for key in oldest_keys:
            connection_history.pop(key, None)
            connection_volume.pop(key, None)

def check_beaconing(key, now, std_threshold=10.0, use_dbscan=False, use_isolation=False):
    if key not in connection_history or len(connection_history[key]) < MIN_CONNECTIONS_FOR_BEACON:
        return None
    times = sorted([t for t in connection_history[key] if t > now - (BEACON_WINDOW_MINUTES * 60)])
    if len(times) < MIN_CONNECTIONS_FOR_BEACON:
        return None
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

    if len(intervals) > MAX_SAMPLES:
        intervals = np.random.choice(intervals, MAX_SAMPLES, replace=False).tolist()
    if not intervals:
        return None

    avg = np.mean(intervals)
    variance = np.var(intervals)
    std_dev = math.sqrt(variance)
    flags = []

    # --- 1. Basic Stats (Always Run) ---
    if std_dev < MAX_INTERVAL_VARIANCE_SECONDS:
        flags.append(f"Basic Beaconing (StdDev: {std_dev:.2f} seconds)")
    if avg > 0 and (variance / avg) < JITTER_RATIO_THRESHOLD:
        flags.append(f"Controlled Jitter Beaconing (Ratio: {(variance / avg):.2f})")

    # --- 2. Advanced Analysis (Requires Minimum Data Density) ---
    # We require at least 4 intervals (5 connections) to run ML/Periodic logic.
    # Anything less produces statistical noise (like Test 3 failure).
    if len(intervals) >= 4:

        # A. ACF Lag 1
        series1 = intervals[:-1]
        series2 = intervals[1:]
        mean1 = np.mean(series1)
        mean2 = np.mean(series2)
        cov = sum((series1[j] - mean1) * (series2[j] - mean2) for j in range(len(series1)))
        var1 = sum((x - mean1) ** 2 for x in series1)
        var2 = sum((x - mean2) ** 2 for x in series2)
        if var1 > 0 and var2 > 0:
            acf = cov / math.sqrt(var1 * var2)
            if acf > ACF_THRESHOLD:
                flags.append(f"Periodic Beaconing (ACF: {acf:.2f})")

        # B. Lomb-Scargle approximation
        normalized_times = [t - times[0] for t in times]
        periods = [30, 60, 120, 300]
        max_power = 0
        for p in periods:
            omega = 2 * math.pi / p
            sin_sum = sum(math.sin(omega * t) for t in normalized_times)
            cos_sum = sum(math.cos(omega * t) for t in normalized_times)
            power = (sin_sum ** 2 + cos_sum ** 2) / len(normalized_times)
            if power > max_power:
                max_power = power
        if max_power > PERIOD_POWER_THRESHOLD:
            flags.append(f"Periodic Beaconing (Power: {max_power:.2f})")

        # C. Prepare Data for ML
        X = np.array(intervals).reshape(-1, 1)

        # ML K-Means
        silhouettes = []
        max_k = min(5, len(X))

        for k in range(2, max_k):
            kmeans = KMeans(n_clusters=k, random_state=0, n_init=10)
            labels = kmeans.fit_predict(X)
            unique_labels = np.unique(labels)
            if 1 < len(unique_labels) < len(X):
                score = silhouette_score(X, labels)
                silhouettes.append((k, score, kmeans, labels))

        if silhouettes:
            best_k, best_score, best_kmeans, best_labels = max(silhouettes, key=lambda x: x[1])

            # FIX: Only consider clusters with > 1 item.
            # A cluster of 1 item has StdDev 0.0, which creates False Positives.
            valid_cluster_stds = []
            for i in np.unique(best_labels):
                cluster_points = X[best_labels == i]
                if len(cluster_points) > 1:
                    valid_cluster_stds.append(np.std(cluster_points))

            if valid_cluster_stds:
                min_std = min(valid_cluster_stds)
                if min_std < std_threshold:
                    flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, Score: {best_score:.2f})")

        # ML DBSCAN
        if use_dbscan:
            eps = max(std_threshold / 2, np.std(X) / 2) if len(X) > 0 else std_threshold / 2
            dbscan = DBSCAN(eps=eps, min_samples=3)
            labels = dbscan.fit_predict(X)
            # Check deviation of core points (not noise -1)
            valid_points = X[labels != -1]
            # DBSCAN needs at least 2 points to be meaningful for variance
            if len(valid_points) > 1:
                core_std = np.std(valid_points)
                if core_std < std_threshold:
                    flags.append(f"ML DBSCAN Beaconing (Core StdDev: {core_std:.2f})")

        # ML Isolation Forest
        if use_isolation:
            iso = IsolationForest(contamination=0.1, random_state=0)
            anomalies = iso.fit_predict(X)
            anomaly_ratio = np.sum(anomalies == -1) / len(X)
            if anomaly_ratio > 0.05:
                flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {anomaly_ratio:.2f})")

    if flags:
        return '; '.join(flags)
    return None

def check_volume(key):
    if key in connection_volume and connection_volume[key] > VOLUME_THRESHOLD:
        return f"High volume detected (Count: {connection_volume[key]})"
    return None

def run_validation_tests(use_dbscan=False, use_isolation=False):
    test_key = "example.com:443"
    now = 10000.0

    print("-" * 40)
    print("STARTING VALIDATION TESTS")
    print("-" * 40)

    # Test 1: Regular Beaconing
    print("Test 1: Regular Beaconing")
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    # Add enough points to trigger ML (5 points = 4 intervals)
    for t in [now-240, now-180, now-120, now-60, now]:
        add_connection(test_key, t)

    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    volume_result = check_volume(test_key)
    print(f"  Result: {beacon_result}")
    assert beacon_result and "Basic Beaconing" in str(beacon_result), "Test 1 Failed"

    # Test 2: Jittered Beaconing
    print("\nTest 2: Jittered Beaconing")
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    # Jittered: 60s +/- variance
    # timestamps: -240, -181 (59), -119 (62), -58 (61), 0 (58)
    for t in [now-240, now-181, now-119, now-58, now]:
        add_connection(test_key, t)

    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"  Result: {beacon_result}")
    assert beacon_result and ("Controlled Jitter" in str(beacon_result) or "ML K-Means" in str(beacon_result)), "Test 2 Failed"

    # Test 3: Random No Beacon (The one that failed before)
    print("\nTest 3: Random No Beacon (Sparse Data)")
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    # Timestamps: -200, -50, -10, 0 -> Intervals: 150, 40, 10
    # This has 3 intervals. Code now requires 4 for ML.
    # Basic Stats: Avg 66, StdDev ~59. Should NOT trigger Basic Beaconing (<10).
    for t in [now-200, now-50, now-10, now]:
        add_connection(test_key, t)

    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"  Result: {beacon_result}")
    assert beacon_result is None or "No" in str(beacon_result), "Test 3 Failed"

    # Test 4: High Volume
    print("\nTest 4: High Volume")
    for _ in range(55):
        add_connection(test_key, now)
    volume_result = check_volume(test_key)
    print(f"  Result: {volume_result}")
    assert volume_result and "High volume" in str(volume_result), "Test 4 Failed"

    # Test 5: Pruning
    print("\nTest 5: Pruning")
    for i in range(5):
        old_key = f"old_key{i}"
        connection_history[old_key] = [now - 3601]
        connection_volume[old_key] = 1
    prune_history(now)
    print(f"  After Prune Count: {len(connection_history)}")
    assert len(connection_history) == 1, "Test 5 Failed"

    # Test 7: Large Dataset
    print("\nTest 7: Large Dataset (Jittered)")
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    current_t = now - 10000
    for _ in range(2000):
        jitter = np.random.uniform(-2, 2)
        current_t += 5 + jitter
        add_connection(test_key, current_t)
    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"  Result: {beacon_result}")
    assert beacon_result and ("ML K-Means" in str(beacon_result) or "Basic Beaconing" in str(beacon_result)), "Test 7 Failed"

    print("\n" + "="*40)
    print("SUCCESS: All Tests Passed!")
    print("="*40)

if __name__ == "__main__":
    run_validation_tests(use_dbscan=True, use_isolation=True)
EOF

# 2. Check for Python3
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 could not be found."
    exit 1
fi

# 3. Create Virtual Environment
echo "[+] Creating virtual environment '$VENV_NAME'..."
python3 -m venv "$VENV_NAME"

# 4. Activate and Install Dependencies
echo "[+] Activating environment and installing dependencies..."
source "$VENV_NAME/bin/activate"

# Upgrade pip quietly
pip install --upgrade pip -q

# Install numpy and scikit-learn quietly
echo "    Installing numpy and scikit-learn (this may take a moment)..."
pip install numpy scikit-learn -q

# 5. Run the Script
echo "[+] Running Validation Tests..."
python "$PYTHON_SCRIPT"