import math
import time
import numpy as np
from sklearn.cluster import KMeans

# Simulated Version 2 beaconing logic in Python for validation
# Updated for new BeaconML.py features: subsampling, adaptive eps, etc.
# Tests: Regular, Jittered, Random, High Volume, Pruning, Periodogram, Large Dataset

# Parameters (defaults from script)
MIN_CONNECTIONS_FOR_BEACON = 3
MAX_INTERVAL_VARIANCE_SECONDS = 10
VOLUME_THRESHOLD = 50
BEACON_WINDOW_MINUTES = 60
ACF_THRESHOLD = 0.5
JITTER_RATIO_THRESHOLD = 0.2
PERIOD_POWER_THRESHOLD = 0.5
MAX_HISTORY_KEYS = 1000
MAX_SAMPLES = 1000  # New: for subsampling

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
        # Sort by oldest max timestamp
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
    # Subsample if large (new)
    if len(intervals) > MAX_SAMPLES:
        intervals = np.random.choice(intervals, MAX_SAMPLES, replace=False).tolist()
    if not intervals:
        return None
    avg = np.mean(intervals)
    variance = np.var(intervals)
    std_dev = math.sqrt(variance)
    flags = []
    if std_dev < MAX_INTERVAL_VARIANCE_SECONDS:
        flags.append(f"Basic Beaconing (StdDev: {std_dev:.2f} seconds)")
    if avg > 0 and (variance / avg) < JITTER_RATIO_THRESHOLD:
        flags.append(f"Controlled Jitter Beaconing (Ratio: {(variance / avg):.2f})")
    # ACF Lag 1
    if len(intervals) >= 2:
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
    # Lomb-Scargle approximation
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
    # ML K-Means (dynamic k with silhouettes)
    if len(intervals) >= 3:
        X = np.array(intervals).reshape(-1, 1)
        silhouettes = []
        for k in range(2, min(5, len(X) + 1)):
            kmeans = KMeans(n_clusters=k, random_state=0, n_init=1)
            labels = kmeans.fit_predict(X)
            if len(np.unique(labels)) > 1:
                score = silhouette_score(X, labels)
                silhouettes.append((k, score, kmeans, labels))
        if silhouettes:
            best_k, best_score, best_kmeans, best_labels = max(silhouettes, key=lambda x: x[1])
            cluster_std = [np.std(X[best_labels == i]) for i in np.unique(best_labels)]
            min_std = min(cluster_std)
            if min_std < std_threshold:
                flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, Score: {best_score:.2f})")
    # DBSCAN (adaptive eps - new)
    if use_dbscan and len(intervals) >= 3:
        eps = max(std_threshold / 2, np.std(X) / 2) if len(X) > 0 else std_threshold / 2
        dbscan = DBSCAN(eps=eps, min_samples=3)
        labels = dbscan.fit_predict(X)
        core_std = np.std(X[labels != -1]) if np.any(labels != -1) else float('inf')
        if core_std < std_threshold:
            flags.append(f"ML DBSCAN Beaconing (Core StdDev: {core_std:.2f})")
    # Isolation Forest (new)
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

# Run Validation Tests with Timing
def run_validation_tests(use_dbscan=False, use_isolation=False):
    test_key = "example.com:443"
    now = 10000.0 # Simulated current time in seconds

    # Test 1: Regular Beaconing
    print("Test 1: Regular Beaconing")
    start = time.time()
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    add_connection(test_key, now - 180)
    add_connection(test_key, now - 120)
    add_connection(test_key, now - 60)
    add_connection(test_key, now)
    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    volume_result = check_volume(test_key)
    print(f"Beacon: {beacon_result}")
    print(f"Volume: {volume_result}")
    print(f"Time: {time.time() - start:.4f}s")
    assert "Basic Beaconing" in str(beacon_result), "Test 1 Failed"

    # Test 2: Jittered Beaconing
    print("\nTest 2: Jittered Beaconing")
    start = time.time()
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    add_connection(test_key, now - 240)
    add_connection(test_key, now - 181)
    add_connection(test_key, now - 119)
    add_connection(test_key, now - 58)
    add_connection(test_key, now)
    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"Beacon: {beacon_result}")
    print(f"Time: {time.time() - start:.4f}s")
    assert "Controlled Jitter" in str(beacon_result) or "ML K-Means Beaconing" in str(beacon_result), "Test 2 Failed"

    # Test 3: Random No Beacon
    print("\nTest 3: Random No Beacon")
    start = time.time()
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    add_connection(test_key, now - 200)
    add_connection(test_key, now - 50)
    add_connection(test_key, now - 10)
    add_connection(test_key, now)
    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"Beacon: {beacon_result}")
    print(f"Time: {time.time() - start:.4f}s")
    assert beacon_result is None or "No" in str(beacon_result), "Test 3 Failed"

    # Test 4: High Volume
    print("\nTest 4: High Volume")
    start = time.time()
    for _ in range(55):
        add_connection(test_key, now)
    volume_result = check_volume(test_key)
    print(f"Volume: {volume_result}")
    print(f"Time: {time.time() - start:.4f}s")
    assert "High volume" in str(volume_result), "Test 4 Failed"

    # Test 5: Pruning
    print("\nTest 5: Pruning")
    start = time.time()
    for i in range(5):
        old_key = f"old_key{i}"
        connection_history[old_key] = [now - 3601] # Older than window
        connection_volume[old_key] = 1
    prune_history(now)
    print(f"After Prune: History Count = {len(connection_history)}")
    print(f"Time: {time.time() - start:.4f}s")
    assert len(connection_history) == 1, "Test 5 Failed" # Only test_key remains

    # Test 6: Periodogram with Periodic Data
    print("\nTest 6: Periodogram with Periodic Data")
    start = time.time()
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    add_connection(test_key, now - 180)
    add_connection(test_key, now - 120)
    add_connection(test_key, now - 60)
    add_connection(test_key, now)
    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"Beacon: {beacon_result}")
    print(f"Time: {time.time() - start:.4f}s")
    assert "Periodic Beaconing (Power" in str(beacon_result), "Test 6 Failed"

    # Test 7: Large Dataset (n=2000 jittered)
    print("\nTest 7: Large Dataset Jittered Beaconing")
    start = time.time()
    connection_history[test_key] = []
    connection_volume[test_key] = 0
    current_t = now - 10000
    for _ in range(2000):
        jitter = np.random.uniform(-2, 2)
        current_t += 5 + jitter  # ~5s intervals with jitter
        add_connection(test_key, current_t)
    beacon_result = check_beaconing(test_key, now, use_dbscan=use_dbscan, use_isolation=use_isolation)
    print(f"Beacon: {beacon_result}")
    print(f"Time: {time.time() - start:.4f}s")
    assert "ML K-Means Beaconing" in str(beacon_result) or "Basic Beaconing" in str(beacon_result), "Test 7 Failed"

    print("\nAll Tests Passed!")

run_validation_tests(use_dbscan=True, use_isolation=True)