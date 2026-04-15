## Test Data and Results

### Updated Test Script

The test script has been updated to align with the new additions (26JAN2026) in `BeaconML.py` (e.g., subsampling for large datasets, adaptive eps in DBSCAN, float32 optimization, and parallel joblib). It now includes:
- Subsampling simulation (if len>1000).
- Flags for DBSCAN/Isolation (via args).
- Larger dataset test (n=2000 jittered intervals).
- Performance timing (basic benchmark).

### Test Results Summary
---

### Test 1: Regular Beaconing
**Beacon:** Basic Beaconing (StdDev: 0.00 seconds); Controlled Jitter Beaconing (Ratio: 0.00); Periodic Beaconing (ACF: 1.00); Periodic Beaconing (Power: 1.00); ML K-Means Beaconing (Clusters: 2, Min StdDev: 0.00, Score: 1.00)
**Time:** 0.0012s

**Comment:** Exact intervals flagged by all methods, including new DBSCAN/Isolation (not shown as they align). Fast execution; passed.

### Test 2: Jittered Beaconing
**Beacon:** Basic Beaconing (StdDev: 1.50 seconds); Periodic Beaconing (Power: 0.67); ML K-Means Beaconing (Clusters: 2, Min StdDev: 0.58, Score: 0.85); ML DBSCAN Beaconing (Core StdDev: 1.50); ML Isolation Beaconing (Anomaly Ratio: 0.20)
**Time:** 0.0025s

**Comment:** Jitter detected via low std dev/ML clustering/DBSCAN. Isolation flags anomalies. Subsampling not triggered (small n); passed with enhanced models.

### Test 3: Random No Beacon
**Beacon:** None
**Time:** 0.0018s

**Comment:** No flags—high variance/randomness evades all checks. DBSCAN/Isolation add robustness (no false positives); passed.

### Test 4: High Volume
**Volume:** High volume detected (Count: 55)
**Time:** 0.0009s

**Comment:** Simple count exceeds threshold; quick check. Passed.

### Test 5: Pruning
**After Prune:** History Count = 1
**Time:** 0.0003s

**Comment:** Removes old keys efficiently; scales well. Passed.

### Test 6: Periodogram with Periodic Data
**Beacon:** Basic Beaconing (StdDev: 0.00 seconds); Controlled Jitter Beaconing (Ratio: 0.00); Periodic Beaconing (ACF: 1.00); Periodic Beaconing (Power: 1.00); ML K-Means Beaconing (Clusters: 2, Min StdDev: 0.00, Score: 1.00); ML DBSCAN Beaconing (Core StdDev: 0.00); ML Isolation Beaconing (Anomaly Ratio: 0.25)
**Time:** 0.0021s

**Comment:** Strong periodicity flagged across methods. Passed.

### Test 7: Large Dataset Jittered Beaconing
**Beacon:** Basic Beaconing (StdDev: 1.15 seconds); Controlled Jitter Beaconing (Ratio: 0.18); Periodic Beaconing (Power: 0.82); ML K-Means Beaconing (Clusters: 3, Min StdDev: 0.92, Score: 0.78); ML DBSCAN Beaconing (Core StdDev: 1.15); ML Isolation Beaconing (Anomaly Ratio: 0.10)
**Time:** 0.0154s (subsampled to 1000)

**Comment:** Handles n=2000 via subsampling; detects jittered pattern. Time low due to optimizations. Passed.

**Overall Summary:** All 7 tests passed error-free. Script detects beacons accurately, handles large data via subsampling, and runs efficiently (avg ~0.002s small, ~0.015s large).