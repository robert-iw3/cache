#!/bin/bash
set -e

# Configuration
VENV_DIR="test_venv_ml"
DRIVER_SCRIPT="test_driver.py"
TARGET_MODULE="BeaconML.py"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

cleanup() {
    echo -e "\n${CYAN}[*] Teardown: Cleaning up resources...${NC}"
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        deactivate 2>/dev/null || true
    fi

    if [ -d "$VENV_DIR" ]; then
        rm -rf "$VENV_DIR"
        echo "    Removed virtual environment: $VENV_DIR"
    fi

    if [ -f "$DRIVER_SCRIPT" ]; then
        rm -f "$DRIVER_SCRIPT"
        echo "    Removed test driver: $DRIVER_SCRIPT"
    fi
    echo -e "${GREEN}[+] Cleanup complete.${NC}"
}
trap cleanup EXIT INT TERM

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}    BeaconML.py Comprehensive Test Suite${NC}"
echo -e "${CYAN}====================================================${NC}"

# 1. Pre-flight Checks
if [ ! -f "$TARGET_MODULE" ]; then
    echo -e "${RED}[-] Error: $TARGET_MODULE not found in current directory!${NC}"
    exit 1
fi

# 2. Setup Environment
echo -e "${YELLOW}[*] Setting up temporary virtual environment...${NC}"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# 3. Install Dependencies
echo -e "${YELLOW}[*] Installing ML dependencies (numpy, scikit-learn, joblib)...${NC}"
# Upgrade pip to avoid warnings
pip install --upgrade pip -q
# Install required libs (suppress output)
pip install numpy scikit-learn joblib pandas -q

# 4. Create Python Test Driver
echo -e "${YELLOW}[*] Generating Test Driver ($DRIVER_SCRIPT)...${NC}"

cat << 'EOF' > "$DRIVER_SCRIPT"
import sys
import numpy as np
import logging

# Configure logging to show only errors/critical info during tests
logging.basicConfig(level=logging.ERROR)

try:
    from BeaconML import detect_beaconing_list
except ImportError:
    print("\n[!] Error: Could not import BeaconML. Make sure BeaconML.py is in the directory.")
    sys.exit(1)

# --- Test Data Generators ---

def generate_perfect_beacon(interval=60, count=20):
    return [interval] * count

def generate_jittered_beacon(interval=60, jitter_pct=0.1, count=50):
    # Jitter between -10% and +10%
    noise = np.random.uniform(-jitter_pct, jitter_pct, count)
    return [interval * (1 + x) for x in noise]

def generate_multi_modal(intervals=[60, 300], count=50):
    # Alternating intervals (e.g. Sleep Masking)
    data = []
    for i in range(count):
        data.append(intervals[i % len(intervals)])
    # Add slight jitter
    noise = np.random.uniform(-0.02, 0.02, count)
    return [d * (1 + n) for d, n in zip(data, noise)]

def generate_random_noise(low=1, high=1000, count=50):
    return np.random.uniform(low, high, count).tolist()

def generate_outlier_beacon(interval=60, count=50):
    data = generate_jittered_beacon(interval, 0.05, count)
    # Inject huge outliers
    data[10] = 5000
    data[25] = 9000
    return data

# --- Assertion Helper ---

def run_test(name, data, expected_substrings=None, should_fail=False, **kwargs):
    print(f"\n--- Test Case: {name} ---")
    print(f"    Input Size: {len(data)} intervals")
    if len(data) < 10:
        print(f"    Data: {data}")
    else:
        print(f"    Data (Head): {data[:5]}...")

    # Run Detection
    result = detect_beaconing_list(data, **kwargs)
    print(f"    Result: {result}")

    # Validation
    passed = True
    if should_fail:
        # We expect "No Beaconing" or "No ML Beaconing"
        if "ML" in result and "No ML" not in result:
            passed = False
            print(f"    [FAIL] Expected NO detection, but got: {result}")
        else:
            print("    [PASS] Correctly ignored.")
    else:
        # We expect specific detection strings
        if not result or "No ML" in result or "No Beaconing" in result:
            passed = False
            print("    [FAIL] Expected detection, got None/Clean.")
        elif expected_substrings:
            missed = [sub for sub in expected_substrings if sub not in result]
            if missed:
                passed = False
                print(f"    [FAIL] Missing expected flags: {missed}")
            else:
                print(f"    [PASS] Detected: {expected_substrings}")
        else:
             print("    [PASS] Detected anomaly (Generic).")

    return passed

# --- Main Execution ---

if __name__ == "__main__":
    print(">>> Starting BeaconML Integration Tests <<<")
    total_tests = 0
    passed_tests = 0

    # Test 1: Insufficient Data
    # BeaconML typically requires min_samples (default 3 or 5)
    total_tests += 1
    if run_test("Insufficient Data", [60, 60], should_fail=True, min_samples=5):
        passed_tests += 1

    # Test 2: Perfect Beacon (DBSCAN should catch this as Core StdDev ~ 0)
    # K-Means might fail if k=2 requires 2 clusters, but DBSCAN handles density.
    total_tests += 1
    data_perfect = generate_perfect_beacon(60, 20)
    if run_test("Perfect Beacon", data_perfect,
                expected_substrings=["DBSCAN"],
                use_dbscan=True):
        passed_tests += 1

    # Test 3: Jittered Beacon (The Bread & Butter)
    # Should trigger K-Means or DBSCAN depending on distribution
    total_tests += 1
    data_jitter = generate_jittered_beacon(60, 0.15, 100)
    if run_test("Jittered Beacon (15%)", data_jitter,
                expected_substrings=["ML"],
                use_dbscan=True, std_threshold=15.0):
        passed_tests += 1

    # Test 4: Multi-Modal (Sleep Mask)
    # [60, 300, 60, 300...] -> K-Means should find 2 clusters
    total_tests += 1
    data_multi = generate_multi_modal([60, 300], 60)
    if run_test("Multi-Modal (60s & 300s)", data_multi,
                expected_substrings=["K-Means"],
                use_dbscan=True):
        passed_tests += 1

    # Test 5: Random Noise
    # Should NOT trigger
    total_tests += 1
    data_noise = generate_random_noise(1, 1000, 50)
    if run_test("Random Noise", data_noise, should_fail=True, use_dbscan=True, std_threshold=5.0):
        passed_tests += 1

    # Test 6: Isolation Forest (Outliers)
    # Regular beacon with some huge spikes
    total_tests += 1
    data_iso = generate_outlier_beacon(60, 100)
    if run_test("Outlier Injection", data_iso,
                expected_substrings=["Isolation"],
                use_isolation=True):
        passed_tests += 1

    # Summary
    print(f"\n>>> Test Summary: {passed_tests}/{total_tests} Passed <<<")
    if passed_tests == total_tests:
        print("RESULT: SUCCESS")
        sys.exit(0)
    else:
        print("RESULT: FAILURE")
        sys.exit(1)

EOF

# 5. Run Tests
echo -e "${YELLOW}[*] Executing tests...${NC}"
python3 "$DRIVER_SCRIPT"

# 6. Result Handling
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}[+] All tests passed successfully.${NC}"
else
    echo -e "${RED}[!] Some tests failed. Check output above.${NC}"
fi

# Cleanup handled by trap
exit $EXIT_CODE