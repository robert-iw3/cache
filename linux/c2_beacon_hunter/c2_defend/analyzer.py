#!/usr/bin/env python3
"""
c2_defend/analyzer.py - View latest detections
"""

import pandas as pd
from pathlib import Path
import sys

output_dir = Path("../output")
csv_file = output_dir / "anomalies.csv"

if not csv_file.exists():
    print("No anomalies.csv found yet. Run c2_beacon_hunter first.")
    sys.exit(1)

df = pd.read_csv(csv_file)

print(f"\n=== c2_beacon_hunter Detections Summary ({len(df)} total) ===")
print(df[["timestamp", "dst_ip", "dst_port", "process", "score", "ml_result"]].tail(20))

high = df[df["score"] >= 70]
if not high.empty:
    print(f"\nHIGH CONFIDENCE DETECTIONS ({len(high)}):")
    print(high[["timestamp", "process", "dst_ip", "dst_port", "score", "reasons"]])