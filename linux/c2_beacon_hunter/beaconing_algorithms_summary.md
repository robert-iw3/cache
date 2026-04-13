### Advanced Beaconing Algorithms in Cybersecurity

Beaconing is a technique where malware or compromised systems periodically "phone home" to command-and-control (C2) servers. Traditional detection relies on simple interval matching, but modern C2 frameworks (Cobalt Strike, Sliver, Havoc, Adaptix, etc.) heavily use **jitter**, long sleep intervals, malleable profiles, and DNS-only communication to evade detection.

This project implements a multi-layered detection approach.

#### 1. Statistical and Time-Series-Based Algorithms
- Low coefficient of variation (CV) and tight standard deviation for classic periodic beacons
- **Sparse/Long-sleep tracking** (v2.6) — Dynamically lowers minimum sample requirements and extends history to 48 hours to catch beacons with 30+ minute (or multi-hour) intervals
- Jitter analysis using adaptive thresholds

#### 2. Machine Learning and Clustering Algorithms
- K-Means clustering with silhouette scoring for optimal cluster count
- Adaptive DBSCAN with dynamic epsilon calculation
- Isolation Forest for outlier detection
- **Packet direction & outbound consistency scoring** (v2.6) — Detects highly malleable C2 that maintains consistent outbound-only traffic patterns (common in Cobalt Strike, Sliver, etc.)

#### 3. Spectral Analysis
- **Lomb-Scargle periodogram + circular phase clustering** (added in v2.5) — Extremely effective against jittered beacons (30–50%+ jitter) that defeat traditional low-CV methods

#### 4. Enhanced DNS Beacon Detection (v2.6)
- Dedicated real-time DNS sniffer using Scapy
- Periodic DNS query analysis combined with ML interval detection
- Flags both regular periodic DNS beacons and high-entropy (DGA-like) patterns

#### 5. Behavioral & UEBA Features (v2.6)
- **Per-process baseline (UEBA lite)** — Learns normal connection interval behavior per process name and flags statistical deviations
- Process tree analysis + masquerading detection
- Entropy scoring on command lines and destination IPs

#### 6. Implementation Notes (Project-Specific)
- Combines multiple signals with weighted scoring (timing + direction + entropy + UEBA + ML)
- Dynamic `TEST_MODE` for safe simulator testing
- Optimized for low overhead and long-term sparse beacon detection
- Exports structured data for SIEM integration

#### Evasion and Countermeasures
Modern C2 tries to mimic legitimate traffic (malleable profiles on 443, long sleep, DNS-only). This tool counters them with:
- Spectral analysis (Lomb-Scargle)
- Direction/consistency checks
- Long-term sparse tracking
- Per-process behavioral baselining

**Last updated:** February 2026 (v2.6)