# c2_defend - Proactive Protection Layer v2.8

This module provides the active response and containment capabilities for the C2 Beacon Hunter platform. It translates high-confidence machine learning anomalies into immediate, wire-speed defensive actions.

### Security Warning
This toolkit modifies critical host infrastructure. It is capable of terminating running processes (SIGKILL), freezing execution states (SIGSTOP), injecting eBPF XDP maps for nanosecond network drops, and modifying the host firewall (firewalld, ufw, iptables). It must be executed with root privileges directly on the host.

---

### Core Capabilities

* **Wire-Speed XDP Containment:** Directly interfaces with pinned eBPF maps (`/sys/fs/bpf/c2_blocklist`) to drop malicious traffic at the Network Interface Card (NIC) level before it reaches the Linux network stack.
* **Defense-in-Depth Firewalls:** Automatically detects and falls back to OS-level firewalls (`firewalld`, `ufw`, or `iptables`) to ensure redundant network isolation.
* **Process Eradication:** Maps malicious network connections back to their origin PIDs and issues kernel-level termination signals to halt execution.
* **DFIR Integration:** Orchestrates live volatile memory extraction and threat intelligence enrichment prior to containment.

---

### Execution Modes

The module can be operated in an automated daemon mode or an interactive forensic mode.

#### 1. Interactive Orchestration (Recommended for DFIR)
Provides a menu-driven interface to review anomalies, gather intelligence, and selectively freeze or kill threats.

```bash
cd c2_defend
sudo chmod +x run.sh analyzer.py defender.py undo.py c2_defend.py
sudo ./run.sh

```

#### 2. Automated Daemon Mode

Runs continuously in the background, tailing the pipeline logs. It will automatically isolate networks and terminate processes when an anomaly score reaches the critical threshold (>= 90).

```bash
# Start in Dry-Run mode (Observation logging only)
sudo python3 c2_defend.py

# Arm the daemon for Active Containment
sudo python3 c2_defend.py --arm

```

---

### Script Inventory & Descriptions

* **`run.sh`**: The main interactive wrapper. It orchestrates the incident response workflow by chaining together the `live_triage.sh` and `threat_intel_check.sh` scripts before handing off to the active defender.
* **`c2_defend.py`**: The asynchronous mitigation daemon. It utilizes `psutil` and `subprocess` to monitor `anomalies.jsonl`. When armed, it automatically updates XDP maps and OS firewalls, and terminates offending PIDs.
* **`defender.py`**: The manual containment engine. It reads recent high-score events from the logs and prompts the analyst to either freeze (SIGSTOP) processes to preserve memory artifacts, kill (SIGKILL) them, or enact network blocks.
* **`undo.py`**: The safe rollback utility. It parses the auto-generated `blocklist.txt` ledger to systematically remove eBPF XDP pins and delete rich rules/iptables entries, instantly restoring network access in the event of a false positive.
* **`analyzer.py`**: A lightweight CLI viewer utilizing `pandas` to read `anomalies.csv` and filter for high-confidence detections without risking accidental system modification.

---

### State Tracking & Logging

All automated and manual actions are strictly logged to prevent loss of context during an incident.

* **Containment Ledger:** `blocklist.txt` (Parsed by `undo.py` for rollbacks).
* **Daemon Logs:** `c2_defend_daemon.log`.
* **Interactive Logs:** `defender.log`.

**Last updated:** March 2026