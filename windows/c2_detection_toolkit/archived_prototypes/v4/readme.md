# Windows Kernel C2 Beacon Hunter v4.0

## Overview
A **kernel-native, diskless** Command and Control (C2) detection and automated response engine for Windows. This project bridges the gap between raw Windows kernel telemetry (ETW) and advanced Machine Learning to catch modern, evasive C2 frameworks (Sliver, Cobalt Strike, Nighthawk) without relying on heavy third-party agents or static IOCs.

By default, the suite operates in a **Safe Baselining Mode (Dry-Run)** to prevent accidental termination of legitimate business applications while mapping your environment's network profile.

---

## V4 Architectural Highlights
* **Zero-Disk I/O Pipeline:** Embedded C# directly intercepts the `Microsoft-Windows-TCPIP` ETW provider in RAM, extracting connections and passing them to the Python ML engine via STDIN pipes. Zero heavy `.etl` trace files are written to disk.
* **Multi-Dimensional ML Clustering:** The Python daemon utilizes highly optimized, single-threaded DBSCAN and K-Means algorithms to evaluate interval rigidity, packet sizes, subnet diversity, and payload entropy to identify jittered/sparse beacons and Fast-Flux infrastructure.
* **Temporal Evasion Mitigation:** The system employs a hybrid state management architecture—balancing high-speed RAM processing with a persistent NTFS JSON database—to identify "Low and Slow" beaconing behavior while maintaining a resilient detection posture across system reboots.
* **Universal Diagnostic Engine:** A toggleable, millisecond-precision IPC logging engine that tracks matrix handoffs and explicitly intercepts underlying Python C-library exceptions for rapid troubleshooting.
* **Automated Lifecycle Management:** A master orchestrator handles dependency bootstrapping (Python 3.11 + ML libraries), parallel daemon execution, and pristine artifact teardown.
* **Post-Processing CTI Enrichment:** An automated script to parse unique outbound flows and query them against VirusTotal, AlienVault OTX, GreyNoise, AbuseIPDB, and Shodan for JARM fingerprints and framework tagging.
* **Tri-Lateral Vector Correlation:** A dedicated fusion engine that cross-references mathematically validated anomalies, the local connection ledger, and external CTI enrichment reports to generate a prioritized investigation report ranked by an aggregate risk score.
* **Automated Active Defense:** Executes multi-tiered remediation by forcefully terminating malicious process trees and injecting permanent outbound firewall block rules for identified C2 infrastructure.
* **Deep-Dive Forensic Triage:** Automatically reconstructs process lineage (PPID), extracts de-obfuscated PowerShell script blocks (Event ID 4104), and enumerates advanced persistence hooks—including WMI event consumers, scheduled tasks, and Image File Execution Options (IFEO) injections—immediately following containment.
* **Evidence-Led Eradication:** Provides actionable intelligence and specific artifact locations to facilitate the systematic removal of malicious staging files, persistence mechanisms, and the rotation of compromised credentials as identified in the forensic triage report.

### System Diagram
---

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'fontFamily': 'Fira Code, monospace', 'lineColor': '#06b6d4', 'mainBkg': '#0a0a0a', 'textColor': '#e2e8f0'}}}%%
graph TD
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:16px,font-weight:bold;
    classDef core fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef script fill:#0a0a0a,stroke:#a78bfa,stroke-width:2px,color:#a78bfa;
    classDef action fill:#1a0505,stroke:#ef4444,stroke-width:2px,color:#ef4444;
    classDef storage fill:#000,stroke:#4ade80,stroke-width:1px,color:#4ade80;
    classDef ext fill:#050505,stroke:#888,stroke-width:1px,color:#888,stroke-dasharray: 3 3;

    TITLE["C2 HUNTER v4.0 // SYSTEM DATA FLOW"]:::title

    %% 1. Pre-requisites & Orchestration
    SETUP["Setup-C2HunterEnvironment.ps1<br/>(Python 3.11 + scikit-learn bootstrap)"]:::script
    ORCH["Invoke-C2HunterLifecycle.ps1<br/>(Master Orchestrator: Safe vs Armed Mode)"]:::core

    %% 2. Telemetry Generation
    TEST["Test-C2FullSuite.ps1<br/>(Synthetic DGA / Jitter / Fast-Flux)"]:::script
    ETW["Windows ETW<br/>(TCPIP Provider)"]:::ext

    %% 3. Core Engine
    MONITOR["MonitorKernelC2BeaconHunter_v4.ps1<br/>(Embedded C# + Safe Baselining)"]:::core
    STATEDB["C2_StateDB\<br/>(Temporal RAM/Disk Tracker)"]:::storage
    DIAG["C2Hunter_Diagnostic.log"]:::storage

    %% 4. Machine Learning
    BEACONML["BeaconML.py<br/>(Headless DBSCAN / K-Means)"]:::script

    %% 5. Outputs
    JSONL["C2KernelMonitoring_v4.jsonl<br/>(ML Alerts & MITRE Mappings)"]:::storage
    LEDGER["OutboundNetwork_Monitor.log<br/>(Deduplicated Connection Ledger)"]:::storage

    %% 6. Enrichment
    CTIAPI["VT / AlienVault / AbuseIPDB"]:::ext
    CTICHECK["cti_check/Invoke-ThreatIntelCheck.ps1<br/>+ config.ini"]:::script
    CTI_REP["threat_intel_report.txt"]:::storage

    %% 7. Correlation
    CORRELATE["Invoke-C2VectorCorrelation.ps1<br/>(Tri-Lateral Fusion Engine)"]:::core
    REPORT["Correlated_C2_Vectors.txt<br/>(Prioritized Risk Scores)"]:::storage

    %% 8. Containment
    CONTAIN["Invoke-C2Containment.ps1<br/>(Tails logs for real-time remediation)"]:::action
    KILL["Stop-Process<br/>(Destructive Process Tree Kill)"]:::action
    FW["NetFirewallRule<br/>(Outbound IP Blacklist)"]:::action
    AUDIT["C2_Containment_Actions.log"]:::storage

    %% 9. Triage
    TRIAGE["Invoke-C2ForensicTriage.ps1<br/>(PPID / EID 4104 / Persistence Hooks)"]:::script
    TRIAGEREP["C2_Triage_Report_PID_XXXX.txt"]:::storage

    %% Flow Routing
    SETUP -.->|"Bootstraps"| ORCH
    TEST -.->|"Injects Synthetic Sockets"| ETW

    ORCH ===>|"Spawns Daemons"| MONITOR
    ETW -->|"Raw Network Events"| MONITOR

    MONITOR <.->|"Flush/Restore"| STATEDB
    MONITOR -.->|"Writes IPC Health"| DIAG
    MONITOR ===>|"IPC: STDIN/STDOUT"| BEACONML

    BEACONML ===>|"Writes Alerts"| JSONL
    MONITOR ===>|"Writes Mappings"| LEDGER

    CTIAPI -.->|"API Queries"| CTICHECK
    CTICHECK ===>|"Generates"| CTI_REP

    JSONL ===>|"Input 1"| CORRELATE
    LEDGER ===>|"Input 2"| CORRELATE
    CTI_REP ===>|"Input 3"| CORRELATE

    CORRELATE ===>|"Generates"| REPORT
    REPORT ===>|"Actionable Threat Data"| CONTAIN

    CONTAIN ===>|"1. Terminates Process"| KILL
    CONTAIN ===>|"2. Blocks IP"| FW
    CONTAIN ===>|"3. Logs Actions"| AUDIT
    CONTAIN ===>|"4. Triggers"| TRIAGE

    TRIAGE ===>|"Extracts Root Cause"| TRIAGEREP
```

---

## Prerequisites
* Windows 10 / Windows 11 / Windows Server 2019+
* PowerShell 5.1+ (Must be run as Administrator)
* *Note: The orchestrator will automatically download and silently install Python 3.11 and the required ML dependencies (`scikit-learn`, `numpy`) if they are not found on the host.*

---

## Quick Start Guide

### 1. Launch the Lifecycle Manager (Safe Mode)
Run the master orchestrator. It will bootstrap the environment, load the ML matrices, and spawn the Monitoring and Defender daemons in **Dry-Run Mode**.
```powershell
.\Invoke-C2HunterLifecycle.ps1
```
*In Dry-Run mode, the Active Defender will only print out the processes and IPs it **would** have terminated or blocked. Leave this running to analyze your environment for false positives.*

### 2. Launch the Lifecycle Manager (Armed Mode)
Once baselining is complete, pass the `-ArmedMode` switch. The Defender daemon will actively terminate malicious processes and add outbound Windows Firewall block rules for high-confidence C2 IPs.
```powershell
.\Invoke-C2HunterLifecycle.ps1 -ArmedMode
```

### 3. Run the Threat Intelligence Enrichment
To retrospectively analyze the outbound IPs captured by the monitor against community CTI databases, ensure your `cti_check/config.ini` is populated with your API keys, then execute:
```powershell
cd cti_check/
.\Invoke-ThreatIntelCheck.ps1
```

---

## Validation & Testing
To ensure the IPC pipes, ML engine, and telemetry parsers are functioning correctly, the project includes an AV-safe validation suite.

While the lifecycle orchestrator is running, open a new Administrative PowerShell window and execute:
```powershell
.\Test-C2FullSuite.ps1
```
This script uses raw `.NET` TCP sockets to bypass OS HTTP stack pollution and safely simulates:
* DGA (Domain Generation Algorithm) queries.
* Rigid (0% jitter) and Jittered (30%) script-kiddie/APT beacons.
* Fast-Flux infrastructure routing.

Monitor the main orchestrator console. You should see simultaneous ML detections trigger approximately 30 seconds after the test suite completes.

---

## Core File Manifest
* **`Invoke-C2HunterLifecycle.ps1`**: The master orchestration, dependency injection, and teardown manager.
* **`Setup-C2HunterEnvironment.ps1`**: Handles unattended Python 3.11 and `pip` dependency installations.
* **`MonitorKernelC2BeaconHunter_v4.ps1`**: The core C# ETW listener, PowerShell state manager, and IPC pipeline.
* **`BeaconML.py`**: The headless Python mathematical daemon providing DBSCAN and interval analysis.
* **`c2_defend.ps1`**: The real-time active defense engine that tails JSONL logs for automated remediation.
* **`cti_check/Invoke-ThreatIntelCheck.ps1`**: The CTI API aggregation and reporting tool.
* **`cti_check/config.ini`**: Secure credential storage for CTI API keys (VirusTotal, AlienVault, etc.).
* **`Invoke-C2VectorCorrelation.ps1`**: The DFIR fusion engine that correlates mathematical anomalies, network flow logs, and CTI data.
* **`Invoke-C2Containment.ps1`**: The automated remediation engine that terminates malicious processes and applies firewall blocks.
* **`Invoke-C2ForensicTriage.ps1`**: The forensic enumeration engine that reconstructs process lineage and identifies persistence mechanisms.
* **`Test-C2FullSuite.ps1`**: The synthetic C2 traffic generator for validation testing.

---

## Telemetry and Persistent Storage
The engine operates primarily in-memory but preserves critical forensic telemetry and state data in `C:\Temp\` for investigation and SIEM ingestion:

| File/Directory | Description | Purpose |
| :--- | :--- | :--- |
| **`C2_StateDB\`** | Directory containing JSON-serialized flow states. | Persistence for "Low and Slow" beacon detection. |
| **`C2KernelMonitoring_v4.jsonl`** | Structured JSON alerts with MITRE ATT&CK mappings. | SIEM ingestion and real-time alerting. |
| **`OutboundNetwork_Monitor.log`** | Deduplicated ledger of all outbound network flows. | Process-to-IP mapping and traffic auditing. |
| **`Correlated_C2_Vectors.txt`** | Prioritized investigation report with aggregate risk scores. | Analyst triage and threat prioritization. |
| **`C2_Containment_Actions.log`** | Forensic audit ledger of all process kills and firewall blocks. | Incident response accountability. |
| **`C2_Triage_Report_PID_XXXX.txt`** | Deep-dive forensic evidence (lineage, script blocks, persistence). | Root cause analysis and eradication. |
| **`C2Hunter_Diagnostic.log`** | Operational health log for IPC and internal state tracking. | System troubleshooting. |

---

## Correlation, Containment, and Eradication Workflow

### Stage 0: Configuration
Credentials for threat intelligence services must be configured in `cti_check/config.ini`. The system requires these keys to validate the reputation of beacon destinations identified by the ML daemon.

### Stage 1: Enrichment and Correlation
1. **`Invoke-ThreatIntelCheck.ps1`**: Once network telemetry is gathered, this module queries global CTI databases.
2. **`Invoke-C2VectorCorrelation.ps1`**: Combines the mathematical alerts from the ML daemon with CTI results and the process ledger to identify definitive attack vectors.

### Stage 2: Containment and Triage
**Component**: `Invoke-C2Containment.ps1`

When an actionable threat is identified (default score threshold - 100), the containment engine executes a three-tiered response:

1. **Isolation**: Forcefully terminates the malicious process tree (unless whitelisted) and creates outbound firewall blocks for the C2 IP.
2. **Automated Triage**: Immediately invokes `Invoke-C2ForensicTriage.ps1` to capture the process context before volatile data is lost.
3. **Forensic Reporting**:
    * Reconstructs the Parent Process ID (PPID) to find the initial dropper.
    * Extracts de-obfuscated PowerShell script blocks (Event ID 4104).
    * Identifies persistence hooks including Scheduled Tasks, WMI event consumers, and Registry Run keys.

---

## Technical Performance Notes
The v4.0 architecture includes a high-fidelity noise reduction layer. It utilizes process and IP-prefix whitelists to ignore known-benign telemetry from browsers (Chrome, Edge) and system keep-alives, ensuring that the correlation engine focuses exclusively on anomalous outbound behavior.
