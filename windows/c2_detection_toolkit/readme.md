# Windows Kernel C2 Beacon Sensor v1.0

## Overview
A **kernel-native, high-performance** Command and Control (C2) detection and automated response engine for Windows. This project bridges the gap between raw Windows kernel telemetry (ETW), Cryptographic Deep Packet Inspection, wire-speed Threat Intelligence (Suricata/Abuse.ch), and native Machine Learning to catch modern, evasive C2 frameworks (Sliver, Cobalt Strike, Nighthawk).  A lightweight, drop-in sensor designed to detect stealthy C2 beacons through advanced mathematical ML analysis and UEBA-driven baselining of normal outbound traffic behavior.

By default, the suite operates in an **Audit Mode (Dry-Run)** to prevent accidental termination of legitimate business applications while mapping your environment's network profile.

---

## V1 Architectural Highlights
* **Native Rust FFI Machine Learning:** Replaced the legacy Python daemon with `c2sensor_ml.dll`. The C# ETW listener pushes multi-dimensional telemetry matrices (Intervals, Packet Sizes, Subnet Diversity) directly into Rust's RAM for mathematically rigorous, lock-free DBSCAN and K-Means clustering.
* **O(1) Network Threat Intel:** Dynamically syncs and compiles EmergingThreats (Suricata) and Abuse.ch network rules into zero-allocation binary searches. Evaluates live DNS and TCP/IP flows against thousands of signatures simultaneously with zero CPU overhead.
* **Universal AppGuard:** Monitors `Kernel-Process` events to instantly intercept web shells and database RCEs (IIS, SQL, Tomcat, Node) attempting to spawn command interpreters in unauthorized directories.
* **Cryptographic DPI & JA3 Profiling:** Natively subscribes to the `NDIS-PacketCapture` provider to inspect raw Layer 2 Ethernet frames. Dynamically extracts TLS `Client Hello` signatures to generate JA3 hashes and block malicious L4 frameworks instantly.
* **Enterprise State Management:** Legacy JSON flat-files have been replaced by a high-speed SQLite Write-Ahead Logging (WAL) database (`C2Sensor_State.db`), securely anchoring temporal "low and slow" beacon tracking across system reboots.
* **Active Anti-Tamper & Self-Defense:** * Establishes a native Windows `icacls` locked vault for the `TamperGuard.log`.
  * Monitors `VirtualProtect` for RWX memory patching (`ntdll.dll` unhooking).
  * Intercepts rogue `logman` commands attempting to blind the ETW session.
* **1-Click DFIR Orchestration:** Automates the incident response pipeline (`Invoke-DFIR_Orchestrator.ps1`). Extracts BYOVD kernel persistence, pulls Sysinternals ProcDump, scans for APT-grade memory injections (Hell's Gate / Direct Syscalls), and stages automated WinDbg Tier 1-5 forensic reports into a centralized, timestamped evidence vault.

---

### System Diagram

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'fontFamily': 'Fira Code, monospace', 'lineColor': '#06b6d4', 'mainBkg': '#0a0a0a', 'textColor': '#e2e8f0'}}}%%
graph TD
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:16px,font-weight:bold;
    classDef core fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef script fill:#0a0a0a,stroke:#a78bfa,stroke-width:2px,color:#a78bfa;
    classDef action fill:#1a0505,stroke:#ef4444,stroke-width:2px,color:#ef4444;
    classDef storage fill:#000,stroke:#4ade80,stroke-width:1px,color:#4ade80;
    classDef ext fill:#050505,stroke:#888,stroke-width:1px,color:#888,stroke-dasharray: 3 3;

    TITLE["C2 SENSOR V1 Architecture"]:::title

    subgraph Phase1 [1. Deployment & Threat Intel]
        direction TB
        BUILD["Build-RustEngine.ps1<br/>(Cargo Compiler)"]:::script
        ABUSE["Abuse.ch SSLBL / Suricata<br/>(External CTI Feeds)"]:::ext
        ORCH["C2Sensor_Launcher.ps1<br/>(Master Orchestrator)"]:::core
        ETW["Windows ETW<br/>(TCPIP & NDIS Layer 2)"]:::ext
    end

    subgraph Phase2 [2. Real-Time Telemetry & Active Defense]
        direction TB
        CSHARP["C2Sensor.cs<br/>(Unmanaged ETW & 0-Alloc Searches)"]:::core
        RUST["c2sensor_ml.dll<br/>(Native Rust FFI)"]:::core

        JA3CACHE["C2Sensor_JA3_Cache.json<br/>(Threat Intel Vault)"]:::storage
        TAMPERLOG["C2Sensor_TamperGuard.log<br/>(ACL Locked Ledger)"]:::storage
        STATEDB["C2Sensor_State.db<br/>(SQLite WAL Tracker)"]:::storage
        JSONL["C2Sensor_Alerts.jsonl<br/>(Rotated SIEM Logs)"]:::storage

        ACT_KILL["Win32 Stop-Process"]:::action
        ACT_BLOCK_RT["NetFirewallRule Block"]:::action
    end

    subgraph Phase3 [3. DFIR Automation]
        direction TB
        DFIR["Invoke-DFIR_Orchestrator.ps1<br/>(IR Automation)"]:::core
        CORRELATE["C2VectorCorrelation.ps1<br/>(Data Fusion)"]:::script
        MEMHUNTER["Invoke-AdvancedMemoryHunter.ps1<br/>(APT Scanner)"]:::script
        CONTAIN["Invoke-C2Containment.ps1<br/>(Surgical Suspend)"]:::script
        ERADICATE["Invoke-AutomatedEradication.ps1<br/>(Remediation)"]:::script
        TRIAGE["Invoke-DumpAnalysis.ps1<br/>(WinDbg Triage)"]:::script
        EVIDENCE["C:\ProgramData\C2Sensor\Evidence\<br/>(Centralized Locker)"]:::storage

        ACT_SUSPEND["Win32 SuspendThread"]:::action
        ACT_REBOOT["Tactical Reboot"]:::action
    end

    %% Phase 1 Routing
    TITLE ~~~ BUILD
    BUILD -.->|"Compiles Native Engine"| RUST
    ABUSE -.->|"Fetches Rules & Hashes"| ORCH

    ORCH ===>|"1. Writes Cache"| JA3CACHE
    ORCH ===>|"2. Injects Memory"| CSHARP
    ETW -->|"Raw Frames & Flows"| CSHARP

    %% Phase 2 Internal Routing
    RUST <.->|"Flush/Restore"| STATEDB
    CSHARP -.->|"Reads"| JA3CACHE
    CSHARP ===>|"FFI Memory Pointer"| RUST
    RUST ===>|"Returns C-String Alert"| CSHARP

    %% Defense Actions
    CSHARP ===>|"Executes if Armed"| ACT_KILL
    CSHARP ===>|"Executes if Armed"| ACT_BLOCK_RT

    %% Phase 2 Storage
    CSHARP -.->|"Writes Events"| JSONL
    CSHARP -.->|"Exclusive Write"| TAMPERLOG

    %% Logical Divider
    JSONL ~~~ DFIR

    %% DFIR Flow Routing
    DFIR ===>|"1. Executes"| CORRELATE
    DFIR ===>|"2. Targeted PIDs"| MEMHUNTER
    DFIR ===>|"3. Target Matrix"| CONTAIN
    DFIR ===>|"4. Feed CSV"| ERADICATE

    CORRELATE -.->|"Output Matrix"| EVIDENCE
    MEMHUNTER -.->|"Injection CSV"| EVIDENCE
    CONTAIN -.->|"Action Log"| EVIDENCE
    ERADICATE -.->|"Secures .dmp"| EVIDENCE
    ERADICATE -.->|"Passes .dmp"| TRIAGE
    TRIAGE -.->|"T1-T5 Report"| EVIDENCE

    CONTAIN ===> ACT_SUSPEND
    ERADICATE ===> ACT_REBOOT
```

---

## Prerequisites
* Windows 10 / Windows 11 / Windows Server 2019+
* PowerShell 5.1+ (Must be run as Administrator)
* **To Compile from Source:** Rust Toolchain (`cargo`) and MSVC C++ Desktop Build Tools (via `Build-RustEngine.ps1`).

---

## Quick Start Guide

### 1. Compile the Native Engine (First Run Only)
Before launching the sensor, compile the Rust machine learning engine into a native `.dll`.
```powershell
.\Build-RustEngine.ps1
```

### 2. Launch the Sensor (Audit Mode)
Run the orchestrator. It will bootstrap the environment, sync Suricata/Abuse.ch network rules, build the zero-allocation binary searches, map the Rust ML engine into memory, and begin monitoring in **Dry-Run Mode**.
```powershell
.\C2Sensor_Launcher.ps1
```
*In Audit mode, the Active Defender will only print out the processes and IPs it **would** have terminated or blocked. Leave this running to analyze your environment for false positives.*

### 3. Launch the Sensor (Armed Mode)
Once baselining is complete, pass the `-ArmedMode` switch. The daemon will utilize real-time ML clustering, Network Signatures, and Layer-2 cryptographic fingerprinting to execute process terminations and apply outbound Windows Firewall block rules autonomously.
```powershell
.\C2Sensor_Launcher.ps1 -ArmedMode
```

### 4. Trigger 1-Click DFIR Automation
When a critical ML or JA3 alert fires during an incident, open a new prompt and execute the master IR orchestrator to fully automate the investigation, memory acquisition, and eradication process.
```powershell
.\Invoke-DFIR_Orchestrator.ps1 -ArmedMode
```

---

## Core File Manifest
* **`C2Sensor_Launcher.ps1`**: The master orchestration, Threat Intel network compiler (Abuse.ch/Suricata), FFI memory mapper, and primary HUD daemon.
* **`C2Sensor.cs`**: The core unmanaged C# ETW listener, NDIS JA3 packet scanner, AppGuard interceptor, and `[DllImport]` boundary.
* **`lib.rs` / `c2sensor_ml.dll`**: The native Rust Machine Learning engine executing DBSCAN, K-Means clustering, SQLite WAL state management, and DGA heuristics natively in memory.
* **`Build-RustEngine.ps1` & `Build-AirGapPackage.ps1`**: Automated deployment pipelines for enterprise provisioning.
* **`Invoke-DFIR_Orchestrator.ps1`**: The 1-click incident response manager that chains all forensic phases into `C:\ProgramData\C2Sensor\Evidence\`.
* **`Invoke-AdvancedMemoryHunter.ps1`**: APT-grade memory forensics utilizing P/Invoke and Wildcard C# matching.
* **`C2VectorCorrelation.ps1`**: The DFIR fusion engine correlating math anomalies, network logs, and CTI data.
* **`Invoke-AutomatedEradication.ps1`**: Neutralizes BYOVD kernel persistence, pulls Sysinternals ProcDump to secure memory, and forces tactical reboots.

---

## Telemetry and Persistent Storage
The engine operates primarily in unmanaged memory, but rigorously logs alerts, states, and SIEM data to the secure `C:\ProgramData\C2Sensor\` enterprise directory:

| File/Directory | Description | Purpose |
| :--- | :--- | :--- |
| **`\Data\C2Sensor_State.db`** | High-speed SQLite database operating in WAL mode. | Persistence for "Low and Slow" beacon interval tracking. |
| **`\Data\C2Sensor_JA3_Cache.json`** | Dynamically updated cache of malicious TLS footprints. | Powers the real-time cryptographic L2 scanner. |
| **`\Data\C2Sensor_TamperGuard.log`** | `icacls` locked ledger tracking ETW bypasses. | Auditing sensor blinding and memory patching attempts. |
| **`\Logs\C2Sensor_Alerts.jsonl`** | Structured JSON alerts with MITRE ATT&CK mappings. | Primary SIEM ingestion file (Features 50MB Auto-Rotation). |
| **`\Logs\C2Sensor_UEBA.jsonl`** | High-volume RAW telemetry firehose. | Forwarded to Azure Sentinel / Splunk for historic querying. |
| **`\Evidence\DFIR_YYYYMMDD_HHmm\`** | Centralized IR Locker dynamically generated by the DFIR Orchestrator. | Incident response accountability and artifact storage. |
| **`advanced_memory_injections.csv`** | Generated CSV containing addresses of Direct Syscalls, RWX anomalies, and YARA hits. | Feeds the Eradication Engine. |
| **`*.dmp` & Forensic Reports** | Full process memory dumps and T1-T5 WinDbg analysis files. | Deep-dive reverse engineering handoff. |

---

**Developer Note (@RW):**
Transitioning the ML clustering engine from a Python daemon to a native Rust FFI library was a definitive architectural pivot. By eliminating the STDIN/STDOUT IPC pipes and compiling the K-Means/DBSCAN math into a C-compatible DLL, we collapsed the architecture into a single, unmanaged memory space. The C# ETW listener now passes memory pointers directly to Rust for zero-latency telemetry evaluation. Combined with a zero-allocation binary searches Intel compiler and SQLite WAL state tracking, V1 operates at true wire-speed.

Under sustained high-load testing (5 consecutive back-to-back stress testing runs with continuous ETW ingestion, NDIS JA3 extraction, zero-allocation binary searches threat-intel matching, and native FFI ML batching), the C2Sensor stayed exceptionally lightweight: CPU usage peaked at only 7-15% and RAM consumption never exceeded 500 MB.