# Windows Kernel C2 Beacon Hunter v3.0

## Overview

A **kernel-native** Command and Control (C2) beacon detector for Windows. This project bridges the gap between raw Windows kernel telemetry (ETW/pktmon) and advanced machine learning to catch modern, evasive C2 frameworks without relying on heavy third-party agents like Sysmon.

By default, the suite operates in a **safe baselining mode (Dry-Run)** to prevent accidental termination of legitimate business applications while mapping your environment's network profile.

---

## Prerequisites

* Windows 10 / Windows 11 / Windows Server 2019+

* PowerShell 5.1+ (Run as Administrator)

* Python 3.8+ *(Note: The orchestrator will attempt an unattended installation of Python 3.11 if it is not found).*

---

## Installation & Usage


The entire lifecycle—from environment setup and dependency installation, to daemon execution, to deep-cleaning the host on exit—is managed by a single orchestrator script.

### Step 1: Safe Baselining (Recommended Default)

Run the lifecycle manager. It will automatically install dependencies, start kernel tracing, and open the Monitor and Defender windows in **Dry-Run Mode**.

```powershell

.Invoke-C2HunterLifecycle.ps1

```

*In Dry-Run mode, the active defender will only print out the processes and IPs it **would** have terminated or blocked. Leave this running to analyze your environment for false positives.*

### Step 2: Armed Mode (Active Defense)

Once you are confident in your environment's baseline, you can arm the defender. This will actively use `Stop-Process -Force` and Windows Firewall rules to severe C2 connections.

```powershell
.Invoke-C2HunterLifecycle.ps1 -ArmedMode -ConfidenceThreshold 80
```

### Step 3: Teardown

To safely stop monitoring, simply return to the master orchestrator window and press **`[ENTER]`**.

The script's built-in `try/finally` logic guarantees that:

 1. The ML and Defender daemons are killed.
 2. The `logman` and `pktmon` kernel sessions are halted and deleted.
 3. Python ML dependencies are uninstalled.
 4. Temporary ETW traces and JSON logs are purged from the disk.

---

## Validation & Testing

To ensure the ML engine and telemetry parsers are functioning correctly, the project includes a full feature validation suite.

While the orchestrator is running, open a new Administrative PowerShell window and execute:

```powershell
.Test-C2FullSuite.ps1
```

This script safely simulates:

* Encoded PowerShell commands
* Malicious file drops
* DGA DNS queries
* Registry persistence modifications
* An 8-connection low-jitter beacon to explicitly trigger the 4D ML engine
* Fast-Flux infrastructure routing

---

## Project Architecture

* **`Invoke-C2HunterLifecycle.ps1`**: The master end-to-end orchestration and teardown manager.
* **`MonitorKernelC2BeaconHunter_v3.ps1`**: Core ETW telemetry parser, pre-filter, and sub-process manager.
* **`BeaconML.py`**: Persistent multi-dimensional clustering and ML daemon listening on `STDIN`.
* **`c2_defend.ps1`**: Active defense engine tailored for automated remediation.
* **`InstallKernelC2Hunter.ps1` / `UninstallKernelC2Hunter.ps1`**: Native OS trace management.
* **`Test-C2FullSuite.ps1`**: Automated adversary simulation for validation.
* **`config.ini`**: Externalized thresholds and behavioral indicators.

