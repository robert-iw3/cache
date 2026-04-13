# Deep Visibility Sensor Development Roadmap

**Before the introduction of massive complexities that comes with a Ring-0 Rust driver in V3, the Ring-3 C# ETW listener and Python ML daemon must be stress-tested to a point of absolute, mathematical stability.**

## Pre-V3 Finalization: Deep Sensor V2 Testing & Hardening

**Theme:** Validating the Ring-3 foundation, stress-testing Active Defense (`-ArmedMode`), and ensuring zero-defect stability before introducing Ring-0 kernel complexities.

**Core Objective:** Execute comprehensive Red Team simulations, memory leak profiling, and QA edge-case remediation to guarantee the sensor is unkillable and accurate under extreme load.

### Epic 10: Active Defense Validation (`-ArmedMode` Stress Testing)
*Transitioning the sensor from passive observation to lethal, autonomous containment in a controlled staging environment.*

- [ ] **Thread Suspension Accuracy:** Deploy benign and malicious Process Hollowing / PE Injection simulators to verify `QuarantineNativeThread` successfully halts the exact injected thread without crashing the parent process or causing BSODs.
- [ ] **Memory Forensics Extraction:** Trigger critical alerts to invoke `PreserveForensics` (MiniDumpWriteDump). Manually load the resulting `.dmp` files into WinDbg or Volatility to ensure the memory captures are uncorrupted and contain the raw, de-obfuscated shellcode.
- [ ] **In-Flight YARA Scanning:** Test the native `YaraContext` engine against the suspended memory regions of quarantined threads. Ensure the engine accurately matches signatures on in-memory payloads without triggering access violations (`0xC0000005`).
- [ ] **Host Isolation Verification:** Synthetically trigger a 10.0 ML Anomaly Score to invoke `Invoke-HostIsolation`. Verify that the Windows Defender Firewall instantly enters a default-deny state, successfully dropping all SMB/HTTP/RDP traffic while preserving the SIEM and Orchestrator API connections.

### Epic 11: Evasion Resilience & Red Team Simulation
*Throwing modern, weaponized evasion tactics at the sensor to prove the Ring-0 ETW bindings and new stack-trace heuristics hold up.*

- [ ] **Direct Syscall Bypasses:** Execute payloads utilizing Hell's Gate, Tartarus' Gate, and SysWhispers. Verify that because the sensor listens at the ETW kernel-transition layer, user-mode API unhooking remains entirely ineffective against our telemetry.
- [ ] **Call Stack Spoofing Validation:** Deploy ThreadlessInject or synthetic stack-spoofed shellcode. Validate that the newly implemented C# mathematical boundary heuristics correctly flag the return addresses as unbacked or missing valid `CALL/JMP` instructions.
- [ ] **AMSI/ETW Blinding Attacks:** Attempt to patch `EtwEventWriteFull` in user-mode memory and execute `AmsiScanBuffer` bypasses. Verify the sensor's kernel-level telemetry continues to ingest the un-tampered data.

### Epic 12: Long-Term QA & Performance Profiling (Soak Testing)
*Ensuring the sensor can run indefinitely on high-traffic production servers without degrading system performance.*

- [ ] **72-Hour High-Noise Soak Test:** Deploy the sensor in Audit Mode on a heavy-workload server (e.g., Domain Controller or IIS Farm) for 3 days. Monitor C# Garbage Collection (GC) metrics to ensure the `[ThreadStatic]` StringBuilders successfully prevent memory thrashing.
- [ ] **IPC Deadlock Sweeping:** Simulate 20,000+ Events Per Second (EPS) bursts through the ETW queues to ensure the PowerShell-to-Python lock-free STDIN/STDOUT pipes do not bottleneck, desync, or deadlock under extreme pressure.
- [ ] **Crash Resilience Verification:** Manually force-kill the PowerShell console (`taskkill /F`) and simulate hard power losses. Verify the new Python SQLite WAL immediate-flush logic successfully preserves 100% of the UEBA baselines without database corruption.

### Epic 13: Ring-3 Architectural Finalization (The V3 Gate)
*The final polish of the user-mode ecosystem before crossing the boundary into kernel-space development.*

- [ ] **DACL & Inheritance QA:** Attempt to modify, delete, or overwrite `DeepSensor_Launcher.ps1`, `OsAnomalyML.py`, and the YARA/Sigma directories using a standard Local Administrator account to ensure the `icacls` lockdown holds firm.
- [ ] **False Positive Pruning:** Review the UEBA database after a week of soak testing. Ensure the Global Rule Degradation logic is accurately pruning hyper-active Sigma rules (triggering across 5+ unique processes) to keep the C# engine's evaluation loop razor-fast.
- [ ] **UI/UX Alert Fatigue Mitigation:** Tune the Orchestrator HUD's refresh rate and queuing logic. Ensure that during massive attack simulations, the dashboard remains mathematically pinned and responsive without scrolling the console or dropping UI frames.

---

## V2 Completion Status

### Point-in-Time Polling Foundation (COMPLETED)
The original foundation successfully established multi-threaded file hunts, memory structure validation, and static exclusion mapping.
- [x] Multi-threaded ADS, Entropy, and Cloaking file sweeps.
- [x] Static Registry Polling (RunKeys, BITS, Scheduled Tasks).
- [x] UI Standardization (Progress Bars, JSON Reporting).

---

### Real-Time ETW Architecture Pivot (COMPLETED)
Transitioned from scheduled disk/registry polling to zero-overhead, event-driven kernel telemetry using an embedded C# engine.
- [x] **C# Kernel Sensor:** `DeepVisibilitySensor.cs` deployed, subscribing directly to `Kernel-Process`, `Kernel-Registry`, and `Kernel-Memory`.
- [x] **Orchestrator HUD:** Mathematically pinned dashboard deployed to monitor live telemetry streams without console scrolling.
- [x] **O(1) Process Lineage Cache:** Implemented `ConcurrentDictionary` to track parent-child executions natively in RAM.
- [x] **Fileless Interception:** `FileIOCreate` callbacks natively intercept Alternate Data Stream (ADS) creation in real-time.

---

### Machine Learning & Active Defense (COMPLETED)
Shifted from static IoCs to mathematical anomaly detection, incorporating autonomous containment mechanisms.
- [x] **Daemonized IPC:** Lock-free STDIN/STDOUT pipes established between PowerShell and Python to prevent disk I/O penalties.
- [x] **Isolation Forest Integration:** `scikit-learn` Isolation Forests deployed to evaluate host activity as multi-dimensional matrices (Entropy, LOLBin Flag, Path Depth).
- [x] **Autonomous Defense:** `-ArmedMode` implemented utilizing Win32 P/Invoke (`TerminateNativeThread`) for surgical thread containment and `Stop-Process` for execution root termination.
- [x] **Anti-Tamper Watchdog:** `VirtualAlloc` monitoring deployed to detect `PAGE_EXECUTE_READWRITE` (0x40) permissions inside the sensor's PID.
- [x] **Log Rotation:** 50MB self-grooming JSONL logging engine implemented in the main Orchestrator loop.

---

### Threat Intelligence & Automated Deployment (COMPLETED)
Evolved the sensor into a self-deploying platform capable of compiling and evaluating community-driven heuristics natively in the kernel event pump.
- [x] **Sigma Rule Compiler:** The Orchestrator natively parses the local `sigma/` directory, auto-corrects YAML syntax, and compiles `CommandLine` and `ImageLoad` logic into parallel string arrays for sub-millisecond evaluation in C#.
- [x] **Live BYOVD Intelligence:** Natively fetches and parses known vulnerable driver definitions from LOLDrivers.io, loading them into an $O(1)$ C# `HashSet` to instantly convict malicious `.sys` loads.
- [x] **Environment Bootstrap:** Implemented a zero-touch deployment sequence that validates local Python environments, silently downloading and installing Python 3.11.8 and all required ML dependencies (`scikit-learn`, `numpy`) if absent.
- [x] **Dual-Canary Health System:** Deployed synthetic heartbeats (a periodic `FileIOCreate` for the ETW Kernel and a `HEALTH_OK` payload for the Python IPC pipe) to instantly detect and alert if the sensor is unhooked or frozen.

---

### High-Performance Engine Optimization (Core Architecture) (COMPLETED)
**Objective:** Eradicate .NET Garbage Collection (GC) spikes and ensure sub-millisecond evaluation at high event volumes.

- [x] **String Allocation Elimination:** Refactor the C# ETW engine to replace `.ToLower().Contains()` with `.IndexOf(..., StringComparison.OrdinalIgnoreCase) >= 0`. This will prevent the allocation of temporary string objects in memory during 10,000+ EPS (Events Per Second) bursts.
- [x] **Aho-Corasick / Trie Sigma Engine:** Transition the Sigma Command Line and Image Load matching arrays from linear `for` loops to an Aho-Corasick string matching algorithm. This ensures $O(n)$ matching speed, allowing the engine to evaluate 10,000+ Sigma rules simultaneously without introducing ETW buffer latency.
- [x] **Process Lineage Memory Grooming:** Implement a TTL (Time-To-Live) or periodic cleanup routine for the `ProcessCache` dictionary to ensure orphaned PIDs do not cause memory leaks over months of continuous uptime.

---

### Advanced Threat Matrix Expansion (Kernel Telemetry) (COMPLETED)
**Objective:** Deepen the sensor's native visibility into cross-process memory manipulation, unbacked execution, and obscure registry persistence vectors.

- [x] **Memory Injection & Hollowing (T1055.002 / T1055.012):** Expanded ETW subscriptions to track `VirtualAlloc` events. Correlated `PAGE_EXECUTE_READWRITE` (0x40) allocations with suspended/recent `ProcessStart` events to heuristically identify Process Hollowing and PE Injection.
- [x] **Unbacked Module Detection (T1562.001):** Tracked `ImageLoad` events to identify modules executing in memory that possess empty filenames (not backed by a physical file on disk), exposing reflective DLL behavior.
- [x] **Deep Registry Persistence (T1547.005 / T1546.008):** Expanded the `MonitoredRegPaths` to cover `\Control\Lsa\Security Packages` (SSP credential theft) and Accessibility Features (`sethc.exe`/`utilman.exe` IFEO hooks).

---

### Behavioral ML Evolution (Python Daemon) (COMPLETED)
**Objective:** Evolve the Machine Learning daemon from static execution evaluation to temporal burst tracking and complex execution lineage.

- [x] **Ransomware / Wiper Burst Detection:** Implemented real-time tracking of `FileIOCreate` and `FileIOWrite` events mapped to PIDs. Processes triggering >50 modifications in <1.0 second with a >7.2 Shannon Entropy path score instantly trip Ransomware defense mitigations.
- [x] **Parent-Child Tuple Scoring:** Refactored the ML engine to replace flat LOLBin flags with dynamic, host-specific execution hashes (`parent_process -> child_process`). The Isolation Forest now trains on process lineage rarity, easily convicting anomalous spawn trees.

---

### Sensor Self-Defense & Hardening (COMPLETED)
**Objective:** Implement robust anti-tamper mechanisms that do not rely on Microsoft's restricted ELAM/PPL ecosystem.

- [x] **Service DACL Hardening:** Configured strict Discretionary Access Control Lists (DACLs) utilizing `sc.exe sdset` to prevent local administrators from modifying or stopping the deployed service execution.
- [x] **Thread Hijacking Watchdog:** Enhanced the `VirtualAlloc` monitor to actively protect its own PID. Automatically neutralizes any external thread attempting to map `PAGE_EXECUTE_READWRITE` memory into the sensor's space using `TerminateNativeThread`.
- [x] **File System & Registry Locking:** Deployed `icacls` lockdown sequences during bootstrap to explicitly deny write access to `BUILTIN\Administrators` for the sensor binaries, Python daemon, and `sigma/` rule configurations, limiting control solely to `NT AUTHORITY\SYSTEM`.

---

### Enterprise Operations & Telemetry Management (COMPLETED)
**Objective:** Ensure safe, scalable fleet deployment with maximum auditability and centralized control.

- [x] **Surgical Containment Audit Trails:** Enhanced the `Invoke-ActiveDefense` pipeline to inject explicit `AuditTrail` JSON objects into the log stream whenever `TerminateNativeThread` is executed, providing analysts precise tracing for thread-level mitigations.
- [x] **SIEM API Forwarding:** Upgraded the JSONL logging loop to support direct REST API ingestion (e.g., Splunk HEC or Azure Log Analytics) via new `$SiemEndpoint` parameters, eliminating complete reliance on local disk telemetry.
- [x] **Centralized Policy Sync:** Implemented a dynamic hot-swap method (`UpdateThreatIntel`) in the C# engine. The Orchestrator now routinely fetches policy updates and rebuilds the Sigma/BYOVD matrices without halting the ETW session or dropping kernel events.

---

### Advanced Adversary Detection (COMPLETED)
**Objective:** Add high-fidelity, low false-positive detection for advanced credential theft, lateral movement, WMI/COM hijacking, and posture weaknesses.

- [x] **Named Pipe Telemetry:** Advanced `FileIOCreate` monitoring for `\Device\NamedPipe\*` with Shannon entropy + malleable C2 pattern detection.
- [x] **VSS Shadow Copy Watchdog:** Real-time tracking of `vssadmin.exe` and WMI shadow copy creation.
- [x] **AMSI Bypass Detection:** Expanded detection for common AMSI bypass techniques in PowerShell and script hosts.
- [x] **Firewall Tampering Monitoring:** Real-time detection of `netsh advfirewall` and PowerShell firewall cmdlet modifications.
- [x] **Memory Dumping Attempts:** Detection of ProcDump, MiniDumpWriteDump, and related credential dumping tools.
- [x] **Daily Environmental Baseline Sweep:** Low-priority background task for posture assessment.
- [x] **Dormant BYOVD Sweeping:** Enhanced `ImageLoad` alerts for vulnerable drivers.
- [x] **WMI Repository Auditing:** Startup audit of `ROOT\subscription` for suspicious EventFilters.
- [x] **ETW WMI Provider Integration:** Real-time subscription to `Microsoft-Windows-WMI-Activity` for lateral movement detection.

---

### V2 Stability (COMPLETED)
**Objective:** Solidify the V2 architecture by implementing strict guardrails, crash resilience, and graceful teardowns.

- [x] **Armed Defense Guardrails:** Segregated the active defense logic into a strict `-ArmedMode` PowerShell parameter, preventing the C# engine and network orchestrator from suspending threads or modifying firewalls during standard audit deployments.
- [x] **Database Locking Conflict Resolved:** Corrected the NTFS inheritance flow on `C:\ProgramData\DeepSensor\Data` by removing explicit deny `icacls` rules that were previously starving the Python daemon of write access.
- [x] **ML Pipeline Graceful Teardown:** Intercepted the native OS `SIGINT` (Ctrl+C) signal within the PowerShell orchestrator loop, bypassing abrupt process termination and enabling Python to cleanly close its STDIN pipe.
- [x] **Zero-Loss SQLite Caching:** Transitioned the ML temporal baselining engine from an arbitrary batch-commit model to an immediate WAL-flush execution, ensuring total crash resilience and 100% data retention across sudden shutdowns.