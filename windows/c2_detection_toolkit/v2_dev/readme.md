## The Plan

### Step 1: Transition PowerShell Functionality to C#
The goal is to recreate all management and orchestration logic currently residing in `C2Sensor_Launcher.ps1`.
* **Suricata Signature Pipeline**: Port the rule downloader and unmanaged byte-scanner parser that extracts IP and FQDN signatures from Emerging Threats feeds.
* **Stateful Sliding Windows**: Implement the connection history and flow metadata trackers using native C# `ConcurrentQueue` and `ConcurrentDictionary` to manage packet sizes and destination IPs without the overhead of PowerShell hashtables.
* **Active Defense Module**: Migrate the `Invoke-ActiveDefense` logic, utilizing native `System.Diagnostics.Process` for termination and direct `netsh` or `Windows Filtering Platform (WFP)` calls for IP blocking.
* **Metric Orchestration**: Port the calculation of processed events, active flows, and lateral movement pings to a centralized metrics controller.

### Step 2: Build Out Modern UI (Dark Mode)
The current ASCII-based HUD will be replaced by a hardware-accelerated **WPF** or **WinUI 3** interface.
* **Card-Based Dashboard**: Implement high-level "Health Tiles" for the ETW Sensor, ML Engine, and Guard State based on the provided modern UI reference.
* **Live Telemetry Analytics**: Integrate hardware-accelerated line charts to visualize real-time event volume and outbound network flows.
* **Reactive Alert Feed**: Replace the static text-block HUD with a high-contrast datagrid that displays the most recent 20-50 alerts with hover-effects for detailed threat intelligence.

### Step 3: Infuse C2Sensor.cs (ETW Engine) into the Main Application
The existing unmanaged ETW engine will be integrated directly into the .NET 8 project.
* **TraceEvent Session Management**: Host the `TraceEventSession` and configure kernel providers (Process, TCPIP, DNS, File, Memory, and NDIS) directly within the executable's lifecycle.
* **Zero-Allocation Pre-Filtering**: Retain and optimize the C# pre-filtering logic that discards high-frequency thread and system noise before it ever becomes a managed object.
* **Aho-Corasick Integration**: Ensure the native Aho-Corasick state machine is armed with Suricata signatures to perform O(1) matching against live streams.

### Step 4: Create the Link to the UEBA/ML Rust DLL
Establish the high-speed bridge between the C# orchestrator and the unmanaged `c2sensor_ml.dll` Rust library.
* **Native FFI PInvoke**: Implement the `[DllImport]` signatures for `init_engine`, `evaluate_telemetry`, and `teardown_engine`.
* **Zero-Serialization Handoff**: Replace legacy JSON string passing with a direct memory pointer bridge, allowing batched connection history queues to flow into the Rust clustering engine without GC pressure.

### Step 5: Performance Tuning
Optimize the entire codebase for minimal resource consumption and maximum uptime.
* **Native AOT Compilation**: Utilize .NET 8 Native Ahead-of-Time (AOT) compilation to produce a single, self-contained binary with a minimal startup footprint.
* **I/O Streamlining**: Use a lock-free `StreamWriter` with a persistent handle for high-volume diagnostic logging to prevent disk I/O bottlenecks.
* **Memory Gating**: Finalize the logic that only constructs complex JSON objects for confirmed threat intel matches, keeping the "benign path" entirely zero-allocation.

### Step 6: Compile and Test
Final validation phase to ensure the migration meets the performance and stability goals.
* **Baseline Validation**: Confirm that the compiled executable idles at or below the 150MB RAM threshold compared to the current 600-800MB PowerShell baseline.
* **Stress Testing**: Validate that the sensor remains responsive (<10ms processing latency) during high-load scenarios exceeding 10,000 packets per second.
* **Mitigation Testing**: Verify that the Active Defense engine correctly triggers Firewall and Process termination rules when confidence scores breach the >85% threshold.

---

### Phase 1 Verification: PowerShell to C# Migration

| Core Feature / Subsystem | Legacy PowerShell (`C2Sensor_Launcher.ps1`) | Native .NET 8 C# (`Program.cs` & `C2Sensor.cs`) | Status |
| :--- | :--- | :--- | :--- |
| **High-Speed Dequeue** | `while ([RealTimeC2Sensor]::EventQueue.TryDequeue([ref]$evtRef))` | `while (RealTimeC2Sensor.EventQueue.TryDequeue(out var evt))` | **Zero-Allocation** |
| **Aho-Corasick Threat Intel** | `Initialize-NetworkThreatIntel` downloading and parsing `.rules` | `ThreatIntelCompiler.SyncAndCompileRules()` via Native `HttpClient` & `Regex` | **Ported** |
| **JA3 Fingerprint Cache** | `Invoke-WebRequest` to abuse.ch with `$global:MaliciousJA3Cache` | `SyncJA3Signatures()` downloading and mapping to a native `HashSet<string>` | **Ported** |
| **Static Behavioral Gates** | Regex matching for `-EncodedCommand` and DGA entropy math | `MathHelpers.IsAnomalousDomain()` and `Regex.IsMatch` on `evt.CommandLine` | **Ported** |
| **Proxy Node Correlation** | Time-delta checks between `$EgressTrack` and `$LateralTrack` | `Math.Abs((eTime - lTime).TotalSeconds) < 60` using native `Dictionary` tracking | **Ported** |
| **AppGuard Lineage** | `Submit-SensorAlert -Type $evt.EventName -Destination "Local_Privilege_Escalation"` | `SubmitAlert(evt.EventName, "Local_Privilege_Escalation", evt.Child, ...)` | **Ported** |
| **Sliding Window Tracking** | `$connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()` | `ConnectionHistory[key] = new Queue<DateTime>()` mapped to a custom `FlowMetadata` struct | **Ported** |
| **Rust ML FFI Bridge** | `$payloadArray | ConvertTo-Json` -> `[RealTimeC2Sensor]::EvaluateBatch` | `JsonSerializer.Serialize(payloadList)` -> `RealTimeC2Sensor.EvaluateBatch` | **Ported** |
| **Active Defense Engine** | `Stop-Process -Force` and `netsh advfirewall` calls | `Process.GetProcessesByName(cleanProc)[i].Kill()` and `Process.Start("netsh", ...)` | **Ported** |
| **Auto-Recovery Watchdog** | `logman stop "C2RealTimeSession" -ets` upon starvation | `Process.Start(new ProcessStartInfo("logman", "stop ..."))` triggered by `IsSessionHealthy()` | **Ported** |
| **Garbage Collection (GC)** | `[System.GC]::Collect(1)` and Deep GC every 30 minutes | `GC.Collect(1, GCCollectionMode.Optimized)` and `GC.Collect()` sweeps | **Ported** |
| **TamperGuard ACLs** | `icacls` to restrict the TamperGuard log | Native `FileSecurity.AddAccessRule()` utilizing `FileSystemRights.FullControl` | **Ported** |