# Deep Sensor -> C2 Beacon Hunter Convergence (v3 Roadmap)

**Theme:** Transitioning from Reactive Ring-3 Observation (ETW) to Proactive Ring-0 Interception (WFP/Minifilter) to support Universal Server-Side Application Defense.

**Core Objective:** Fuse the high-speed Native Rust ML engine with a custom Windows Kernel Driver. By intercepting file I/O and network sockets synchronously at Ring-0, the Isolation Forest can mathematically detect and quarantine C2 beacons before the outbound packet leaves the host.

```mermaid
%%{init: {"theme": "dark", "themeVariables": { "fontFamily": "Fira Code, monospace", "lineColor": "#06b6d4", "mainBkg": "#0a0a0a", "textColor": "#e2e8f0"}}}%%
graph TD
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:16px,font-weight:bold;
    classDef core fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef logic fill:#0a0a0a,stroke:#ec4899,stroke-width:2px,color:#ec4899;
    classDef storage fill:#000,stroke:#4ade80,stroke-width:1px,color:#4ade80;
    classDef action fill:#0a0a0a,stroke:#ef4444,stroke-width:2px,color:#ef4444;

    TITLE["v3 ARCHITECTURAL CONVERGENCE"]:::title

    subgraph Ring0 ["RING 0 // KERNEL SPACE"]
        WFP["WFP Network Callouts<br/>(Socket Interception)"]:::logic
        MINI["FSFilter / ObReg<br/>(OS & File Interception)"]:::logic
        DRIVER["endpoint_monitor_driver.sys<br/>(Rust WDM)"]:::core
        BUFFER["Atomic Ring Buffer<br/>(Lock-Free IPC)"]:::storage
        Q_ARRAY["Quarantine PID Array<br/>(Active Blocklist)"]:::action
    end

    subgraph Ring3 ["RING 3 // USER SPACE"]
        CSHARP["OsSensor.cs<br/>(Inverted Call Orchestrator)"]:::core

        subgraph MLEngines ["NATIVE RUST FFI (DeepSensor_ML.dll)"]
            C2_HUNTER["C2 Beacon Hunter<br/>(Network Behavior & Math)"]:::logic
            DEEP_SENSOR["Deep Visibility Sensor<br/>(Sigma Rules & UEBA)"]:::logic
        end
    end

    %% Telemetry Ingestion
    WFP -->|"Network Traffic"| DRIVER
    MINI -->|"OS Operations"| DRIVER
    DRIVER -->|"Push Event"| BUFFER
    CSHARP <-->|"Poll via IOCTL"| BUFFER

    %% Micro-Batch Routing
    CSHARP ==>|"Socket Micro-Batch"| C2_HUNTER
    CSHARP ==>|"OS Micro-Batch"| DEEP_SENSOR

    %% Containment Loop
    C2_HUNTER -.->|"Flag Beacon Pattern"| CSHARP
    DEEP_SENSOR -.->|"Flag Anomalous OS Behavior"| CSHARP

    CSHARP -.->|"Push Malicious PID"| Q_ARRAY
    Q_ARRAY -.->|"STATUS_ACCESS_DENIED"| WFP
    Q_ARRAY -.->|"STATUS_ACCESS_DENIED"| MINI

    TITLE ~~~ WFP
```

---

## Phase 1: Deep Visibility v2.1 Stabilization (COMPLETED)
*The foundation is mathematically sound and stripped of interpreted bottlenecks.*
- [x] **Python Deprecation:** Completely removed the Python daemon and STDIN/STDOUT pipe latency.
- [x] **Native FFI Implementation:** Compiled the Isolation Forest and UEBA SQLite engine into a native C-compatible DLL (`lib.rs`).
- [x] **Micro-Batching:** Engineered the C# `BlockingCollection` to feed up to 1,000 events per P/Invoke cross, eliminating thread pool exhaustion.
- [x] **Asynchronous Training:** Implemented `Arc<RwLock>` allowing the Isolation Forest to rebuild in a background thread without pausing ETW ingestion.

## Phase 2: Ring-0 Telemetry Pipeline (Current Sprint)
*Replacing the asynchronous C# ETW listener with synchronous Rust kernel callbacks.*
- [ ] **WDK Compilation Pipeline:** Finalize `build.rs` and `Cargo.toml` configurations for the `wdk-sys` WDM driver model.
- [ ] **Minifilter Registration:** Implement `FLT_OPERATION_REGISTRATION` for `IRP_MJ_CREATE`, `READ`, and `WRITE` to track process and file operations natively.
- [ ] **The Inverted Call Bridge:** Wire the lock-free `AtomicUsize` Ring Buffer (`buffer.rs`) to securely hold kernel events until the C# orchestrator polls them via `DeviceIoControl`.

## Phase 3: C2 Beacon Hunter Integration
*Bringing the specific C2 hunting logic down to the kernel.*
- [ ] **WFP Callout Hooks:** Instrument the Windows Filtering Platform (WFP) to capture outbound IPv4/IPv6 socket creation.
- [ ] **Network Entropy Correlation:** Feed the destination IPs, payload sizes, and connection frequencies into the Ring-3 FFI ML Engine.
- [ ] **Beacon Pattern Recognition:** Configure the Isolation Forest to score rhythmic, low-jitter outbound network calls typical of Cobalt Strike or sliver beacons.

## Phase 4: Synchronous Active Defense
*Executing wire-speed containment without crashing the host.*
- [ ] **Kernel Quarantine Array:** Utilize the `QUARANTINED_PIDS` atomic array in `buffer.rs` to maintain a strict blocklist.
- [ ] **Drop-on-Sight:** When the ML engine flags a PID as a beacon (-1.0 score), C# pushes the PID via IOCTL to the kernel array. The minifilter and WFP hooks instantly `STATUS_ACCESS_DENIED` all further operations for that PID.
- [ ] **Driver Signing & HLK:** Execute `sign_kernel_driver.ps1` using the EV Certificate and submit for WHCP attestation to bypass HVCI restrictions on modern OS builds.


## Platform Development

### The 20k-Foot View: The "Nexus" Architecture

The architecture will have three distinct layers:
1. **The Telemetry Bus**
2. **The Unified ML Brain**
3. **The Control Plane**.

```mermaid
%%{init: {"theme": "dark", "themeVariables": { "fontFamily": "Fira Code, monospace", "lineColor": "#06b6d4", "mainBkg": "#0a0a0a", "textColor": "#e2e8f0"}}}%%
graph TD
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:16px,font-weight:bold;
    classDef core fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef logic fill:#0a0a0a,stroke:#ec4899,stroke-width:2px,color:#ec4899;
    classDef storage fill:#000,stroke:#4ade80,stroke-width:1px,color:#4ade80;
    classDef action fill:#0a0a0a,stroke:#ef4444,stroke-width:2px,color:#ef4444;
    classDef orchestrator fill:#1e1e1e,stroke:#f59e0b,stroke-width:2px,color:#f59e0b;

    TITLE["V3 NEXUS XDR PLATFORM"]:::title

    subgraph ControlPlane ["THE CONTROL PLANE (Orchestrator)"]
        CONFIG[("Platform Policy & Tuning\n(User Configs / Weights)")]:::storage
        ORCHESTRATOR["Nexus Orchestrator Service\n(Module Loader & Policy Router)"]:::orchestrator
    end

    subgraph TelemetryBus ["THE UNIFIED TELEMETRY BUS"]
        RING0["endpoint_monitor.sys\n(Ring-0 WFP & FSFilter)"]:::core
        OS_SENSOR["Deep Visibility Sensor\n(Ring-3 ETW OS/Memory)"]:::core
        C2_SENSOR["C2 Beacon Hunter\n(Ring-3 ETW Network)"]:::core
        DLP_SENSOR["Data Protection (Future)\n(Ring-3 File Ops)"]:::core

        BUFFER["Lock-Free Micro-Batch Router\n(Normalized Structs)"]:::storage
    end

    subgraph MLEngine ["NATIVE RUST UNIFIED ML ENGINE (lib.rs)"]
        GRAPH["Time-Series Graph Correlator\n(PID + Time + Hash)"]:::logic

        subgraph Models
            ISO_FOREST["Isolation Forest\n(Lineage Anomaly)"]:::logic
            DBSCAN["DBSCAN Clustering\n(Beacon Jitter)"]:::logic
            ENTROPY["Shannon Entropy\n(Obfuscation)"]:::logic
        end

        CONFIDENCE["Multi-Modal Confidence Scorer\n(Cross-Sensor Conviction)"]:::action
    end

    %% Control Flow
    CONFIG -->|"Hot-Swap Params"| ORCHESTRATOR
    ORCHESTRATOR -->|"Enable/Tune"| RING0
    ORCHESTRATOR -->|"Enable/Tune"| OS_SENSOR
    ORCHESTRATOR -->|"Enable/Tune"| C2_SENSOR
    ORCHESTRATOR -.->|"Update Thresholds"| MLEngine

    %% Telemetry Flow
    RING0 ==>|"Raw Kernel I/O"| BUFFER
    OS_SENSOR ==>|"Raw OS Events"| BUFFER
    C2_SENSOR ==>|"Raw Sockets"| BUFFER
    DLP_SENSOR ==>|"Raw DLP Events"| BUFFER

    BUFFER ===>|"Multi-Modal Batch"| GRAPH
    GRAPH ==> ISO_FOREST
    GRAPH ==> DBSCAN
    GRAPH ==> ENTROPY

    ISO_FOREST --> CONFIDENCE
    DBSCAN --> CONFIDENCE
    ENTROPY --> CONFIDENCE

    CONFIDENCE -.->|"Kill/Block Command"| ORCHESTRATOR
    ORCHESTRATOR -.->|"Execute Block"| RING0

    TITLE ~~~ ControlPlane
```

---

### Core Pillar 1: The Unified Native ML Engine (Rust)
Because we have dropped Python, we are no longer bound by IPC bottlenecks. The new `lib.rs` DLL becomes a **multi-modal mathematical engine**.

Instead of routing network data *only* to the C2 logic and OS data *only* to the Isolation Forest, **all telemetry enters a unified Time-Series Graph Correlator**.
* **The Correlation Matrix:** When the engine receives events, it links them by `PID`, `TID`, and `Timestamp`.
* **The Multiplier Effect:** If the DBSCAN clustering algorithm detects a borderline network jitter (e.g., 60% confidence of a C2 beacon), it queries the Isolation Forest: *"Did this PID exhibit anomalous lineage recently?"* If the Isolation Forest confirms that the PID was spawned by `wmiprvse.exe` (lateral movement) 400ms prior, the engine applies a mathematical multiplier, spiking the total confidence to 99.9% and instantly triggering a quarantine.

### Core Pillar 2: The Nexus Orchestrator (The Control Plane)
To manage multiple sensors, the orchestrator (currently the PowerShell/C# hybrid, eventually transitioning to a standalone Rust Service) acts as the **Module Loader**.
* **Dynamic Loading:** Sensors are no longer hardcoded loops. They are classes or native threads. The orchestrator reads a configuration file and spins up the requested sensors (e.g., "Load OS Sensor", "Disable DLP Sensor").
* **Configuration Hot-Swapping:** User parameters (e.g., `EntropyThreshold = 5.5`, `AutoQuarantine = True`, `LearningDays = 14`) are stored in an `Arc<RwLock<Config>>` in the Rust engine. The orchestrator can dynamically overwrite this lock without tearing down the telemetry pipeline, immediately altering the ML engine's sensitivity on the fly.

### Core Pillar 3: Standardized Telemetry Schema
For a single ML engine to correlate data from a Ring-0 driver, a Ring-3 network ETW feed, and an OS behavioral feed, the telemetry schema must be heavily normalized before it crosses the FFI boundary into Rust.
* Instead of custom JSON strings per sensor, all sensors map their findings into a standardized Rust struct (e.g., `PlatformEvent`).
* Every `PlatformEvent` must contain a global `ActorID` (usually the PID/TID combo) and a microsecond-precision timestamp. This allows the Rust correlation graph to weave the disparate events into a single execution storyline seamlessly.

### Core Pillar 4: Centralized Ring-0 Enforcement
In V3, the Ring-0 driver (`endpoint_monitor_driver.sys`) is not just a sensor; it is the ultimate enforcement arm of the platform.
* When the Unified ML Engine reaches a conviction confidence of 100%, it doesn't need to guess how to stop it. It simply returns the `PID` to the Orchestrator with an `ACTION_KILL` flag.
* The Orchestrator pushes that PID directly into the Ring-0 `QUARANTINED_PIDS` atomic array. The driver immediately slices all outbound network sockets (WFP) and blocks all disk I/O (FSFilter) for that process simultaneously.

### The Developmental Path Forward
To bridge the gap from the current V2.1 architecture to this V3 Platform, the next logical step is to build the **Unified Config Struct** and the **Time-Series Graph Correlator** in the Rust DLL. This prepares the mathematical brain to accept and correlate the C2 network batches alongside the OS batches.

## High Level Phases

**V3 Ascendancy Roadmap**

* **Phase 1: Foundation Soak (Current)** -> Monitor V2.1 (Native FFI OS Sensor) for absolute stability, memory safety, and ETW drop-rates under extreme stress.
* **Phase 2: Protection Standardization** -> Optimize, standardize, and harden the Active Defense (Suspend/Dump/Strip) containment cycle to ensure it triggers flawlessly without destabilizing the host.
* **Phase 3: Sensor Fusion** -> Absorb the C2 Beacon Hunter. Wire the Ring-3 network ETW telemetry into `OsSensor.cs` and merge the DBSCAN clustering logic into the native `lib.rs` DLL.
* **Phase 4: Unified ML Correlation** -> Link the OS and Network feeds into a single Time-Series Graph Correlator within Rust to achieve cross-modal conviction (Testing & Validation).
* **Phase 5: Ring-0 Vanguard** -> Inject the `endpoint_monitor_driver.sys` kernel driver. Transition from reactive Ring-3 ETW observation to synchronous Ring-0 WFP/FSFilter interception.
* **Phase 6: The Nexus Platform (V3)** -> Finalize the Orchestrator Control Plane, linking the Ring-0 telemetry/containment pipeline directly into the Unified ML Engine for true XDR capabilities.
