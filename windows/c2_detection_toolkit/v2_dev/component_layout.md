### Logical Layout
---

1. **The Ingestion Lane (ETW to Pre-Filters):** This must be entirely zero-allocation. The C# engine reads raw memory pointers from Windows ETW and immediately discards 95% of traffic (RFC 1918, safe domains, broadcast) before it ever becomes a C# object.
2. **The Stateful Analysis Lane (C# Orchestrator):** Traffic that survives the pre-filters is routed to specialized engines. The Aho-Corasick engine performs O(1) threat intel matching. Flow Metadata is stored in `ConcurrentQueue` structures to prevent heap fragmentation.
3. **The Math & Memory Lane (Rust ML Engine):** This is physically separated into `c2sensor_ml.dll`. Instead of passing slow JSON strings, the C# orchestrator passes native memory pointers across the Foreign Function Interface (FFI) bridge directly into Rust. Rust handles the heavy K-Means clustering and SQLite database writes autonomously, preventing the .NET Garbage Collector from ever seeing that data.
4. **The Execution Lane (Active Defense):** When an anomaly is confirmed by either the C# heuristics or the Rust ML engine, the defense module executes mitigation asynchronously to prevent blocking the main network listener thread.

```mermaid
graph TD
    subgraph OS["Windows OS Layer"]
        ETW[Windows Kernel ETW]
        NDIS[NDIS Packet Capture]
        FW[Windows Firewall & Process Manager]
    end

    subgraph CSharp["C# Native Orchestrator (C2Sensor.exe)"]
        Trace[TraceEvent Memory Listener]
        PreFilter{Zero-Allocation Pre-Filters}
        Drop[Dropped Noise]
        
        subgraph Analysis["Stateful Analysis Lane"]
            AC[Aho-Corasick Threat Intel]
            AppGuard[AppGuard Lineage Tracker]
            JA3[JA3 Cryptographic DPI]
            FlowQ[(O-1 Flow Metadata Queues)]
        end

        Alerts[Alert Dispatcher & UI HUD]
        Defense[Active Defense Engine]
    end

    subgraph Rust["Rust Unmanaged Boundary (c2sensor_ml.dll)"]
        FFI[Native FFI Memory Bridge]
        ML[K-Means Clustering Math Engine]
        DB[(SQLite WAL Database)]
    end

    %% Data Flow - Ingestion
    ETW -->|Raw Pointers| Trace
    NDIS -->|Raw Frames| Trace
    Trace -->|Unboxed Objects| PreFilter
    
    %% Filtering
    PreFilter -->|RFC 1918 / Safe Domains| Drop
    PreFilter -->|Network Traffic| AC
    PreFilter -->|Process Creation| AppGuard
    PreFilter -->|TLS Client Hello| JA3

    %% Direct Heuristics to Alerts
    AC -->|Suricata Match| Alerts
    AppGuard -->|Web Shells / RCE| Alerts
    JA3 -->|Matched Fingerprints| Alerts

    %% Stateful Math Lane
    AC -->|Standard Traffic Flow| FlowQ
    FlowQ -->|Batched Context via Memory Pointers| FFI
    FFI --> ML
    ML <-->|Historical State| DB
    ML -->|Confirmed Anomalies| FFI
    FFI -->|Evaluated Alerts| Alerts

    %% Execution Lane
    Alerts -->|Confidence > 85%| Defense
    Defense -->|Terminate Process / Block IP| FW

    %% Styling
    classDef os fill:#2d3436,stroke:#636e72,stroke-width:2px,color:#dfe6e9;
    classDef csharp fill:#0984e3,stroke:#74b9ff,stroke-width:2px,color:#ffffff;
    classDef rust fill:#d63031,stroke:#ff7675,stroke-width:2px,color:#ffffff;
    classDef queue fill:#e17055,stroke:#fab1a0,stroke-width:2px,color:#ffffff;
    classDef filter fill:#00b894,stroke:#55efc4,stroke-width:2px,color:#ffffff;

    class ETW,NDIS,FW os;
    class Trace,Alerts,Defense csharp;
    class FFI,ML,DB rust;
    class FlowQ queue;
    class PreFilter,Drop,AC,AppGuard,JA3 filter;
```