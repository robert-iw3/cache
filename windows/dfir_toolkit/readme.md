## DFIR Collector & Triage
- Author: Robert Weber

### Quick Deploy
---

1. `cd middleware`
2. `cp .env.example .env` and fill secrets
3. `docker compose up -d` (or `podman-compose up -d`)
4. On endpoints: `.\collector\orchestrator.ps1`

### arch
---
```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'fontFamily': 'Fira Code, monospace', 'lineColor': '#06b6d4', 'mainBkg': '#0a0a0a', 'textColor': '#e2e8f0'}}}%%
graph TD
    %% Cyberpunk Style Definitions
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:18px,font-weight:bold;
    classDef external fill:#050505,stroke:#888,stroke-width:1px,color:#888,stroke-dasharray: 3 3;
    classDef sensor fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef hunter fill:#0a0a0a,stroke:#ec4899,stroke-width:2px,color:#ec4899;
    classDef storage fill:#000,stroke:#4ade80,stroke-width:1px,color:#4ade80;
    classDef etl fill:#0a0a0a,stroke:#a78bfa,stroke-width:2px,color:#a78bfa;
    classDef deploy fill:#0a0a0a,stroke:#f59e0b,stroke-width:2px,color:#f59e0b;

    %% Node Definitions
    TITLE["DFIR COLLECTOR v3.1 // NATIVE POWERSHELL + MULTI-SIEM MIDDLEWARE"]:::title

    subgraph EndpointSpace [WINDOWS ENDPOINTS]
        ENDPOINT["🖥️ Windows Endpoint<br/>collect_forensics.ps1<br/>orchestrator.ps1"]:::sensor
    end

    subgraph CollectorSpace [COLLECTION ENGINE]
        COLLECT["collect_forensics.ps1<br/>• Phase 1-6 artifacts<br/>• AMCache.hve + ShimCache<br/>• Event Logs + Registry"]:::hunter
        ZIP["ZIP + Base64 Payload<br/>+ Chain-of-Custody SHA256"]:::storage
        ORCH["orchestrator.ps1<br/>→ Triage + Anomaly Hunt"]:::hunter
    end

    subgraph MiddlewareSpace [DOCKER / PODMAN CONTAINER]
        MIDDLEWARE["middleware.py<br/>(or middleware.ps1)<br/>+ config.ini + .env"]:::hunter
        PARSER["JSON Payload Handler<br/>+ Multipart Fallback"]:::etl
    end

    subgraph AnalysisSpace [LOCAL TRIAGE + ANOMALY HUNT]
        TRIAGE["triage_response.ps1<br/>Heuristic Rules<br/>RED / YELLOW / GREEN Verdict"]:::hunter
        ANOMALY["anomaly_hunt.ps1<br/>Shannon Entropy + Beacon Rhythm"]:::hunter
        REPORT["DFIR_Report.html<br/>+ CSV exports + manifest.json"]:::storage
    end

    subgraph SIEMSpace [MULTI-SIEM DESTINATIONS]
        SPLUNK["🔍 SPLUNK<br/>HEC (on-prem / cloud)"]:::external
        ELASTIC["🧲 ELASTIC / OPENSEARCH<br/>_bulk API"]:::external
        SENTINEL["☁️ MICROSOFT SENTINEL<br/>Log Analytics"]:::external
        DATADOG["🐶 DATADOG<br/>HTTP Intake"]:::external
        SYSLOG["📡 SYSLOG<br/>UDP / TCP"]:::external
    end

    subgraph DeploySpace [DEPLOYMENT]
        DOCKER["🐳 DOCKER / PODMAN<br/>Dockerfile + docker-compose.yml"]:::deploy
        ENV[".env + config.ini<br/>Secrets Management"]:::storage
    end

    %% Edge Connections (Top → Bottom Flow)
    ENDPOINT -->|"Native PowerShell<br/>Run as Admin"| COLLECT
    COLLECT -->|"JSON artifacts<br/>+ manifest.json"| ZIP
    ZIP ==>|"Base64 ZIP over HTTPS<br/>Bearer Token Auth"| MIDDLEWARE
    MIDDLEWARE -->|"Parse + Chunk"| PARSER
    PARSER -->|"Batched + Throttled"| SPLUNK
    PARSER -->|"Batched + Throttled"| ELASTIC
    PARSER -->|"Batched + Throttled"| SENTINEL
    PARSER -->|"Batched + Throttled"| DATADOG
    PARSER -->|"Batched + Throttled"| SYSLOG

    ORCH -->|"KeepLocalCopy = $true"| TRIAGE
    ORCH -->|"KeepLocalCopy = $true"| ANOMALY
    TRIAGE & ANOMALY -->|"HTML + CSV + manifest"| REPORT

    MIDDLEWARE <-->|"Load Rules / Config"| ENV
    DOCKER ==>|"Build & Deploy<br/>middleware.py"| MiddlewareSpace

    classDef title fill:none,stroke:none,color:#06b6d4,font-size:18px,font-weight:bold;
    class TITLE title
```