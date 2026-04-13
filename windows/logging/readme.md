# Windows Event Forwarding + Cribl Worker Pipeline

**Modern, containerized Windows event collection and forwarding pipeline.**

- Windows clients forward events to WEC server
- Docker Client parses/trim events using schema
- Docker Server forwards to SIEM
- Cribl Stream Worker Node on WEC ingests live logs + archives + Docker JSON, transforms, and sends to Splunk (HEC) or Elastic (HTTPS)

### Quick Start

1. Place all files in one folder
2. Edit `docker-compose.*.yml` (SERVER_URL, Elastic/Splunk credentials)
3. Run:
   ```powershell
   .\Orchestrate-Deployment.ps1 -Deployment Both
   ```
4. Send events from Windows:
   ```powershell
   Get-WinEvent -LogName Security -MaxEvents 50 | ConvertTo-Json -Depth 5 -Compress | Invoke-WebRequest -Uri http://localhost:9881/ -Method Post -ContentType application/json
   ```

**Access:**
- Cribl UI: `https://localhost:9000` (admin/admin)
- Client listens on 9881, Server on 9880

**Supported Destinations:**
- Splunk HEC (HTTPS)
- Elastic / OpenSearch (HTTPS + Basic Auth / API Key)

**Files:**
- schema.json
- client_parser.py / server_parser.py
- Dockerfiles + docker-compose files
- Orchestrate-Deployment.ps1
- Install-CriblWorker.ps1


**Architecture Diagram**
---

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'fontFamily': 'Fira Code, monospace', 'lineColor': '#06b6d4', 'mainBkg': '#0a0a0a', 'textColor': '#e2e8f0'}}}%%
graph TD
    %% Cyberpunk Style
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:18px,font-weight:bold;
    classDef endpoint fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef wec fill:#0a0a0a,stroke:#ec4899,stroke-width:2px,color:#ec4899;
    classDef docker fill:#0a0a0a,stroke:#a78bfa,stroke-width:2px,color:#a78bfa;
    classDef cribl fill:#0a0a0a,stroke:#f59e0b,stroke-width:2px,color:#f59e0b;
    classDef siem fill:#050505,stroke:#4ade80,stroke-width:1px,color:#4ade80;

    TITLE["WINDOWS EVENT PIPELINE v1.0<br/>WEC + Docker + Cribl Worker"]:::title

    subgraph EndpointSpace [WINDOWS ENDPOINTS]
        ENDPOINT["🖥️ Windows Clients<br/>PowerShell → HTTP POST<br/>Get-WinEvent → JSON"]:::endpoint
    end

    subgraph WECSpace [WEC SERVER]
        WEC["WEC Server<br/>ForwardedEvents<br/>+ Archives (D:\Logs)"]:::wec
    end

    subgraph DockerSpace [DOCKER CONTAINERS]
        CLIENT["Docker Client<br/>9881<br/>Parse / Trim / Schema"]:::docker
        SERVER["Docker Server<br/>9880<br/>Forward to SIEM"]:::docker
    end

    subgraph CriblSpace [CRIBL WORKER NODE]
        CRIBL["Cribl Stream Worker<br/>HTTPS UI:9000<br/>Live + Archives + Docker JSON"]:::cribl
    end

    subgraph SIEMSpace [SIEM DESTINATIONS]
        SPLUNK["🔍 SPLUNK<br/>HEC HTTPS"]:::siem
        ELASTIC["🧲 ELASTIC / OPENSEARCH<br/>HTTPS + Auth"]:::siem
    end

    ENDPOINT -->|"HTTP POST JSON"| CLIENT
    WEC -->|"Live + Archives .evtx"| CRIBL
    CLIENT -->|"Trimmed JSON"| SERVER
    CLIENT -->|"Parsed JSON"| CRIBL
    SERVER -->|"Forward"| SPLUNK
    SERVER -->|"Forward"| ELASTIC
    CRIBL -->|"Transform + Forward"| SPLUNK
    CRIBL -->|"Transform + Forward"| ELASTIC

    class TITLE title
```