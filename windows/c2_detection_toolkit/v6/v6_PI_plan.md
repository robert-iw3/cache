# Program Increment (PI) Plan: C2 Hunter V6 "Offensive-Defense & Infrastructure Exploitation"

## 1. PI Vision and Objectives
**Vision:** Elevate the C2 Hunter architecture from a robust Endpoint Detection and Response (EDR) engine into an active exploitation and deception platform. V6 will expand visibility into server-side applications, track internal peer-to-peer lateral movement, and transition the defense strategy from simply blocking threats to actively fingerprinting and sinkholing adversary infrastructure to extract decrypted stage-2 configurations.

**Committed PI Objectives:**
1. Deliver Server-Side Application Defense to detect web shells and lateral movement via common web servers and databases.
2. Deliver Peer-to-Peer (P2P) Lateral Movement Tracking to correlate internal SMB/Named Pipe pivots with external egress nodes.
3. Deploy Next-Gen Memory Forensics to defeat Thread Call Stack Spoofing and automate C2 Configuration Ripping.
4. Deliver Active Adversary Engagement via JARM fingerprinting and dynamic Stage-2 Sinkholing.

**Uncommitted (Stretch) Objectives:**
1. *Architectural Enabler:* Encrypted Client Hello (ECH) & DoH Evasion Tracking.
2. Implement ML risk weighting for "Opaque TLS" handshakes to future-proof the sensor against the deprecation of plaintext JA3.

---

## 2. Feature and Enabler Backlog

### Feature 1: Universal Server-Side Application Defense (AppGuard)
* **Story 1.1 (Expanded Web Daemons):** Instrument ETW `Kernel-Process` monitoring for modern web proxies and runtimes (e.g., `w3wp`, `nginx`, `node`, `java`, `python`, `dotnet`).
* **Story 1.2 (Expanded DB Daemons):** Instrument `Kernel-Process` monitoring for relational and NoSQL database engines (e.g., `sqlservr`, `postgres`, `redis-server`, `mongod`).
* **Story 1.3 (Heuristics & LOLBins):** Develop behavioral constraints targeting Living off the Land Binaries (`wmic`, `rundll32`, `certutil`) and execution from `SuspiciousPaths` (e.g., `\temp\`, `\inetpub\wwwroot\`).
* **Story 1.4 (O(1) Performance):** Engineer an Integer PID Cache (`ConcurrentDictionary`) to track active server daemons without incurring string-parsing CPU penalties during ETW firehose ingestion.
* **Story 1.5 (Pipeline):** Route AppGuard telemetry into the JSONL stream with dynamic MITRE ATT&CK tags (TA0003/T1505.003), and configure the Orchestrator to execute Precise Containment against the child process to preserve host uptime.

#### Web Application Servers & Proxies
* **Microsoft IIS / ASP.NET (`w3wp.exe`, `iisexpress.exe`):**
    * **The TTP:** Exploitation of deserialization flaws (e.g., ViewState), exploiting unpatched CVEs in enterprise applications (Exchange/SharePoint), or the upload of compiled `.aspx` web shells (e.g., Godzilla, Chopper).
    * **The Behavior:** The IIS worker process unexpectedly dropping into `cmd.exe` or utilizing LOLBins like `rundll32.exe` and `certutil.exe` to stage secondary payloads.
* **Apache Tomcat / Java (`java.exe`, `javaw.exe`, `tomcat*.exe`):**
    * **The TTP:** Exploitation of insecure deserialization (Log4j, Spring4Shell) or the upload of malicious `.jsp` web shells.
    * **The Behavior:** `java.exe` natively spawning `cmd.exe`, `powershell.exe`, or `whoami.exe`.
* **Apache HTTP & Nginx (`httpd.exe`, `nginx.exe`):**
    * **The TTP:** Exploitation of CGI scripts, PHP web shells, or the loading of malicious compiled modules (e.g., rogue `.so` or `.dll` extensions acting as memory-resident C2).
    * **The Behavior:** The web daemon directly dropping into a command interpreter.
* **Node.js / Express (`node.exe`):**
    * **The TTP:** Exploitation of NPM package dependencies or React Server Component deserialization flaws.
    * **The Behavior:** Attackers use the `child_process` module to bind `cmd.exe` to a network socket for a reverse shell.
* **Python Web Frameworks (`python.exe`, `python3.exe`):**
    * **The TTP:** Server-Side Template Injection (SSTI) in Jinja2 (Flask/Django) or insecure `pickle` deserialization vulnerabilities.
    * **The Behavior:** The Python runtime invoking a reverse shell via `bash`, `sh`, or `cmd.exe`.
* **.NET Core / Kestrel (`dotnet.exe`):**
    * **The TTP:** Exploiting vulnerable NuGet dependencies or unsafe type deserialization in modern, cross-platform .NET web APIs.
    * **The Behavior:** `dotnet.exe` spawning `powershell.exe` or compilers like `csc.exe` outside of a legitimate Just-In-Time (JIT) context.
* **PHP CGI / FastCGI (`php.exe`, `php-cgi.exe`):**
    * **The TTP:** Arbitrary file upload of `.php` scripts or exploiting insecure uses of `eval()`, `system()`, or `passthru()` functions.
    * **The Behavior:** The PHP interpreter directly executing system commands or spawning `cmd.exe`.

#### Database & Caching Engines
* **Microsoft SQL Server (`sqlservr.exe`):**
    * **The TTP:** Privilege escalation and lateral movement via the `xp_cmdshell` extended stored procedure, or abusing OLE automation procedures (`sp_OACreate`) via SQL injection.
    * **The Behavior:** `sqlservr.exe` natively spawning `cmd.exe` or `powershell.exe` to download network beacons.
* **MySQL / MariaDB (`mysqld.exe`, `mariadbd.exe`):**
    * **The TTP:** Attackers with SQL access use `SELECT ... INTO DUMPFILE` to write a malicious `.dll` to the Windows plugin directory, then create a **User Defined Function (UDF)** (e.g., `sys_exec`).
    * **The Behavior:** The database engine is hijacked to execute arbitrary OS commands as the `NETWORK SERVICE` or `SYSTEM` account.
* **PostgreSQL (`postgres.exe`):**
    * **The TTP:** Abuse of the `COPY FROM PROGRAM` command. Since Postgres 9.3, authenticated users with the `pg_execute_server_program` role can force the database to execute OS commands directly.
    * **The Behavior:** `postgres.exe` spawning shells.
* **Oracle Database (`oracle.exe`, `tnslsnr.exe`):**
    * **The TTP:** Exploitation of the Oracle TNS Listener or abusing Java stored procedures within the Oracle database architecture to break out into the host OS.
    * **The Behavior:** The Oracle engine or listener daemon spawning `cmd.exe`, `certutil.exe`, or `wscript.exe`.
* **Redis (`redis-server.exe`):**
    * **The TTP:** Attackers exploit unauthenticated Redis instances to load **Rogue Modules** (`MODULE LOAD`) or abuse the Lua sandboxing engine.
    * **The Behavior:** The in-memory cache server suddenly attempts to spawn a Windows command shell.
* **MongoDB (`mongod.exe`):**
    * **The TTP:** Server-Side JavaScript Execution (SSJS) injection via the `$where` operator or exploiting unauthenticated, internet-exposed endpoints.
    * **The Behavior:** The `mongod.exe` process invoking shell commands to establish a C2 beacon.
* **Memcached (`memcached.exe`):**
    * **The TTP:** UDP amplification vectors or memory corruption vulnerabilities leading to remote code execution.
    * **The Behavior:** The in-memory cache daemon unexpectedly dropping into a command interpreter.

### Feature 2: Advanced Lateral Movement Tracking (P2P)
* **Story 2.1:** Expand the C# ETW engine to filter `Microsoft-Windows-Kernel-File` specifically for the creation of `\Device\NamedPipe\` handles associated with known C2 default pipenames.
* **Story 2.2:** Develop correlation logic to link anomalous internal SMB/RPC traffic with processes simultaneously exhibiting outbound ML beaconing traits (Proxy Node signature).
* **Story 2.3:** Update the UI Dashboard and JSONL logging to visually distinguish between internal lateral flows and external egress connections.

### Feature 3: Active Adversary Engagement (JARM & Sinkholing)
* **Story 3.1:** Develop an asynchronous JARM prober. Upon a high-confidence ML alert, actively send 10 crafted TLS `Client Hello` packets to the destination IP to generate a JARM server fingerprint.
* **Story 3.2:** Integrate JARM hashes with the existing Abuse.ch Threat Intel caching mechanism to instantly verify Cobalt Strike/Sliver Team Servers.
* **Story 3.3:** Implement WFP (Windows Filtering Platform) or `netsh interface portproxy` APIs to dynamically intercept compromised sockets and seamlessly route them to `127.0.0.1:9999` (Stage-2 Sinkholing).
* **Story 3.4:** Build a lightweight local Python honeypot listener to capture incoming Stage-2 shellcode/tasking pushed by the C2 server, dumping it into the DFIR evidence locker.

### Feature 4: Next-Gen Memory Forensics (Call Stack & Config Ripping)
* **Story 4.1:** Upgrade `Invoke-AdvancedMemoryHunter.ps1` with `StackWalk64` Win32 APIs to examine thread return addresses, detecting Thread Call Stack Spoofing (masquerading as `kernelbase.dll`).
* **Story 4.2:** Develop a headless Python Config Ripper to execute during Phase 6 of the DFIR pipeline on acquired `.dmp` files.
* **Story 4.3:** Implement YARA-based AES/XOR decryption routines within the Config Ripper to automatically extract and log C2 domains, jitter rates, and watermarks from dumped memory.

### Architectural Enabler 5: ECH & DoH Evasion Tracking (Next)
* **Story 5.1:** Build heuristics into the ML daemon to profile DoH (DNS over HTTPS) abuse by detecting high-frequency, low-byte TCP/443 connections that strictly precede larger payload bursts.
* **Story 5.2:** Implement mathematical flags for "Opaque TLS" handshakes utilizing ECH padding, assigning a higher baseline risk score to binaries that are not modern browsers.

---

## 3. Iteration (Sprint) Roadmap
*Assuming standard 2-week iterations.*

* **Iteration 1: Server-Side & P2P Foundations**
  * Execute Story 1.1 & 1.2 (Universal AppGuard Daemon Instrumentation for Web/DB Arrays).
  * Execute Story 1.3 (Execution Path Heuristics & LOLBin HashSet Integration).
  * Execute Story 1.4 & 1.5 (O(1) Integer PID Cache & MITRE ATT&CK Pipeline Injection).
  * Execute Story 2.1 (Named Pipe ETW Extraction).
* **Iteration 2: Next-Gen Memory & Call Stack Analysis**
  * Execute Story 4.1 (`StackWalk64` Spoofing Detection).
  * Execute Story 4.2 (Python Config Ripper Skeleton).
  * Execute Story 4.3 (AES/XOR Decryption Routines).
* **Iteration 3: Active Engagement (Fingerprinting)**
  * Execute Story 3.1 (Asynchronous JARM Prober).
  * Execute Story 3.2 (Threat Intel JARM Integration).
  * Execute Story 1.3 & 2.2 (Data Correlation & Pipeline Integration).
* **Iteration 4: Active Engagement (Sinkholing & Capture)**
  * Execute Story 3.3 (WFP/PortProxy Socket Interception).
  * Execute Story 3.4 (Python Honeypot Listener & DFIR Integration).
  * Execute Story 2.3 (Dashboard UI Updates).
* **Iteration 5: Evasion Tracking & Integration (IP Sprint)**
  * Execute Story 5.1 & 5.2 (DoH Heuristics and ECH Profiling).
  * System integration testing of Features 1-4.
  * Final regression testing.
  * System Demo for stakeholders.
  * Documentation finalization for V6 deployment.

---

### Risk Management (ROAM)
---

* **Resolved:** * *Risk:* CPU exhaustion and pipeline freezing caused by continuous string parsing of `ParentImageFileName` during ETW firehose ingestion.
  * *Resolution:* Eliminated by engineering the O(1) Integer PID Cache (`ConcurrentDictionary`), ensuring strings are only parsed once during daemon startup.
  * *Risk:* CPU exhaustion from raw NDIS packet capture causing sensor lockups.
  * *Resolution:* Mitigated by the inline C# byte-filter and offset calculations engineered during V5.
* **Owned:**
  * *Risk:* Stage-2 Sinkholing via WFP/PortProxy could introduce host network routing instability if the sensor crashes before tearing down the redirection rules.
  * *Owner:* Lead Detection Engineer (to engineer a fail-safe teardown sequence inside the Orchestrator's `finally` block).
* **Accepted:**
  * *Risk:* WMI Breakaway (`Win32_Process.Create`). Executions invoked via WMI will parent under `WmiPrvSE.exe` rather than the originating web/database daemon, bypassing AppGuard interception.
  * *Acceptance:* Cross-process RPC correlation is intentionally omitted to preserve O(1) ETW performance. Subsequent payloads will be caught downstream by Phase 3 Memory Forensics.
  * *Risk:* Active JARM probing might alert an advanced adversary that their infrastructure is being investigated.
  * *Acceptance:* The probe only fires *after* a high-confidence ML detection has already occurred, meaning the defense team is already preparing to burn the infrastructure.
* **Mitigated:**
  * *Risk:* Legitimate application behavior (e.g., ASP.NET Just-In-Time compilation) triggering false-positive web shell alerts.
  * *Mitigation:* Explicit behavioral constraints engineered into the AppGuard loop to suppress `csc.exe` and `cvtres.exe` executions isolated to the `Temporary ASP.NET Files` directory.
  * *Risk:* The Automated Config Ripper failing to decrypt highly novel or custom C2 frameworks.
  * *Mitigation:* Handled by maintaining the Tier 1-5 WinDbg analysis reports and preserving the raw `.dmp` file in the Evidence Locker for manual analyst reverse engineering.