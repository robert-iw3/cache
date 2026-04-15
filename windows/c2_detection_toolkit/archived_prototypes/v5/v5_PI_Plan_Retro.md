# Program Increment (PI) Plan: C2 Hunter V5 "Active Defense Hardening"

## 1. PI Vision and Objectives
**Vision:** Elevate the C2 Hunter architecture from a robust detection script into an APT-grade, tamper-resilient Endpoint Detection and Response (EDR) engine capable of defeating parasitic thread injection, sensor blinding (BYOVD), Domain Fronting obfuscation, and C2 sleep obfuscation via heuristic memory extraction.

**Committed PI Objectives:**
1. Deliver Thread-Level Correlation to isolate malicious behavior within legitimate host processes without causing system instability.
2. Deliver Surgical Containment via Win32 API (`SuspendThread`) to freeze compromised threads for forensic extraction.
3. Deploy an Anti-Tamper Sensor Heartbeat to detect ETW hooking or Ring-0 driver blinding attacks.
4. Deliver Heuristic Memory Extraction to bypass C2 sleep obfuscation and extract decrypted payloads directly from RAM.

**Uncommitted (Stretch) Objectives:**
1. *Architectural Enabler:* Pivot to the NDIS Packet Capture ETW provider.
2. Deliver JA3 TLS Fingerprinting to bypass CDN/Domain Fronting evasion tactics. *(Note: Classified as uncommitted due to the high engineering complexity of raw byte-level packet parsing in C#).*

---

## 2. Feature and Enabler Backlog

### Feature 1: Surgical Thread Containment Engine
* **Story 1.1:** Upgrade the C# ETW listener to extract `data.ThreadID` and append it to the JSON IPC payload.
* **Story 1.2:** Refactor the PowerShell State Tracker. Migrate the correlation key structure from `PID_IP` to `PID_TID_IP` to ensure ML mathematics are applied per-thread.
* **Story 1.3:** Implement `kernel32.dll` P/Invoke inside `Invoke-C2Containment.ps1` to execute `OpenThread`, `SuspendThread`, and `CloseHandle`.
* **Story 1.4:** Update the containment logging module to track suspended TIDs and output memory dump instructions for forensic analysts.

**Update: Testing Finished, QA Validated, done.**

### Feature 2: Anti-Tamper Sensor Watchdog
* **Story 2.1:** Implement an asynchronous background runspace in the orchestrator that issues a synthetic TCP connection attempt (`127.0.0.99:443`) every 60 seconds.
* **Story 2.2:** Update the main ETW loop to intercept the canary domain/IP and update a `$LastHeartbeat` timestamp.
* **Story 2.3:** Implement a deadman's switch mechanism. If `$now - $LastHeartbeat` exceeds 130 seconds, fire a critical "Sensor Blinded" alert and write to the diagnostic log.

**Update: Testing Finished, QA Validated, done.**

### Feature 3: Heuristic Memory Extraction (Sleep Defeat)
* **Story 3.1:** Build an unmanaged Win32 memory reader utilizing `VirtualQueryEx` and `ReadProcessMemory` to scan committed memory pages.
* **Story 3.2:** Implement logic gates to detect advanced evasion techniques, including Unbacked Thread Execution (MEM_PRIVATE) and Module Stomping (Wiped PE/MZ headers in MEM_IMAGE).
* **Story 3.3:** Streamline the scanner with buffer reuse to prevent GC thrashing and suppress `.NET` JIT false positives.
* **Story 3.4:** Integrate `Invoke-AdvancedMemoryHunter.ps1` into the containment pipeline to trigger immediately after thread suspension.

**Update: Testing Finished, QA Validated, done.**

### Architectural Enabler 4: NDIS Raw Packet Inspection & Active Defense
* **Story 4.1:** Modify the C# ETW session to subscribe to `Microsoft-Windows-NDIS-PacketCapture`.
* **Story 4.2:** Develop an unmanaged C# byte scanner capable of isolating the TLS `Client Hello` signature (`0x16 0x03 0x01`).
* **Story 4.3:** Implement the hashing algorithm to extract TLS Version, Ciphers, and Extensions to generate the MD5 JA3 hash.
* **Story 4.4:** Integrate JA3 hash queries into the `Invoke-ThreatIntelCheck.ps1` module (AbuseCH / ThreatFox integration).

**Update: Development finished, initial testing has occurred, awaiting burn-in period for validation and patch/QA modifications.**

---

## 3. Iteration (Sprint) Roadmap
*Assuming standard 2-week iterations.*

* **Iteration 1: Telemetry and Watchdog Foundations**
  * Execute Story 1.1 (C# TID Extraction).
  * Execute Story 1.2 (State Tracker `PID_TID_IP` Refactor).
  * Execute Story 2.1 (Canary Thread Implementation).
* **Iteration 2: Containment and Alerting Execution**
  * Execute Story 1.3 (P/Invoke `SuspendThread` Integration).
  * Execute Story 1.4 (Forensic Logging updates).
  * Execute Story 2.2 & 2.3 (Heartbeat Monitor and Deadman's Alerting).
* **Iteration 3: Heuristic Memory Extraction (Sleep Defeat)**
  * Execute Story 3.1 & 3.2 (Win32 Memory Reader & APT Heuristics).
  * Execute Story 3.3 (Enterprise Optimization & False Positive Suppression).
  * Execute Story 3.4 (Automated Containment Integration Hook).
* **Iteration 4: Integration Testing and Enabler Research**
  * System integration testing of Features 1, 2, and 3. Validation against synthetic thread injection scenarios.
  * Begin execution of Story 4.1 (NDIS Provider Pivot Research & Profiling).
* **Iteration 5: Advanced Fingerprinting & Innovation (IP Sprint)**
  * Execute Story 4.2, 4.3 & 4.4 (TLS Client Hello parsing, JA3 hashing, and CTI updates).
  * Final regression testing.
  * System Demo for stakeholders.
  * Documentation finalization for V5 deployment.

---

## 4. Risk Management (ROAM)

* **Resolved:** * *Risk:* State tracker memory exhaustion from tracking individual threads instead of grouped processes.
  * *Resolution:* Already mitigated by the Hybrid RAM/Disk State Manager implemented in V4.
* **Owned:**
  * *Risk:* Enabling `Microsoft-Windows-NDIS-PacketCapture` may introduce unacceptable CPU overhead in high-throughput environments.
  * *Owner:* Lead Detection Engineer (to conduct performance profiling during Iteration 4).
* **Accepted:**
  * *Risk:* Advanced adversaries may randomize their JA3 fingerprint dynamically (e.g., JA3S randomization).
  * *Acceptance:* We accept that JA3 is an indicator, not a silver bullet. It will be used as a weighted factor in the correlation engine, not a standalone automated containment trigger.
* **Mitigated:**
  * *Risk:* Erroneous thread suspension causing unexpected OS instability.
  * *Mitigation:* `Invoke-C2Containment.ps1` will retain its Dry-Run default state, and the hardcoded System PID/TID whitelist will be strictly enforced prior to executing P/Invoke commands.
  * *Risk:* False positives from `.NET` JIT memory allocations triggering the unbacked thread heuristic during memory hunting.
  * *Mitigation:* Handled via loaded module analysis (`clr.dll`, `mscorlib.dll` exclusions) implemented in Story 3.3.

---

### V5 Architecture Retrospective & Phase 4 Implementation Plan

**Date:** April 8, 2026

**Subject:** Features 1-3 Performance / Unit Testing / QA Validation Review Completed; Phase 4 (Cryptographic Engine) Specification and Retrospective

---

#### Part 1: Retrospective on Features 1-3

**1. Telemetry & IPC Performance (The ETW / ML Bottleneck)**
* **Architecture:** An in-memory C# `TraceEvent` engine piping raw network flows to a Python ML daemon via STDIN/STDOUT.
* **Challenge:** Single-threaded architectures proved fragile under heavy heuristic load (e.g., 300+ TID batches during browser/EDR storms). Initial attempts to decouple the ML handoff into an asynchronous Runspace introduced critical race conditions and broke our Hybrid State Garbage Collection. Furthermore, .NET 8 type-forwarding broke cross-platform C# compilation in PowerShell 7+, and the Python daemon's internal data-grooming silently dropped our loopback health checks, causing false "BAD" states.
* **Resolution:** We abandoned the asynchronous Runspace experiment in favor of a heavily optimized synchronous pipeline. We eliminated the IPC bottleneck by extending the ML handoff timeout to 60 seconds while aggressively dropping the polling latency to 20ms, allowing the main loop to drain the pipe instantly upon completion. The ML Watchdog was expanded to 300 seconds to prevent Deadman panics during heavy DBSCAN calculations. Cross-platform compilation was hardened by directly mapping physical micro-libraries to bypass PS7+ type-forwarding, and the synthetic ML health check was successfully camouflaged as external public traffic (`9.9.9.99`) to force mathematical verification.

**2. Memory Forensics (The Mathematical Collision Problem)**
* **Architecture:** `Invoke-AdvancedMemoryHunter.ps1` utilizing P/Invoke to read raw memory segments natively.
* **Challenge:** Static matching of short byte strings (e.g., the 4-byte `0xDEADBEEF` or the 4-byte Direct Syscall stub) mathematically collided with JIT-compiled browser memory, generating massive false-positive storms. Additionally, heuristics checking for missing MZ headers failed because legitimate OEM hardware packers naturally leave memory segments as Read/Write/Execute (RWX).
* **Resolution:** Detection logic transitioned from static string matching to **Behavioral Constraints** (evaluating abnormal RWX permissions specifically on disk-backed images). A **Wildcard Pattern Matcher** was engineered to scan full 10-byte syscall sequences while dynamically ignoring randomized middle bytes.

**3. DFIR & Containment (The Danger of Blunt Force)**
* **Architecture:** A 1-Click Orchestrator correlating threat intel and executing automated eradication.
* **Challenge:** Executing standard process tree termination poses a critical risk. If an attacker utilizes Process Hollowing or Reflective DLL Injection on critical system binaries (e.g., `svchost.exe`), blunt termination will induce an OS crash.
* **Resolution:** The response pipeline was upgraded to **Surgical Containment**. By extracting the Native Thread ID (TID), the engine uses Win32 APIs to suspend the exact malicious execution flow locked in RAM. The host process remains active, while the evidence matrix is cross-referenced to hunt and destroy the original dropper file on disk.

---

#### Part 2: Phase 4 Strategic Specification (NDIS / JA3 Integration)

Current detection logic relies entirely on behavioral telemetry (timing, mathematical anomalies, and memory protections). Phase 4 will introduce cryptographic certainty by intercepting raw network packets to extract the TLS Client Hello. This allows the pipeline to fingerprint custom HTTP libraries used by frameworks like Cobalt Strike or Sliver.

*Architectural Reality Check: Moving from Layer 4 to Layer 2 (Data Link) means ETW will hand us raw Ethernet frames. To prevent CPU exhaustion and pipeline crashes, the entire L2-to-L7 parsing stack must execute strictly within the inline C# engine. PowerShell will only receive the final cryptographic string.*

**1. The NDIS ETW Subscription & L4 Filter**
* **Specification:** Modify the existing C# ETW session to subscribe to `Microsoft-Windows-NDIS-PacketCapture` instead of relying on legacy raw sockets (`SIO_RCVALL`).
* **Performance Constraint:** Reading raw packets is highly CPU-intensive. We must apply an immediate C# byte-filter to drop any packet where the destination port is not 443 (or standard TLS ports). If the packet is not destined for a TLS port, the thread must return instantly to save cycles.

**2. Unmanaged TLS Client Hello Scanner**
* **Specification:** Develop a fast C# sliding window scanner capable of isolating the TLS `Client Hello` signature (`0x16 0x03 0x01`).
* **Implementation Note:** Blindly searching for these three bytes across raw payloads will yield false positives (e.g., random file downloads). The parser must dynamically calculate offsets—jumping past the Ethernet (14 bytes), IPv4 (20+ bytes), and TCP (20+ bytes) headers—to pinpoint the exact start of the data payload before verifying the signature.

**3. Cryptographic Extraction & JA3 Hashing**
* **Specification:** Implement the hashing algorithm to extract the TLS Version, Ciphers, and Extensions from the Client Hello to generate the MD5 JA3 hash (`SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurveFormat`).
* **State Management:** We will utilize `System.Security.Cryptography.MD5`. Due to our cross-platform architecture, we must explicitly add the cryptography micro-libraries to the `$RefAssemblies` dynamic loader to prevent .NET 8 compiler crashes in PowerShell 7+.
* **Pipeline Fusion:** The inline C# engine will append the calculated JA3 hash directly to the V5 matrix key (e.g., `PID_16312_TID_7012_JA3_e7d705a3286e19ea42f587b344ee6865_Port_443`), passing it seamlessly to the `EventQueue`.

**4. Threat Intel Integration (Abuse.ch)**
* **Specification:** Integrate JA3 hash queries into the `Invoke-ThreatIntelCheck.ps1` module (Abuse.ch / ThreatFox / SSLBlacklist).
* **Execution:** Maintain a local, high-speed cache of known malicious JA3 hashes. If a process reaches out with a matched JA3 hash natively in RAM, it bypasses the ML matrix entirely and triggers immediate Surgical Containment via the Active Defense module.

---

#### Part 3: Retrospective on Phase 4 (NDIS / JA3 Integration & Active Defense)

**1. The C# Compiler & Scope Shielding**
* **Architecture:** Inline compilation of unmanaged C# to intercept NDIS frames at Layer 2 alongside the legacy TCPIP parser at Layer 4.
* **Challenge:** The C# compiler threw fatal scope collision errors during the initial build because variables used in the NDIS payload extraction (`destIp`, `json`) shadowed variables declared further down the pipeline in the TCPIP block.
* **Resolution:** Strict namespace and variable isolation was enforced inside the NDIS interceptor block (e.g., renaming to `ndisDestIp` and `ndisJson`) to guarantee memory safety, isolate the child scopes, and ensure the unmanaged byte-scanner dropped the packet gracefully before hitting the legacy parser.

**2. The Tamper Guard AppDomain Trap**
* **Architecture:** Creating an immutable, NTFS-locked `TamperGuard.log` using strict Access Control Lists (ACLs) to prevent adversaries from tampering with the sensor's state tracking.
* **Challenge:** Attempting to lock the file using native PowerShell cmdlets (`Set-Acl`) failed. The instantiation of the C# `TraceEvent` engine shifted the .NET Application Domain, preventing PowerShell from dynamically loading the `Microsoft.PowerShell.Security` module required to execute the ACL cmdlets. Furthermore, Windows heavily enforced inherited permissions (like "Authenticated Users") from the `C:\Temp` root.
* **Resolution:** We bypassed the PowerShell module constraint entirely by dropping down to native Windows OS binaries. We utilized `icacls.exe /inheritance:r` to violently sever inherited permissions, and mapped universal Windows SIDs (`*S-1-5-18` for SYSTEM) to enforce the lock perfectly regardless of the runtime domain.

**3. L2 to L4 Pipeline Interoperability**
* **Architecture:** Catching cryptographic fingerprints (JA3) extracted from raw NDIS frames and applying them to the active threat ledger.
* **Challenge:** Because NDIS operates at Layer 2, the raw Ethernet frames lacked the Layer 4 Process ID (PID) context required to identify which application generated the packet. Additionally, introducing the new `JA3_C2_FINGERPRINT` event type broke the downstream DFIR vector correlation engine, which was only calibrated to look for `ML_Beacon` events.
* **Resolution:** The main PowerShell loop was upgraded to cross-reference the extracted NDIS Destination IP against the active Layer 4 network tracking dictionary (`$flowMetadata`), successfully mapping the L2 cryptographic hash back to the Ring-3 executable. The DFIR orchestrator (`C2VectorCorrelation.ps1`) was surgically refactored to parse the new cryptographic events, assigning an instant +100 CRITICAL score to verified APT frameworks.

**4. Streamlining the Kill-Chain (Eradication)**
* **Architecture:** The final Phase 5 DFIR action to scrub persistent staging artifacts (Scheduled Tasks, Run Keys) left behind by contained threats.
* **Challenge:** The legacy Phase 5a eradication script (`Invoke-C2Eradication.ps1`) was architecturally incompatible with the new V5 data structures, resulting in orphaned code and un-scrubbed persistence mechanisms.
* **Resolution:** The persistence scrubbing logic (which parses the Forensic Triage report to hunt file droppers and registry keys) was completely excised from the legacy script and merged directly into the new `Invoke-AutomatedEradication.ps1`. This created a single, unified "Seek and Destroy" engine that handles memory acquisition, driver neutralization, persistence wiping, and tactical reboots seamlessly.