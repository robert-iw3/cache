**notes, because I forget**

---

**Completed Modifications (v2.7)**

- Implemented `baseline_learner.py` with per-process/dest/hour/weekend baselines, batch DB inserts, Isolation Forest, and data retention.
- Integrated baseline model loading in `c2_beacon_hunter.py` for UEBA score adjustments.
- Added modular eBPF collectors: `ebpf_collector_base.py` (abstract), `bcc_collector.py` (dev), `libbpf_collector.py` (prod with CO-RE).
- Created `collector_factory.py` for config-driven backend selection (auto/BCC/libbpf).
- Added `c2_probe.bpf.c` and `Makefile` in `dev/probes/` for CO-RE compilation.
- Ensured collectors pass MITRE ATT&CK mappings to learner via `record_flow()`.
- Developed `run_full_stack.py` to launch hunter + learner + collector.
- Added `test_c2_simulation_libbpf.py` and `test_baseline_learner.py` in `dev/tests/`.
- Updated configs, Dockerfiles, and compose for full stack support.
- Preserved all v2.6 features (sparse tracking, direction analysis, DNS, UEBA lite).
- **[NEW]** Migrated from fragile Python libbpf bindings to a robust, Native C-Loader (`c2_loader.c`) that compiles alongside the CO-RE probe and streams microsecond events to user-space via JSON.
- **[NEW]** Solved the eBPF verifier strict memory referencing issues to ensure safe mapping of ringbuf data.
- **[NEW]** Shifted eBPF hooks deeper into the Linux network stack (`tcp_sendmsg`, `udp_sendmsg`, `tcp_recvmsg`, `udp_recvmsg`) to extract precise Destination IPs (`8.8.8.8`) directly from kernel socket structs and user-space `msghdr`, solving the `0.0.0.0` UDP/DNS telemetry gap.
- **[NEW]** Expanded the SQLite `baseline.db` schema to act as a high-speed event broker, capturing `pid` and `cmd_entropy` for flawless Process Tree reconstruction.
- **[NEW]** Rewrote the Main Hunter's ingest engine (`snapshot_loop`) to act as a dual-router: seamlessly pivoting between the microsecond SQLite eBPF pipeline and the legacy v2.6 `psutil`/`ss` polling based purely on config, ensuring 100% backward compatibility.

```bash
dev/
├── config_dev.ini                   # Development-specific config (different from main config.ini)
│                                    # Controls ebpf backend, intervals, whitelists, etc.
│
├── run_full_stack.py                # Unified launcher: starts hunter + learner + collector together
│
├── requirements.txt                 # Python dependencies needed only for v2.7 dev
│
├── plan.md                          # Development roadmap and notes for v2.7
│
├── src/                             # Core Python source code (organized as a package)
│   ├── __init__.py                  # Makes src/ a proper Python package (allows clean imports)
│   ├── baseline_learner.py          # Core learning engine - builds statistical + ML baselines
│   ├── ebpf_collector_base.py       # Abstract base class - defines common interface for collectors
│   ├── bcc_collector.py             # BCC-based eBPF collector (development-friendly)
│   ├── libbpf_collector.py          # libbpf + CO-RE collector (production-optimized)
│   └── collector_factory.py         # Factory that chooses BCC or libbpf based on config
│
├── probes/                          # Raw eBPF C source files
│   └── c2_probe.bpf.c               # The actual eBPF probe code (CO-RE compatible)
│   └── Makefile                     # Automated CO-RE compilation
│
└── tests/                           # Unit and integration tests for v2.7 components
    ├── __init__.py                  # Makes tests/ a proper Python package
    ├── test_baseline_learner.py     # Tests for baseline_learner.py
    └── test_c2_simulation_libbpf.py # Simulates normal and C2 traffic for eBPF/learner evaluation
```

**Long-term Modularity**

**Goal**:
Build a **modular eBPF collector** that supports two backends:
- **BCC** → Fast development, easy debugging, great for testing (implemented)
- **libbpf + CO-RE** → Production-grade performance, lower overhead, better portability (implemented)

---

### Overall Architecture (Implemented)

```
Collector Factory
       │
       ├── BCCCollector (dev-friendly)
       └── LibbpfCollector (production-optimized, CO-RE)
                │
         Calls same record_flow() → baseline_learner.py
```

---

### Completed Phases (v2.7)

1. **Phase 1** – Built `baseline_learner.py` + integration into hunter for UEBA adjustments.
2. **Phase 2** – Improved baseline model (added packet size, direction, entropy via eBPF data).
3. **Phase 3** – Implemented eBPF data collection (non-intrusive, modular backends).
4. **Phase 4** – Optional full eBPF detection engine (deferred; current focuses on collection for baselines).

---

### Detailed Next Steps (v2.8 Ideas)

**Step 1: Enhance Baselines**
- Incorporate more eBPF metrics (e.g., interval_ns, packet_size_min/max) into models.
- Add real-time anomaly feedback loop from hunter to learner.

**Step 2: Full eBPF Engine**
- Extend probes to detect in-kernel (e.g., direct beacon scoring).
- Integrate with `c2_defend` for auto-response on eBPF events (blocking directly at the kernel level).

**Step 3: Advanced Testing**
- Add integration tests for full stack (e.g., simulate C2, verify detections/baselines).
- Performance benchmarks (CPU/mem) for BCC vs. Native C-Loader.

**Step 4: Deployment Improvements**
- Systemd service for full stack.
- Kubernetes manifests for containerized prod.

**Step 5: New Features**
- DGA detection in DNS sniffer.
- Export to SIEM (e.g., JSON over HTTP directly from the SQLite pipeline).
- GUI dashboard for anomalies.

**Compilation Instructions for the C Probe** (Verified)

- Run these commands in the dev/probes/ folder:

```bash
cd dev/probes

sudo apt update
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)
make

# Verify
ls -l c2_probe.bpf.o
```

**Pre-reqs** (Updated for v2.7)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r dev/requirements.txt  # For eBPF/ML extras

sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) libbpf-dev   # Ubuntu/Debian
# or
sudo dnf install bcc-tools python3-bcc kernel-devel libbpf-devel                # Fedora/RHEL
```

# Program Increment (PI) 2.8: Active Enforcement & Enterprise Scalability
**Theme:** Transitioning `c2_beacon_hunter` from Passive Detection to Active Enforcement.

As we kick off PI 2.8, our primary objective is to leverage the stable eBPF architectural runway built in PI 2.7 to deliver immediate, automated threat mitigation and enterprise-grade visibility.



## PI 2.8 WSJF Prioritization Matrix
We use **Weighted Shortest Job First (WSJF)** to sequence our Epics. Rapid, closed-loop mitigation (Epic 1) scores highest due to low implementation effort and immediate risk reduction.

| Epic / Feature | Business Value | Risk Reduction / Enablement | Job Size (Effort) | WSJF Score | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. User-Space Active Response (`c2_defend`)** | High (8) | High (8) | Low (3) | **Highest** | **1** |
| **2. Enterprise Export (SIEM/Dashboards)** | High (8) | Medium (5) | Medium (5) | **High** | **2** |
| **3. eBPF DNS & Payload Entropy** | Medium (5) | High (8) | Medium (5) | **Medium** | **3** |
| **4. Next-Gen eBPF Active Blocking (XDP)** | Highest (13) | High (8) | Highest (13) | **Lowest** | **4** |

---

## Sprint Execution Plan (Iterations)

### Iteration 2.8.1: Epic 1 - Closed-Loop Active Response (`c2_defend`)
**Type:** Business Epic

**Objective:** Deliver an immediate MVP for automated threat mitigation to stop active beacons while we build more advanced capabilities.

* **Story 1.1:** Develop the `c2_defend.py` daemon to monitor `anomalies.jsonl` or `baseline.db` for detections with a score >= 90.
* **Story 1.2:** Implement surgical process termination using `psutil.Process(pid).kill()`.
* **Story 1.3:** Implement network isolation by injecting dynamic `iptables` or `ufw` rules to blackhole the extracted destination IP.
* **Story 1.4:** Build the `undo.py` utility for safe rollbacks (removing blocklist entries) in the event of a false positive.

### Iteration 2.8.2: Epic 2 - Enterprise Export & Visualization
**Type:** Business Epic

**Objective:** Transition the tool from a standalone script to an enterprise-ready security sensor.

* **Story 2.1:** Build an asynchronous HTTP POST shipper inside `c2_beacon_hunter.py` to forward JSON anomalies directly to an ELK (Elasticsearch/Logstash/Kibana) or Splunk listener.
* **Story 2.2:** Develop a lightweight FastAPI/Flask endpoint that queries `baseline.db` to serve real-time metrics.
* **Story 2.3:** Create a single-page web dashboard displaying live process trees, ML anomaly graphs, and current `c2_defend` blocklists.

### Iteration 2.8.3: Epic 3 - Architectural Enablers (In-Kernel Upgrades)
**Type:** Enabler Epic

**Objective:** Deprecate slow Python dependencies (`scapy`) and shift heavy lifting to the eBPF kernel pipeline to prepare for wire-speed blocking.

* **Story 3.1:** Write a BPF tail-call or direct parser in `c2_probe.bpf.c` to intercept UDP port 53 traffic and extract the queried DNS domain string directly from the packet payload.
* **Story 3.2:** Implement an in-kernel fast Shannon entropy calculator on the first 64 bytes of `tcp_sendmsg` buffers to flag encrypted/obfuscated C2 payloads hiding on standard ports (e.g., 443).
* **Story 3.3:** Update `c2_loader.c` to stream these new DNS strings and payload entropy scores into the Python JSON pipeline.

### Iteration 2.8.4: Epic 4 - The "Holy Grail" (eBPF Enforcement)
**Type:** Architectural Epic

**Objective:** Implement wire-speed, sub-millisecond threat mitigation.

* **Story 4.1:** Utilize the `bpf_send_signal(SIGKILL)` helper in the eBPF probe. If the `tcp_v4_connect` hook detects a process attempting to connect to an IP actively listed in our BPF map blocklist, kill the process instantly.
* **Story 4.2:** Develop an XDP (eXpress Data Path) BPF program attached directly to the network interface card (NIC) driver to drop inbound/outbound packets to flagged IPs before the Linux network stack even allocates memory for them.

### Iteration 2.8.5: IP (Innovation and Planning) Iteration
**Objective:** Buffer for technical debt, integration testing, and documentation.

* Ensure the dual-routing capability (eBPF vs. classic psutil) gracefully handles the new `c2_defend` active response features.
* Finalize deployment documentation (Docker Compose scaling, Systemd service templates).
* Conduct PI Retrospective and prepare backlog for PI 2.9.