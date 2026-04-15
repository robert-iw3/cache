## Parameters and Config.ini Detailed Descriptions

### Config.ini
---

The `config.ini` file (placed in the same directory as the script) already supports all specific lists, including LOLBins and CloudDomains, under the `[Specifics]` section. The script parses these as comma-separated values and trims them for use. Here's an expanded example of `config.ini` that includes all specifics (TLDs, RMMTools, LOLBins, CloudDomains) along with some anomaly thresholds:

```
[Anomaly]
DomainEntropyThreshold=3.8
DomainLengthThreshold=35
NumericRatioThreshold=0.45
VowelRatioThreshold=0.15
IPEntropyThreshold=3.2
VolumeThreshold=60

[Specifics]
TLDs=.ru,.cn,.top
RMMTools=AnyDesk.exe,TeamViewer.exe
LOLBins=rundll32.exe,regsvr32.exe,mshta.exe
CloudDomains=amazonaws.com,azureedge.net,cloudfront.net
```

- **How it works**: The script checks for `config.ini` at startup and loads these values into variables (e.g., `$SpecificLOLBins`, `$SpecificCloudDomains`). If present, they enable targeted flagging alongside general anomaly detection. Command-line parameters (e.g., `-SpecificLOLBins @('rundll32.exe')`) override config values. If no config or params are provided, these specifics default to empty arrays (no targeted matching, only heuristics).

The script explicitly looks for and parses these in `config.ini` (see the `Read-IniFile` function and override logic in the code). This allows persistent customization without always using command-line args.

### Detailed Parameter Explanations
---

Below is a breakdown of each parameter, including what it controls, its default value, and a brief explanation of concepts like entropy. These can be set via command-line args, `config.ini` (under `[Anomaly]` or `[Specifics]`), or left as defaults. Thresholds tune sensitivity: lower values flag more (risk of false positives), higher values flag less (risk of missing subtle anomalies).

#### Anomaly Detection Thresholds (Heuristic-Based)
These use mathematical/pattern-based checks to detect unusual behavior without relying on known lists, closing gaps for emerging TTPs.

- **DomainEntropyThreshold** (default: 3.5):
  Sets the Shannon entropy limit for domain names (e.g., in hostnames or DNS queries). Entropy measures randomness/unpredictability in a string (e.g., "google.com" has low entropy ~2.5 due to readable patterns; DGA-generated like "xjf83j4f.com" has high ~3.8+). Values above this threshold flag as anomalous (potential DGA/C2). Adjust higher (e.g., 4.0) for fewer alerts in noisy environments.

- **DomainLengthThreshold** (default: 30):
  Maximum length for domain names before flagging as anomalous. Long domains (e.g., >30 chars) often indicate DGA or obfuscation. Lower for stricter checks on shorter suspicious domains.

- **NumericRatioThreshold** (default: 0.4):
  Ratio of numeric characters (0-9) in a domain/IP string. If > this value (e.g., 40% digits), flags as anomalous (common in random/DGA strings like "192837.com"). IPs are numeric by nature, but this helps detect malformed or obfuscated ones.

- **VowelRatioThreshold** (default: 0.2):
  Minimum ratio of vowels (a,e,i,o,u) in a domain. Below this (e.g., <20% vowels), flags as anomalous (DGA domains often lack natural language patterns). Higher values make it less sensitive to consonant-heavy legit domains.

- **IPEntropyThreshold** (default: 3.0):
  Shannon entropy limit for IP addresses. IPs like "192.168.1.1" have low entropy (~2.0); random/high-entropy IPs (e.g., "47.92.183.56" if unusually varied) flag above this, indicating potential fast-flux or obfuscated C2. Similar to domain entropy but tuned for numeric/dot strings.

- **VolumeThreshold** (default: 50):
  Maximum connections to a single endpoint (IP/hostname:port) in the beacon window before flagging high-volume anomaly (potential exfil or DDoS-like C2). Tracks in-memory; adjust based on normal traffic (e.g., 100 for busy servers).

#### Beaconing Detection Parameters
These control frequency-based C2 detection (regular "phone home" patterns).

- **BeaconWindowMinutes** (default: 60):
  Time window (in minutes) to analyze connection intervals for beaconing. Longer windows detect slow beacons; shorter for real-time.

- **MinConnectionsForBeacon** (default: 3):
  Minimum connections to an endpoint needed to check for beaconing. Prevents flagging sporadic traffic.

- **MaxIntervalVarianceSeconds** (default: 10):
  Maximum standard deviation (in seconds) of connection intervals. Low variance (below this) flags beaconing (e.g., every 60s ±<10s variance indicates regular C2 check-ins).

#### General Parameters
- **OutputPath** (default: C:\Temp\C2Monitoring.csv):
  File path for logs. Appends events with flags/mappings.

- **Format** (default: CSV):
  Output format (CSV, JSON, YAML). YAML requires `powershell-yaml` module.

- **IntervalSeconds** (default: 10):
  How often (in seconds) to poll Sysmon logs. Lower for near-real-time; higher for less CPU.

- **MaxHistoryKeys** (default: 1000):
  Maximum endpoints tracked in memory (to prevent growth). Prunes oldest if exceeded.

#### Specific Matching Parameters (Threat Intel-Based)
These optional lists enable targeted flagging based on known indicators (e.g., from threat intel). Use comma-separated in config.ini or arrays in params. Empty by default (relies on heuristics).

- **SpecificTLDs** (default: @()):
  Array of top-level domains (e.g., '.ru', '.cn') to specifically flag if matched in domains/DNS. Adds "Specific TLD Match" flag.

- **SpecificRMMTools** (default: @()):
  Array of RMM tool executables (e.g., 'AnyDesk.exe') to flag in processes. Adds "Specific RMM Tool Match" for potential abuse.

- **SpecificLOLBins** (default: @()):
  Array of living-off-the-land binaries (e.g., 'rundll32.exe') to flag in processes. Adds "Specific LOLBin Match" for evasion tactics.

- **SpecificCloudDomains** (default: @()):
  Array of cloud provider domains (e.g., 'amazonaws.com') to flag in connections. Adds "Specific Cloud Domain Match" for cloud-based C2.