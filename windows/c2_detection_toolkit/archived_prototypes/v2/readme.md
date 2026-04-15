# C2 Detection (Anamalous Network Traffic) with PowerShell

## Overview
This tool monitors Windows systems for potential C2 (Command and Control) activities using Sysmon events. It detects anomalies like beaconing, high-entropy domains/IPs, unusual ports, and process behaviors, mapping them to MITRE ATT&CK tactics/techniques. Outputs logs to CSV or JSON for analysis.

## Requirements
- Windows OS with administrative privileges.
- Sysmon installed and configured (use the companion script).
- PowerShell 5.1+.

## Installation
1. Run `InstallSysmonForC2Detection.ps1` as admin to download, install, and configure Sysmon for required events (ProcessCreate, NetworkConnect, etc.).
   - If Sysmon is already installed, it updates the config.
2. (Optional) Create `config.ini` in the script directory for persistent settings. Example:
   ```
   [Anomaly]
   DomainEntropyThreshold=3.8
   VolumeThreshold=60

   [Specifics]
   TLDs=.ru,.cn
   RMMTools=AnyDesk.exe,TeamViewer.exe
   ```

## Usage
Run `MonitorC2Activities.ps1` as admin. It runs indefinitely, polling Sysmon logs every interval.

### Command-Line Parameters
Override defaults/config with params (e.g., `.\MonitorC2Activities.ps1 -OutputPath "C:\Logs\output.json" -Format JSON -SpecificTLDs @('.ru', '.cn')`):
- `-OutputPath`: Output file path (default: C:\Temp\C2Monitoring.csv).
- `-Format`: CSV, JSON, or YAML (default: CSV).
- `-IntervalSeconds`: Polling interval (default: 10).
- `-BeaconWindowMinutes`: Beaconing detection window (default: 60).
- `-MinConnectionsForBeacon`: Min connections for beaconing (default: 3).
- `-MaxIntervalVarianceSeconds`: Max std dev for beaconing (default: 10).
- `-MaxHistoryKeys`: Max tracked endpoints (default: 1000).
- `-VolumeThreshold`: High-volume anomaly threshold (default: 50).
- `-DomainEntropyThreshold`: Domain entropy threshold (default: 3.5).
- `-DomainLengthThreshold`: Domain length threshold (default: 30).
- `-NumericRatioThreshold`: Numeric ratio threshold (default: 0.4).
- `-VowelRatioThreshold`: Vowel ratio threshold (default: 0.2).
- `-IPEntropyThreshold`: IP entropy threshold (default: 3.0).
- `-SpecificTLDs`: Array of TLDs to flag (e.g., @('.ru', '.cn')).
- `-SpecificRMMTools`: Array of RMM tools to flag (e.g., @('AnyDesk.exe')).
- `-SpecificLOLBins`: Array of LOLBins to flag (e.g., @('rundll32.exe')).
- `-SpecificCloudDomains`: Array of cloud domains to flag (e.g., @('amazonaws.com')).

## Output
- Logs all outbound network/DNS events and flagged anomalies.
- Fields include EventType, Timestamp, SuspiciousFlags, ATTCKMappings.
- Appends to the output file; check console for append confirmations.

## Customization
- Edit `config.ini` for defaults without params.
- Adjust thresholds for sensitivity (higher entropy/length = fewer false positives).

## Troubleshooting
- Ensure Sysmon is running (`Get-Service Sysmon*`).
- If no events, verify Sysmon config logs the required IDs.
- Stop with Ctrl+C.