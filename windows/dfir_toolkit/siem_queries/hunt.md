### The "Pipeline Overview" (Artifact Census)
Before hunting, you need a dashboard widget that proves the middleware is successfully routing data and shows exactly how many artifacts have been collected per host.

**Elastic (ES|QL)**
```esql
FROM dfir*
// Group by the host and the type of JSON artifact
| STATS ArtifactCount = COUNT() BY agent.hostname, event.dataset
| SORT ArtifactCount DESC
| LIMIT 100
```

**Datadog (Log Explorer Syntax)**
```text
source:dfir_collector
```
* **UI Action:** In the Datadog Log Explorer, click **"Top List"** next to the search bar. Group by `host` and `artifact` to instantly generate a breakdown of all ingested DFIR telemetry.

### 1. Programmatic C2 Beaconing (Coefficient of Variation < 0.35)
This query calculates the time delta between connections to the same external IP, derives the Mean and Standard Deviation, and calculates the CV to identify programmatic jitter.

**Microsoft Sentinel (KQL)**
```kusto
EndpointDFIR_CL
| where DFIR_Artifact == "ActiveNetworkConnections"
// Expand the TCP array from the JSON payload
| mv-expand TCP = todynamic(data).TCP
| extend RemoteAddress = tostring(TCP.RemoteAddress), CreationTime = todatetime(TCP.CreationTime)
// Filter out local/internal noise
| where RemoteAddress !startswith "10." and RemoteAddress !startswith "192.168." and RemoteAddress !startswith "127."
| sort by RemoteAddress, CreationTime asc
| serialize
// Calculate the time difference between the current connection and the previous one
| extend TimeDelta = datetime_diff('second', CreationTime, prev(CreationTime))
| extend PrevAddress = prev(RemoteAddress)
| where RemoteAddress == PrevAddress
// Aggregate the math per target IP and Host
| summarize MeanDelta = avg(TimeDelta), StdDevDelta = stdev(TimeDelta), ConnectionCount = count() by RemoteAddress, DFIR_Host
| where ConnectionCount >= 4
// Calculate Coefficient of Variation (CV)
| extend CV = StdDevDelta / MeanDelta
// Filter for programmatic rhythm (CV < 0.35) and exclude rapid-fire bursts (Mean > 1s)
| where CV < 0.35 and MeanDelta > 1.0
| project DFIR_Host, RemoteAddress, ConnectionCount, MeanDelta, StdDevDelta, CV
| sort by CV asc
```

**Splunk (SPL)**
```splunk
index=* sourcetype="dfir:ActiveNetworkConnections"
| spath input=event path=TCP{} output=tcp_connections
| mvexpand tcp_connections
| spath input=tcp_connections
| search RemoteAddress!="10.*" RemoteAddress!="192.168.*" RemoteAddress!="127.*"
| eval conn_time = strptime(CreationTime, "%Y-%m-%dT%H:%M:%S.%NZ")
| sort 0 RemoteAddress, conn_time
| streamstats current=f window=1 global=f last(conn_time) as PrevTime by RemoteAddress, host
| eval Delta = conn_time - PrevTime
| where isnotnull(Delta)
| stats count as ConnectionCount, avg(Delta) as MeanDelta, stdev(Delta) as StdDevDelta by RemoteAddress, host
| where ConnectionCount >= 4
| eval CV = StdDevDelta / MeanDelta
| where CV < 0.35 AND MeanDelta > 1.0
| table host, RemoteAddress, ConnectionCount, MeanDelta, StdDevDelta, CV
| sort CV
```

**Elastic (ES|QL)**
```esql
FROM dfir*
| WHERE event.dataset == "ActiveNetworkConnections"
| KEEP @timestamp, agent.hostname, forensics.TCP.RemoteAddress, forensics.TCP.OwningProcess
// Filter out local subnets
| WHERE forensics.TCP.RemoteAddress NOT LIKE "10.*"
  AND forensics.TCP.RemoteAddress NOT LIKE "192.168.*"
  AND forensics.TCP.RemoteAddress NOT LIKE "127.*"
// Group connections by the external IP
| STATS ConnectionCount = COUNT() BY agent.hostname, forensics.TCP.RemoteAddress
| WHERE ConnectionCount >= 10
| SORT ConnectionCount DESC
```

**Datadog (Dashboard Configuration)**
1. Create a **Timeseries Widget**.
2. Query: `source:dfir_collector artifact:ActiveNetworkConnections -@message.TCP.RemoteAddress:(10.* OR 192.168.* OR 127.*)`
3. Group by: `@message.TCP.RemoteAddress`
4. Set the display to **Bars** and apply the **Anomaly Detection** algorithm in the Datadog UI. Datadog's native ML will automatically highlight the programmatic rhythms and low-variance jitter that our PowerShell CV math was looking for locally.

---

### 2. Anomalous Process Lineage (Web Shells & SQL Exploits)
Threat actors frequently leverage compromised IIS (`w3wp.exe`) or SQL Server (`sqlservr.exe`) instances to spawn command shells using native environment variables. This query performs a self-join on the process tree to map children back to highly vulnerable parent processes.

**Microsoft Sentinel (KQL)**
```kusto
let ProcessData = EndpointDFIR_CL
    | where DFIR_Artifact == "ProcessTree"
    | extend ProcessId = tostring(data.ProcessId), ParentProcessId = tostring(data.ParentProcessId), Name = tostring(data.Name), ExecPath = tostring(data.ExecutablePath);
ProcessData
| project DFIR_Host, ProcessId, ParentProcessId, Name, ExecPath
// Self-join to map the parent process ID to its actual executable name
| join kind=inner (
    ProcessData
    | project DFIR_Host, ParentId = ProcessId, ParentName = Name
) on $left.ParentProcessId == $right.ParentId and $left.DFIR_Host == $right.DFIR_Host
// Define the vulnerable infrastructure targets
| where ParentName matches regex @"(?i)^(w3wp\.exe|sqlservr\.exe|winword\.exe|excel\.exe|httpd\.exe)$"
// Define the suspicious shell spawns
| where Name matches regex @"(?i)^(cmd\.exe|powershell\.exe|pwsh\.exe|rundll32\.exe|bash\.exe)$"
| project DFIR_Host, ParentName, ParentProcessId, SuspiciousChild = Name, ProcessId, ExecPath
```

**Splunk (SPL)**
```splunk
index=* sourcetype="dfir:ProcessTree"
| spath input=event output=ProcessId path=ProcessId
| spath input=event output=ParentProcessId path=ParentProcessId
| spath input=event output=Name path=Name
| spath input=event output=CommandLine path=CommandLine
| rename Name as ChildProcess
| eval join_id = host + "_" + ParentProcessId
| join type=inner join_id [
    search index=* sourcetype="dfir:ProcessTree"
    | spath input=event output=ProcessId path=ProcessId
    | spath input=event output=Name path=Name
    | eval join_id = host + "_" + ProcessId
    | rename Name as ParentProcess
    | fields join_id, ParentProcess
]
| regex ParentProcess="(?i)^(w3wp\.exe|sqlservr\.exe|winword\.exe|excel\.exe)$"
| regex ChildProcess="(?i)^(cmd\.exe|powershell\.exe|pwsh\.exe|rundll32\.exe)$"
| table host, ParentProcess, ParentProcessId, ChildProcess, ProcessId, CommandLine
```

**Elastic (ES|QL)**
*Note: Because ES|QL handles row-by-row streaming, we filter for the known malicious child processes and extract the command lines.*
```esql
FROM dfir*
| WHERE event.dataset == "ProcessTree"
// Target shells commonly spawned by compromised IIS (w3wp.exe) or SQL (sqlservr.exe)
| WHERE forensics.Name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "bash.exe")
| KEEP @timestamp, agent.hostname, forensics.ProcessId, forensics.ParentProcessId, forensics.Name, forensics.CommandLine, forensics.ExecutablePath
// Flag highly suspicious execution paths
| WHERE forensics.ExecutablePath RLIKE "(?i).*(\\\\Temp\\\\|\\\\ProgramData\\\\|\\\\Users\\\\Public\\\\).*"
   OR forensics.CommandLine RLIKE "(?i).*(-enc|-encodedcommand|-nop|bypass|downloadstring|invoke-webrequest).*"
| SORT @timestamp DESC
```

**Datadog (Log Explorer Syntax)**
```text
source:dfir_collector artifact:ProcessTree @message.Name:(cmd.exe OR powershell.exe OR pwsh.exe OR rundll32.exe)
(@message.ExecutablePath:(*\\Temp\\* OR *\\ProgramData\\* OR *\\Users\\Public\\*) OR @message.CommandLine:(*-enc* OR *-encodedcommand* OR *bypass* OR *downloadstring*))
```

---

### 3. Critical Event Log Triage (Defense Evasion & RMM Abuse)
This query directly parses the targeted high-fidelity logs we pulled in Phase 5 of the collector. It specifically looks for audit destruction and the installation of persistence/RMM services.

**Microsoft Sentinel (KQL)**
```kusto
EndpointDFIR_CL
| where DFIR_Artifact == "CriticalEventLogs"
| extend EventId = toint(data.Id), Message = tostring(data.Message), Provider = tostring(data.ProviderName), TimeCreated = todatetime(data.TimeCreated)
| where EventId in (1102, 104, 7045, 4104)
| extend ThreatCategory = case(
    EventId in (1102, 104), "Defense Evasion: Logs Cleared",
    EventId == 7045 and Message matches regex @"(?i)(PSEXESVC|Metasploit|Cobalt|Bypass|AnyDesk|Atera)", "PrivEsc: Malicious Service/RMM",
    EventId == 4104 and Message matches regex @"(?i)(VirtualAlloc|AmsiScanBuffer|MiniDumpWriteDump)", "Execution: Malicious Script Block",
    "Review Required"
)
| where ThreatCategory != "Review Required"
| project TimeCreated, DFIR_Host, ThreatCategory, EventId, Provider, Message
| sort by TimeCreated desc
```

**Splunk (SPL)**
```splunk
index=* sourcetype="dfir:CriticalEventLogs"
| spath input=event output=EventId path=Id
| spath input=event output=Message path=Message
| spath input=event output=Provider path=ProviderName
| search EventId IN (1102, 104, 7045, 4104)
| eval ThreatCategory=case(
    EventId==1102 OR EventId==104, "Defense Evasion: Logs Cleared",
    EventId==7045 AND match(Message, "(?i)(PSEXESVC|Metasploit|Cobalt|AnyDesk|Atera)"), "PrivEsc: Malicious Service/RMM",
    EventId==4104 AND match(Message, "(?i)(VirtualAlloc|AmsiScanBuffer|MiniDumpWriteDump)"), "Execution: Malicious Script Block",
    true(), "null"
)
| search ThreatCategory!="null"
| table _time, host, ThreatCategory, EventId, Provider, Message
```

**Elastic (ES|QL)**
```esql
FROM dfir*
| WHERE event.dataset == "CriticalEventLogs"
| KEEP @timestamp, agent.hostname, forensics.Id, forensics.ProviderName, forensics.Message
| WHERE forensics.Id IN (1102, 104, 7045, 4104)
// Use CASE to dynamically tag the events with our DFIR heuristic severities
| EVAL ThreatCategory = CASE(
    forensics.Id IN (1102, 104), "Defense Evasion: Logs Cleared",
    forensics.Id == 7045 AND forensics.Message RLIKE "(?i).*(PSEXESVC|Metasploit|Cobalt|AnyDesk|Atera).*", "PrivEsc: Malicious Service/RMM",
    forensics.Id == 4104 AND forensics.Message RLIKE "(?i).*(VirtualAlloc|AmsiScanBuffer|MiniDumpWriteDump).*", "Execution: Malicious Script Block",
    "Review Required"
  )
| WHERE ThreatCategory != "Review Required"
| SORT @timestamp DESC
```

**Datadog (Log Explorer Syntax)**
```text
source:dfir_collector artifact:CriticalEventLogs @message.Id:(1102 OR 104 OR 7045 OR 4104)
(@message.Message:(*PSEXESVC* OR *Metasploit* OR *Cobalt* OR *AnyDesk* OR *VirtualAlloc* OR *AmsiScanBuffer* OR *MiniDumpWriteDump*) OR @message.Id:(1102 OR 104))
```
* **UI Action:** Add a custom column in the Datadog log view for `@message.Id` and `@message.Message` to quickly triage the findings without opening the JSON payloads.