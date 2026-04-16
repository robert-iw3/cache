# Purpose: Broad Forensic Sweep for Static Alerts (Sigma, Suricata, JA3, DGA)
# Maps process-level alerts to all active host instances for lineage tracking.
# The "C2Sensor_Alerts.jsonl" is a concise log without context, this bridges that gap during investigations.

$LogPath = "C:\ProgramData\C2Sensor\Logs\C2Sensor_Alerts.jsonl"
$OutFile = "C:\ProgramData\C2Sensor\Logs\C2Sensor_StaticAlert_Context.csv"

if (-not (Test-Path $LogPath)) {
    Write-Host "[!] Log file not found at $LogPath" -ForegroundColor Red
    return
}

Write-Host "[*] Parsing JSONL for Static Detections and Threat Intel..." -ForegroundColor Cyan

$StaticEvents = @()
Get-Content $LogPath | ForEach-Object {
    $event = try { $_ | ConvertFrom-Json } catch { $null }
    if ($null -ne $event -and $event.EventType -in @("ThreatIntel_Match", "Static_Detection")) {
        $StaticEvents += $event
    }
}

if ($StaticEvents.Count -eq 0) {
    Write-Host "[-] No static alerts found to analyze." -ForegroundColor Yellow
    return
}

# Group alerts
$UniqueAlerts = $StaticEvents | Group-Object Image, SuspiciousFlags | Select-Object Name,
    @{Name='ProcessName'; Expression={$_.Group[0].Image}},
    @{Name='EventType'; Expression={$_.Group[0].EventType}},
    @{Name='Signature'; Expression={$_.Group[0].SuspiciousFlags}},
    @{Name='HitCount'; Expression={$_.Group.Count}},
    @{Name='LastSeen'; Expression={$_.Group[-1].Timestamp_Local}}

# === WMI PRE-CACHING PHASE ===
$RequiredNames = $UniqueAlerts.ProcessName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch "(?i)^terminated$" } | Select-Object -Unique

Write-Host "[*] Pre-fetching WMI telemetry to prevent COM hangs..." -ForegroundColor Cyan
$WmiCache = @{}

foreach ($name in $RequiredNames) {
    $cleanName = $name -replace '\.exe$', ''
    # Fetch all WMI data for this process name ONCE
    $wmiInfo = Get-CimInstance Win32_Process -Filter "Name = '$cleanName.exe' OR Name = '$cleanName'" -ErrorAction SilentlyContinue
    $WmiCache[$name] = $wmiInfo
}

Write-Host "[*] Compiling lineage context for $($UniqueAlerts.Count) unique indicators..." -ForegroundColor Cyan
$ConsolidatedData = @()

foreach ($alert in $UniqueAlerts) {
    $procName = $alert.ProcessName

    if ([string]::IsNullOrWhiteSpace($procName) -or $procName -match "(?i)^terminated$") {
        $ConsolidatedData += [PSCustomObject]@{
            Alert_Type      = $alert.EventType
            Triggered_Rule  = $alert.Signature
            Log_ProcessName = if ([string]::IsNullOrWhiteSpace($procName)) { "UNKNOWN_OR_EMPTY" } else { $procName }
            Live_PID        = "N/A"
            CommandLine     = "N/A"
            ParentPID       = "N/A"
            Total_Hits      = $alert.HitCount
            Last_Triggered  = $alert.LastSeen
        }
        continue
    }

    $cleanProcName = $procName -replace '\.exe$', ''
    $activeInstances = Get-Process -Name $cleanProcName -ErrorAction SilentlyContinue

    if ($null -eq $activeInstances -or $activeInstances.Count -eq 0) {
        $ConsolidatedData += [PSCustomObject]@{
            Alert_Type      = $alert.EventType
            Triggered_Rule  = $alert.Signature
            Log_ProcessName = $procName
            Live_PID        = "EXITED"
            CommandLine     = "N/A"
            ParentPID       = "N/A"
            Total_Hits      = $alert.HitCount
            Last_Triggered  = $alert.LastSeen
        }
    } else {
        foreach ($proc in $activeInstances) {
            # Pull from the fast memory cache instead of querying WMI
            $matchedWmi = $null
            if ($WmiCache[$procName]) {
                $matchedWmi = $WmiCache[$procName] | Where-Object { $_.ProcessId -eq $proc.Id }
            }

            $ConsolidatedData += [PSCustomObject]@{
                Alert_Type      = $alert.EventType
                Triggered_Rule  = $alert.Signature
                Log_ProcessName = $procName
                Live_PID        = $proc.Id
                CommandLine     = if ($matchedWmi -and $matchedWmi.CommandLine) { $matchedWmi.CommandLine } else { "ACCESS_DENIED_OR_EMPTY" }
                ParentPID       = if ($matchedWmi -and $matchedWmi.ParentProcessId) { $matchedWmi.ParentProcessId } else { "UNKNOWN" }
                Total_Hits      = $alert.HitCount
                Last_Triggered  = $alert.LastSeen
            }
        }
    }
}

$ConsolidatedData | Sort-Object Alert_Type, Log_ProcessName | Export-Csv -Path $OutFile -NoTypeInformation -Force
Write-Host "[+] Static Alert Forensic Context Exported to: $OutFile" -ForegroundColor Green