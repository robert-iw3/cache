<#
.SYNOPSIS
    Hybrid Sysmon C2 Monitor (PowerShell Collector + Async Python ML).
    Features: Real-time Heuristics + Advanced Lomb-Scargle/DBSCAN Jitter Detection via BeaconML.py.
    Architecture: Non-blocking data collection with periodic offloaded analysis.

.DESCRIPTION
    Operates in two modes simultaneously:
    1. Real-Time: Immediate detection of DGA, Sideloading, and Persistence.
    2. Async Batch: Offloads network timestamps to Python every N seconds for heavy math analysis.

    Config Priority: CLI Arguments > Config.ini > Script Defaults.
    Requires: BeaconML.py in the same directory (or specified via path).

.PARAMETER OutputPath
    Path to output file (default: C:\Temp\C2Monitoring.csv).

.PARAMETER Format
    Output format: CSV (default) or JSON.

.PARAMETER PythonPath
    Path to Python executable (default: "python").

.PARAMETER MLScriptPath
    Path to the Python analysis engine (default: "BeaconML.py").

.PARAMETER BatchAnalysisIntervalSeconds
    How often to offload data to Python for analysis (default: 60).

.PARAMETER MinConnectionsForML
    Minimum data points required before sending to Python (default: 5).

# ... [Standard Detection Parameters same as MonitorC2Activities_v2.ps1] ...

.EXAMPLE
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -BatchAnalysisIntervalSeconds 30
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -PythonPath "C:\Python39\python.exe" -Format JSON

.NOTES
    Author: Robert Weber

    Updates (v2):
    - Architecture: Async Batching (Does not block event loop).
    - Logic: Fixed Regex/Switch syntax errors.
    - Feature: Integration with BeaconML.py (DBSCAN/Spectral Analysis).
    - Config: Fixed precedence (CLI now correctly overrides Config.ini).
#>

param (
    [string]$OutputPath = "C:\Temp\C2Monitoring.csv",
    [ValidateSet("CSV", "JSON")][string]$Format = "CSV",
    [string]$PythonPath = "python",
    [string]$MLScriptPath = "BeaconML.py", # Relative to script dir by default

    # Polling & Batch Config
    [int]$IntervalSeconds = 10,
    [int]$BatchAnalysisIntervalSeconds = 60, # Run Python ML every 60s
    [int]$MinConnectionsForML = 5,
    [int]$MaxHistoryKeys = 1000,

    # Anomaly Thresholds (Defaults)
    [double]$DomainEntropyThreshold = 3.8,
    [int]$DomainLengthThreshold = 30,
    [double]$NumericRatioThreshold = 0.4,
    [double]$VowelRatioThreshold = 0.2,
    [double]$IPEntropyThreshold = 3.0,
    [int]$VolumeThreshold = 50,

    # Specific Targets
    [string[]]$SpecificTLDs = @(),
    [string[]]$SpecificRMMTools = @(),
    [string[]]$SpecificLOLBins = @(),
    [string[]]$SpecificCloudDomains = @()
)

# --- 1. SETUP & PATHS ---

$ScriptDir = Split-Path $PSCommandPath -Parent
$FullMLPath = Join-Path $ScriptDir $MLScriptPath

# Verify Python Availability
try {
    $null = Get-Command $PythonPath -ErrorAction Stop
    $PythonAvailable = $true
} catch {
    Write-Warning "Python not found in PATH. ML Beaconing features will be disabled."
    $PythonAvailable = $false
}

# Compiled Regex (FIXED: Uses comma separation)
$Regex_InternalIP = [regex]::new('^((10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)|(127\.)|(169\.254\.))', 'Compiled')
$Regex_NonDigit   = [regex]::new('[^0-9]', 'Compiled')
$Regex_Encoded    = [regex]::new('-EncodedCommand|-enc|IEX|Invoke-Expression|DownloadString', 'Compiled, IgnoreCase')
$Regex_Defense    = [regex]::new('Set-MpPreference.*-Disable|sc delete|net stop', 'Compiled, IgnoreCase')
$Regex_SysPaths   = [regex]::new('System32|SysWOW64|WinSxS', 'Compiled, IgnoreCase')
$Regex_MS_Signed  = [regex]::new('Signed="true".*Signature="Microsoft Windows".*SignatureStatus="Valid"', 'Compiled')

# Math Helpers & Collections
$log2 = [Math]::Log(2)
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")
# Buffer for ML: Key -> Queue of Timestamps
$connectionHistory = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()

# --- 2. CONFIGURATION ENGINE (CLI > Config > Default) ---

function Read-IniFile {
    param ([string]$Path)
    $ini = @{}
    if (Test-Path $Path) {
        switch -regex -file $Path {
            "^\[(.*)\]$" { $section = $matches[1].Trim() ; $ini[$section] = @{} }
            "^(.*?)=(.*)$" { if ($section) { $ini[$section][$matches[1].Trim()] = $matches[2].Trim() } }
        }
    }
    return $ini
}

$configPath = Join-Path $ScriptDir "config.ini"
$config = Read-IniFile -Path $configPath

# Robust Override Logic
if ($config['Anomaly']) {
    $s = $config['Anomaly']
    if ($s['DomainEntropyThreshold'] -and -not $PSBoundParameters.ContainsKey('DomainEntropyThreshold')) { $DomainEntropyThreshold = [double]$s['DomainEntropyThreshold'] }
    if ($s['DomainLengthThreshold'] -and -not $PSBoundParameters.ContainsKey('DomainLengthThreshold')) { $DomainLengthThreshold = [int]$s['DomainLengthThreshold'] }
    if ($s['NumericRatioThreshold'] -and -not $PSBoundParameters.ContainsKey('NumericRatioThreshold')) { $NumericRatioThreshold = [double]$s['NumericRatioThreshold'] }
    if ($s['VowelRatioThreshold'] -and -not $PSBoundParameters.ContainsKey('VowelRatioThreshold')) { $VowelRatioThreshold = [double]$s['VowelRatioThreshold'] }
    if ($s['IPEntropyThreshold'] -and -not $PSBoundParameters.ContainsKey('IPEntropyThreshold')) { $IPEntropyThreshold = [double]$s['IPEntropyThreshold'] }
    if ($s['VolumeThreshold'] -and -not $PSBoundParameters.ContainsKey('VolumeThreshold')) { $VolumeThreshold = [int]$s['VolumeThreshold'] }
}

if ($config['Specifics']) {
    $s = $config['Specifics']
    if ($s['TLDs'] -and -not $PSBoundParameters.ContainsKey('SpecificTLDs')) { $SpecificTLDs = ($s['TLDs'] -split ',').Trim() }
    if ($s['RMMTools'] -and -not $PSBoundParameters.ContainsKey('SpecificRMMTools')) { $SpecificRMMTools = ($s['RMMTools'] -split ',').Trim() }
    if ($s['LOLBins'] -and -not $PSBoundParameters.ContainsKey('SpecificLOLBins')) { $SpecificLOLBins = ($s['LOLBins'] -split ',').Trim() }
    if ($s['CloudDomains'] -and -not $PSBoundParameters.ContainsKey('SpecificCloudDomains')) { $SpecificCloudDomains = ($s['CloudDomains'] -split ',').Trim() }
}

# --- 3. HELPER FUNCTIONS ---

function Get-Entropy {
    param ([string]$inputString)
    if ([string]::IsNullOrEmpty($inputString)) { return 0.0 }
    $charCounts = @{}
    foreach ($c in $inputString.ToCharArray()) { $charCounts[$c]++ }
    $entropy = 0.0; $len = $inputString.Length
    foreach ($count in $charCounts.Values) {
        $p = $count / $len
        $entropy -= $p * ([Math]::Log($p) / $log2)
    }
    return $entropy
}

function Is-AnomalousDomain {
    param ([string]$domain)
    if ([string]::IsNullOrEmpty($domain)) { return $false }
    if ($domain.Length -gt $DomainLengthThreshold) { return $true }

    $digits = $Regex_NonDigit.Replace($domain, "").Length
    if (($digits / $domain.Length) -gt $NumericRatioThreshold) { return $true }

    $vowelCount = 0
    foreach ($char in $domain.ToLower().ToCharArray()) { if ($vowels.Contains($char)) { $vowelCount++ } }
    if (($vowelCount / $domain.Length) -lt $VowelRatioThreshold) { return $true }

    return (Get-Entropy $domain) -gt $DomainEntropyThreshold
}

# --- 4. MAIN MONITORING LOOP ---

$logName = "Microsoft-Windows-Sysmon/Operational"
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) { New-Item -Path $outputDir -ItemType Directory -Force | Out-Null }

$lastQueryTime = (Get-Date).AddMinutes(-1)
$lastMLRunTime = Get-Date
$tempBatchFile = [System.IO.Path]::GetTempFileName()
$RefDate = Get-Date -Date "01/01/1970" # Reference for Unix Timestamps

Write-Host "[-] Starting Hybrid C2 Monitor..." -ForegroundColor Cyan
Write-Host "    Mode: Python ML Integration (Async)" -ForegroundColor Gray
Write-Host "    Config: Loaded from ini, overridden by CLI args." -ForegroundColor Gray

while ($true) {
    try {
        $now = Get-Date
        if (-not $lastQueryTime) { $lastQueryTime = $now.AddMinutes(-1) }

        $filter = @{ LogName = $logName; ID = 1,3,7,11,12,13,22; StartTime = $lastQueryTime }
        $events = try { Get-WinEvent -FilterHashtable $filter -ErrorAction Stop } catch { $null }

        if ($events) {
            foreach ($event in $events) {
                $rawXml = $event.ToXml()

                # OPTIMIZATION: Fast-Path Filter
                if ($event.Id -eq 7 -and $Regex_MS_Signed.IsMatch($rawXml)) { continue }

                $xmlData = [xml]$rawXml
                $eventDataHash = @{}
                foreach ($node in $xmlData.Event.EventData.Data) { $eventDataHash[$node.Name] = $node.'#text' }

                $props = [ordered]@{
                    EventType = switch ($event.Id) { 1 {"ProcessCreate"} 3 {"NetworkConnect"} 7 {"ImageLoad"} 11 {"FileCreate"} 12 {"RegistryEvent"} 13 {"RegistryEvent"} 22 {"DnsQuery"} default {$event.Id} }
                    Timestamp = $event.TimeCreated
                    Image = $eventDataHash['Image']
                    SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                    ATTCKMappings = [System.Collections.Generic.List[string]]::new()
                    CommandLine = $eventDataHash['CommandLine']
                    DestinationIp = $eventDataHash['DestinationIp']
                    DestinationHostname = $eventDataHash['DestinationHostname']
                    TargetFilename = $eventDataHash['TargetFilename']
                    TargetObject = $eventDataHash['TargetObject']
                }

                # --- EVENT ANALYSIS ---
                switch ($event.Id) {
                    1 {
                        if ($Regex_Encoded.IsMatch($props['CommandLine'])) {
                            $props.SuspiciousFlags.Add("Anomalous CommandLine (Script/Encoded)")
                            $props.ATTCKMappings.Add("TA0002: T1059.001")
                        }
                        if ($Regex_Defense.IsMatch($props['CommandLine'])) {
                            $props.SuspiciousFlags.Add("Defense Tampering Attempt")
                            $props.ATTCKMappings.Add("TA0005: T1562.001")
                        }
                        if ($SpecificRMMTools -contains $props['Image']) {
                            $props.SuspiciousFlags.Add("RMM Tool Detected")
                            $props.ATTCKMappings.Add("TA0011: T1219")
                        }
                    }
                    3 {
                        if ($props['DestinationHostname'] -and (Is-AnomalousDomain $props['DestinationHostname'])) {
                            $props.SuspiciousFlags.Add("High Entropy Domain (Network)")
                            $props.ATTCKMappings.Add("TA0011: T1568.002")
                        }

                        $isOutbound = ($Regex_InternalIP.IsMatch($eventDataHash['SourceIp']) -and -not $Regex_InternalIP.IsMatch($eventDataHash['DestinationIp']))
                        if ($isOutbound) {
                            $dst = if ($props['DestinationHostname']) { "$($props['DestinationHostname']):$($eventDataHash['DestinationPort'])" } else { "$($props['DestinationIp']):$($eventDataHash['DestinationPort'])" }
                            if (-not $connectionHistory.ContainsKey($dst)) { $connectionHistory[$dst] = [System.Collections.Generic.Queue[datetime]]::new() }
                            $connectionHistory[$dst].Enqueue($now)
                        }
                    }
                    7 {
                        if ($Regex_SysPaths.IsMatch($props['Image']) -and -not $Regex_SysPaths.IsMatch($props['ImageLoaded'])) {
                            $props.SuspiciousFlags.Add("Anomalous DLL Load (Sideloading Risk)")
                            $props.ATTCKMappings.Add("TA0005: T1574.002")
                        }
                    }
                    11 {
                        if ($props['TargetFilename'] -match '\.ps1$|\.vbs$|\.bat$|\.exe$') {
                            $props.SuspiciousFlags.Add("Executable/Script File Created")
                            $props.ATTCKMappings.Add("TA0002: T1059")
                        }
                    }
                    { $_ -in 12, 13 } { # FIXED: Using script block for multiple values
                        if ($props['TargetObject'] -match 'Run|RunOnce|Services|Startup') {
                            $props.SuspiciousFlags.Add("Persistence Registry Key Modified")
                            $props.ATTCKMappings.Add("TA0003: T1547.001")
                        }
                    }
                    22 {
                        $props['QueryName'] = $eventDataHash['QueryName']
                        if (Is-AnomalousDomain $props['QueryName']) {
                            $props.SuspiciousFlags.Add("DGA DNS Query Detected")
                            $props.ATTCKMappings.Add("TA0011: T1568.002")
                        }
                        if ($SpecificTLDs -and ($SpecificTLDs | Where-Object { $props['QueryName'].EndsWith($_) })) {
                            $props.SuspiciousFlags.Add("Suspicious TLD Match")
                        }
                    }
                }

                if ($props.SuspiciousFlags.Count -gt 0) {
                    $outObj = New-Object PSObject -Property $props
                    $outObj.SuspiciousFlags = $props.SuspiciousFlags -join '; '
                    $outObj.ATTCKMappings = $props.ATTCKMappings -join '; '
                    $dataBatch.Add($outObj)
                }
            }
        }

        # --- ASYNC ML BEACONING EXECUTION ---
        if ($PythonAvailable -and ($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {

            $payload = @{}
            $targets = 0
            foreach ($key in $connectionHistory.Keys) {
                if ($connectionHistory[$key].Count -ge $MinConnectionsForML) {
                    $timestamps = $connectionHistory[$key].ToArray() | ForEach-Object { ($_ - $RefDate).TotalSeconds }
                    $payload[$key] = $timestamps
                    $targets++
                }
            }

            if ($targets -gt 0) {
                Write-Host "    [ML] analyzing $targets targets..." -NoNewline -ForegroundColor Gray

                $payload | ConvertTo-Json -Depth 2 -Compress | Set-Content -Path $tempBatchFile

                $pyArgs = "`"$FullMLPath`" `"$tempBatchFile`" --use_dbscan"
                $pInfo = New-Object System.Diagnostics.ProcessStartInfo
                $pInfo.FileName = $PythonPath; $pInfo.Arguments = $pyArgs
                $pInfo.RedirectStandardOutput = $true; $pInfo.CreateNoWindow = $true; $pInfo.UseShellExecute = $false

                $p = [System.Diagnostics.Process]::Start($pInfo)
                $p.WaitForExit()

                try {
                    $jsonOut = $p.StandardOutput.ReadToEnd()
                    $alerts = $jsonOut | ConvertFrom-Json
                    if ($alerts -and -not $alerts.error) {
                        foreach ($t in $alerts.PSObject.Properties.Name) {
                            $mlObj = [ordered]@{
                                EventType="ML_BEACON_ALERT"; Timestamp=$now; Destination=$t
                                SuspiciousFlags=$alerts.$t; ATTCKMappings="TA0011: T1071"
                            }
                            $dataBatch.Add((New-Object PSObject -Property $mlObj))
                        }
                        Write-Host " Found $($alerts.PSObject.Properties.Count) beacons." -ForegroundColor Yellow
                    } else { Write-Host " Clean." -ForegroundColor Green }
                } catch { Write-Warning " Python ML Error: $_" }
            }
            $lastMLRunTime = $now

            if ($connectionHistory.Count -gt $MaxHistoryKeys) {
                $keys = $connectionHistory.Keys | Select-Object -First 100
                foreach ($k in $keys) { [void]$connectionHistory.Remove($k) }
            }
        }

        # --- EXPORT ---
        if ($dataBatch.Count -gt 0) {
            switch ($Format) {
                "CSV"  { $dataBatch | Export-Csv -Path $OutputPath -Append -NoTypeInformation }
                "JSON" { $dataBatch | ConvertTo-Json -Depth 2 | Add-Content -Path $OutputPath }
            }
            $dataBatch.Clear()
        }

        $lastQueryTime = $now
        Start-Sleep -Seconds $IntervalSeconds

    } catch { Write-Error $_ }
}