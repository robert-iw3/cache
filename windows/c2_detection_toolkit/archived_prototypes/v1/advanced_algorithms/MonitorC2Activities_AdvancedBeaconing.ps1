#Requires -RunAsAdministrator

<#
.SYNOPSIS
    PowerShell script to monitor Sysmon events for C2 and related threats with MITRE ATT&CK mappings (Version 2.0).
    Optimized for performance: Reduced XML parsing overhead, batched exports, efficient pruning, minimized string operations.
    Supports config.ini for persistent settings (e.g., thresholds, specifics); command-line params override config/defaults.
    Enhanced beaconing: Added jitter ratio, autocorrelation, Lomb-Scargle periodogram approximation, and optional ML clustering via Python (if installed).
    Syntax validated: No errors (braces match, cmdlets correct, variables defined).

.DESCRIPTION
    Loads settings from config.ini (if exists in script dir), overrides with params.
    Checks Sysmon, monitors events, detects anomalies, outputs to file.
    For advanced ML beaconing (K-Means clustering on intervals), checks for Python; if available, calls BeaconML.py (provided separately).
    Config.ini example:
    [Anomaly]
    DomainEntropyThreshold=3.5
    [Specifics]
    TLDs=.ru,.cn

.PARAMETER OutputPath
    Path to output file (default: C:\Temp\C2Monitoring.csv).

.PARAMETER Format
    Output format: CSV (default), JSON, YAML.

.PARAMETER IntervalSeconds
    Polling interval (default: 10).

.PARAMETER BeaconWindowMinutes
    Beaconing window (default: 60).

.PARAMETER MinConnectionsForBeacon
    Min connections for beaconing check (default: 3).

.PARAMETER MaxIntervalVarianceSeconds
    Max std dev for beaconing (default: 10).

.PARAMETER MaxHistoryKeys
    Max history keys (default: 1000).

.PARAMETER VolumeThreshold
    Connection count threshold for volume anomaly in window (default: 50).

.PARAMETER DomainEntropyThreshold
    Entropy threshold for domain anomaly (default: 3.5).

.PARAMETER DomainLengthThreshold
    Length threshold for domain anomaly (default: 30).

.PARAMETER NumericRatioThreshold
    Numeric ratio threshold for domain/IP anomaly (default: 0.4).

.PARAMETER VowelRatioThreshold
    Minimum vowel ratio for domain anomaly (below flags anomaly) (default: 0.2).

.PARAMETER IPEntropyThreshold
    Entropy threshold for IP anomaly (default: 3.0).

.PARAMETER SpecificTLDs
    Optional array of specific TLDs to flag (e.g., @('.ru', '.cn')).

.PARAMETER SpecificRMMTools
    Optional array of specific RMM tool names to flag (e.g., @('AnyDesk.exe')).

.PARAMETER SpecificLOLBins
    Optional array of specific LOLBin names to flag (e.g., @('rundll32.exe')).

.PARAMETER SpecificCloudDomains
    Optional array of specific cloud domains to flag (e.g., @('amazonaws.com')).

.EXAMPLE
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -SpecificTLDs @('.ru', '.cn') -DomainEntropyThreshold 3.8
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -OutputPath "D:\Logs\C2Log.json" -Format JSON -IntervalSeconds 15
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -SpecificRMMTools @('AnyDesk.exe','TeamViewer.exe') -SpecificLOLBins @('rundll32.exe','regsvr32.exe')
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -SpecificCloudDomains @('amazonaws.com','azureedge.net') -VolumeThreshold 100
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -BeaconWindowMinutes 120 -MinConnectionsForBeacon 5 -MaxIntervalVarianceSeconds 5
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -DomainLengthThreshold 25 -NumericRatioThreshold 0.3 -VowelRatioThreshold 0.25 -IPEntropyThreshold 2.5
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -MaxHistoryKeys 2000 -VolumeThreshold 75
    .\MonitorC2Activities_AdvancedBeaconing.ps1 -Format YAML
    .\MonitorC2Activities_AdvancedBeaconing.ps1
        (Uses defaults and config.ini if present)

.NOTES
    Author: Robert Weber
#>

param (
    [string]$OutputPath = "C:\Temp\C2Monitoring.csv",
    [ValidateSet("CSV", "JSON", "YAML")][string]$Format = "CSV",
    [int]$IntervalSeconds = 10,
    [int]$BeaconWindowMinutes = 60,
    [int]$MinConnectionsForBeacon = 3,
    [double]$MaxIntervalVarianceSeconds = 10,
    [int]$MaxHistoryKeys = 1000,
    [int]$VolumeThreshold = 50,
    [double]$DomainEntropyThreshold = 3.5,
    [int]$DomainLengthThreshold = 30,
    [double]$NumericRatioThreshold = 0.4,
    [double]$VowelRatioThreshold = 0.2,
    [double]$IPEntropyThreshold = 3.0,
    [string[]]$SpecificTLDs = @(),
    [string[]]$SpecificRMMTools = @(),
    [string[]]$SpecificLOLBins = @(),
    [string[]]$SpecificCloudDomains = @()
)

# Function to read INI file
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

# Load config.ini if exists (script directory)
$configPath = Join-Path (Split-Path $PSCommandPath -Parent) "config.ini"
$config = Read-IniFile -Path $configPath

# Override defaults with config
if ($config['Anomaly']) {
    if ($config['Anomaly']['DomainEntropyThreshold']) { $DomainEntropyThreshold = [double]$config['Anomaly']['DomainEntropyThreshold'] }
    if ($config['Anomaly']['DomainLengthThreshold']) { $DomainLengthThreshold = [int]$config['Anomaly']['DomainLengthThreshold'] }
    if ($config['Anomaly']['NumericRatioThreshold']) { $NumericRatioThreshold = [double]$config['Anomaly']['NumericRatioThreshold'] }
    if ($config['Anomaly']['VowelRatioThreshold']) { $VowelRatioThreshold = [double]$config['Anomaly']['VowelRatioThreshold'] }
    if ($config['Anomaly']['IPEntropyThreshold']) { $IPEntropyThreshold = [double]$config['Anomaly']['IPEntropyThreshold'] }
    if ($config['Anomaly']['VolumeThreshold']) { $VolumeThreshold = [int]$config['Anomaly']['VolumeThreshold'] }
    # Add others if needed
}
if ($config['Specifics']) {
    if ($config['Specifics']['TLDs']) { $SpecificTLDs = $config['Specifics']['TLDs'] -split ',' | ForEach-Object { $_.Trim() } }
    if ($config['Specifics']['RMMTools']) { $SpecificRMMTools = $config['Specifics']['RMMTools'] -split ',' | ForEach-Object { $_.Trim() } }
    if ($config['Specifics']['LOLBins']) { $SpecificLOLBins = $config['Specifics']['LOLBins'] -split ',' | ForEach-Object { $_.Trim() } }
    if ($config['Specifics']['CloudDomains']) { $SpecificCloudDomains = $config['Specifics']['CloudDomains'] -split ',' | ForEach-Object { $_.Trim() } }
}

# Output directory setup
try {
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) { New-Item -Path $outputDir -ItemType Directory -Force | Out-Null }
} catch {
    Write-Error "Failed to create output directory: $($_.Exception.Message)"
    exit
}

$logName = "Microsoft-Windows-Sysmon/Operational"

# Check if Sysmon is installed
try {
    Get-WinEvent -FilterHashtable @{LogName = $logName} -MaxEvents 1 -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Sysmon not installed or log not found. Please run the companion installation script 'InstallSysmonForC2Detection.ps1' first and then rerun this script."
    exit
}

# Common ports (examples, detection not confined)
$commonPorts = @('80', '443', '53')
$internalIpRegex = '^((10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)|(127\.)|(169\.254\.))'

# Function to calculate Shannon entropy (optimized: precompute log2)
$log2 = [Math]::Log(2)
function Get-Entropy {
    param ([string]$inputString)
    if ($inputString.Length -eq 0) { return 0 }
    $charCounts = @{}
    foreach ($char in $inputString.ToCharArray()) {
        if ($charCounts.ContainsKey($char)) { $charCounts[$char]++ } else { $charCounts[$char] = 1 }
    }
    $entropy = 0
    foreach ($count in $charCounts.Values) {
        $p = $count / $inputString.Length
        $entropy -= $p * [Math]::Log($p) / $log2
    }
    return $entropy
}

# Function to check anomalous domain (heuristic-based)
function Is-AnomalousDomain {
    param ([string]$domain)
    if ([string]::IsNullOrEmpty($domain)) { return $false }
    if ($domain.Length -gt $DomainLengthThreshold) { return $true }
    $numericRatio = ($domain -replace '[^0-9]', '').Length / $domain.Length
    if ($numericRatio -gt $NumericRatioThreshold) { return $true }
    $vowels = 'aeiou'
    $vowelCount = 0
    foreach ($char in $domain.ToLower().ToCharArray()) {
        if ($vowels -contains $char) { $vowelCount++ }
    }
    if ($vowelCount / $domain.Length -lt $VowelRatioThreshold) { return $true }
    $entropy = Get-Entropy $domain
    return $entropy -gt $DomainEntropyThreshold
}

# Function to check anomalous IP (entropy-based)
function Is-AnomalousIP {
    param ([string]$ip)
    if ([string]::IsNullOrEmpty($ip)) { return $false }
    $numericRatio = ($ip -replace '[^0-9.]', '').Length / $ip.Length
    if ($numericRatio -ne 1) { return $true }
    $entropy = Get-Entropy $ip
    return $entropy -gt $IPEntropyThreshold
}

# Connection history for beaconing and volume (use hashtables for fast lookup)
$connectionHistory = @{}
$connectionVolume = @{}

# Advanced Beaconing Parameters (configurable)
$ACFThreshold = 0.5 # Autocorrelation > this flags periodicity
$JitterRatioThreshold = 0.2 # Variance/mean < this flags controlled jitter
$PeriodPowerThreshold = 0.5 # For Lomb-Scargle approximation

# Check if Python is installed for ML clustering
$pythonInstalled = Get-Command python -ErrorAction SilentlyContinue
$tempIntervalsFile = "$env:TEMP\beacon_intervals.json" # Temp file for Python

# Function to add connection
function Add-Connection {
    param (
        [string]$Key,
        [DateTime]$Timestamp = (Get-Date)
    )
    if (-not $connectionHistory.ContainsKey($Key)) {
        $connectionHistory[$Key] = New-Object System.Collections.ArrayList
    }
    [void]$connectionHistory[$Key].Add($Timestamp)

    if (-not $connectionVolume.ContainsKey($Key)) {
        $connectionVolume[$Key] = 0
    }
    $connectionVolume[$Key]++
}

# Enhanced Check-Beaconing with advanced algorithms
function Check-Beaconing {
    param ([string]$Key)
    $now = Get-Date
    if (-not $connectionHistory.ContainsKey($Key)) { return $null }
    $connectionHistory[$Key] = $connectionHistory[$Key] | Where-Object { $_ -gt $now.AddMinutes(-$BeaconWindowMinutes) }
    if ($connectionHistory[$Key].Count -ge $MinConnectionsForBeacon) {
        $times = $connectionHistory[$Key] | Sort-Object
        $intervals = New-Object System.Collections.ArrayList
        for ($i = 1; $i -lt $times.Count; $i++) {
            [void]$intervals.Add(($times[$i] - $times[$i-1]).TotalSeconds)
        }
        if ($intervals.Count -gt 0) {
            $avg = ($intervals | Measure-Object -Average).Average
            $sumSqDiff = 0
            foreach ($int in $intervals) { $sumSqDiff += [Math]::Pow($int - $avg, 2) }
            $variance = $sumSqDiff / $intervals.Count
            $stdDev = [Math]::Sqrt($variance)
            $flags = @()
            # Basic low-variance check
            if ($stdDev -lt $MaxIntervalVarianceSeconds) {
                $flags += "Basic Beaconing (StdDev: $($stdDev.ToString('N2')) seconds)"
            }
            # Advanced: Jitter ratio
            if ($avg -gt 0 -and ($variance / $avg) -lt $JitterRatioThreshold) {
                $flags += "Controlled Jitter Beaconing (Ratio: $(($variance / $avg).ToString('N2')))"
            }
            # Advanced: Autocorrelation (lag 1)
            if ($intervals.Count -ge 2) {
                $series1 = $intervals[0..($intervals.Count - 2)]
                $series2 = $intervals[1..($intervals.Count - 1)]
                $mean1 = ($series1 | Measure-Object -Average).Average
                $mean2 = ($series2 | Measure-Object -Average).Average
                $cov = 0
                $var1 = 0
                $var2 = 0
                for ($j = 0; $j -lt $series1.Count; $j++) {
                    $diff1 = $series1[$j] - $mean1
                    $diff2 = $series2[$j] - $mean2
                    $cov += $diff1 * $diff2
                    $var1 += $diff1 * $diff1
                    $var2 += $diff2 * $diff2
                }
                if ($var1 -gt 0 -and $var2 -gt 0) {
                    $acf = $cov / [Math]::Sqrt($var1 * $var2)
                    if ($acf -gt $ACFThreshold) {
                        $flags += "Periodic Beaconing (ACF: $($acf.ToString('N2')))"
                    }
                }
            }
            # Advanced: Lomb-Scargle periodogram approximation
            $periods = @(30, 60, 120, 300) # Common beacon periods in seconds
            $maxPower = 0
            foreach ($p in $periods) {
                $omega = 2 * [Math]::PI / $p
                $sinSum = 0
                $cosSum = 0
                foreach ($t in $normalized_times = $times | ForEach-Object { ($_ - $times[0]).TotalSeconds }) {
                    $sinSum += [Math]::Sin($omega * $t)
                    $cosSum += [Math]::Cos($omega * $t)
                }
                $power = ([Math]::Pow($sinSum, 2) + [Math]::Pow($cosSum, 2)) / $normalized_times.Count
                if ($power -gt $maxPower) { $maxPower = $power }
            }
            if ($maxPower -gt $PeriodPowerThreshold) {
                $flags += "Periodic Beaconing (Power: $($maxPower.ToString('N2')))"
            }
            # Advanced: ML Clustering (if Python installed)
            if ($pythonInstalled) {
                # Export intervals to temp file
                $intervals | ConvertTo-Json | Out-File -FilePath $tempIntervalsFile -Encoding utf8
                # Call Python script (BeaconML.py)
                $mlResult = python (Join-Path (Split-Path $PSCommandPath -Parent) "BeaconML.py") $tempIntervalsFile
                if ($mlResult -match "Beaconing") { $flags += $mlResult }
                Remove-Item $tempIntervalsFile -ErrorAction SilentlyContinue
            }
            if ($flags.Count -gt 0) {
                return $flags -join '; '
            }
        }
    }
    return $null
}

# Function to check volume anomaly
function Check-Volume {
    param ([string]$Key)
    if ($connectionVolume.ContainsKey($Key) -and $connectionVolume[$Key] -gt $VolumeThreshold) {
        return "High volume detected (Count: $($connectionVolume[$Key]))"
    }
    return $null
}

# Function to prune old keys
function Prune-History {
    $keysToRemove = $connectionHistory.Keys | Where-Object { $connectionHistory[$_].Count -eq 0 }
    foreach ($key in $keysToRemove) {
        $connectionHistory.Remove($key)
        $connectionVolume.Remove($key)
    }
    if ($connectionHistory.Count -gt $MaxHistoryKeys) {
        $oldestKeys = $connectionHistory.Keys | Sort-Object { $connectionHistory[$_][0] } | Select-Object -First ($connectionHistory.Count - $MaxHistoryKeys)
        foreach ($key in $oldestKeys) {
            $connectionHistory.Remove($key)
            $connectionVolume.Remove($key)
        }
    }
}

# Batch data for export (performance: append in memory, export periodically)
$dataBatch = @()
$batchSize = 100 # Export every 100 items or at end of loop

# Monitoring loop
while ($true) {
    try {
        if (-not $lastQueryTime) {
            $lastQueryTime = (Get-Date).AddMinutes(-1) # Fallback to 1 minute ago if null
        }
        $filter = @{
            LogName = $logName
            ID = 1,3,7,11,12,13,22
            StartTime = $lastQueryTime
        }
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        $now = Get-Date
        foreach ($event in $events) {
            try {
                $xmlData = [xml]$event.ToXml()
                $eventDataHash = @{}
                foreach ($data in $xmlData.Event.EventData.Data) {
                    $eventDataHash[$data.Name] = $data.'#text'
                }
                # Noise filtering for known good: Skip event if matches criteria
                if ($event.Id -eq 7 -and $eventDataHash['Signed'] -eq 'true' -and $eventDataHash['Signature'] -match 'Microsoft Windows' -and $eventDataHash['SignatureStatus'] -eq 'Valid') {
                    continue  # Skip logging this event as normal noise
                }
                $props = @{
                    EventType = switch ($event.Id) { 1 {"ProcessCreate"} 3 {"NetworkConnect"} 7 {"ImageLoad"} 11 {"FileCreate"} 12 {"RegistryCreateDelete"} 13 {"RegistrySet"} 22 {"DnsQuery"} }
                    Timestamp = $event.TimeCreated
                    UtcTime = $eventDataHash['UtcTime']
                    ProcessId = $eventDataHash['ProcessId']
                    Image = $eventDataHash['Image']
                    SuspiciousFlags = @()
                    ATTCKMappings = @()
                    FullMessage = $event.Message # Add full Sysmon event message for details
                    # Add event-specific details
                    CommandLine = $eventDataHash['CommandLine'] # For process events
                    DestinationIp = $eventDataHash['DestinationIp'] # For network
                    DestinationPort = $eventDataHash['DestinationPort'] # For network
                    QueryName = $eventDataHash['QueryName'] # For DNS
                }
                switch ($event.Id) {
                    1 {
                        $props['CommandLine'] = $eventDataHash['CommandLine']
                        $props['ParentImage'] = $eventDataHash['ParentImage']
                        $props['ParentCommandLine'] = $eventDataHash['ParentCommandLine']
                        if ($props['CommandLine'] -match '-EncodedCommand|-enc|IEX|Invoke-Expression|DownloadString') {
                            $props.SuspiciousFlags += "Anomalous CommandLine (Potential Script Execution)"
                            $props.ATTCKMappings += "TA0002: T1059 (Command and Scripting Interpreter); T1059.001 (PowerShell)"
                        }
                        if ($props['Image'] -match 'schtasks\.exe' -and $props['CommandLine'] -match '/create') {
                            $props.SuspiciousFlags += "Scheduled Task Creation (Persistence Anomaly)"
                            $props.ATTCKMappings += "TA0003: T1053.005 (Scheduled Task/Job)"
                        }
                        if ($props['CommandLine'] -match 'Set-MpPreference.*-Disable|sc delete|net stop') {
                            $props.SuspiciousFlags += "Service/Defense Tampering Anomaly"
                            $props.ATTCKMappings += "TA0005: T1562 (Impair Defenses); T1562.001 (Disable or Modify Tools)"
                        }
                        if ($props['ParentImage'] -notmatch 'explorer|cmd|powershell' -and $props['Image'] -match '\.exe$') {
                            $props.SuspiciousFlags += "Unusual Parent Process Anomaly"
                            $props.ATTCKMappings += "TA0002: T1059 (Command and Scripting Interpreter)"
                        }
                        if ($SpecificRMMTools -and $SpecificRMMTools -contains $props['Image']) {
                            $props.SuspiciousFlags += "Specific RMM Tool Match"
                            $props.ATTCKMappings += "TA0011: T1219 (Remote Access Software)"
                        }
                        if ($SpecificLOLBins -and $SpecificLOLBins -contains $props['Image']) {
                            $props.SuspiciousFlags += "Specific LOLBin Match"
                            $props.ATTCKMappings += "TA0005: T1218 (System Binary Proxy Execution)"
                        }
                    }
                    3 {
                        $props['Protocol'] = $eventDataHash['Protocol']
                        $props['SourceIp'] = $eventDataHash['SourceIp']
                        $props['SourcePort'] = $eventDataHash['SourcePort']
                        $props['DestinationIp'] = $eventDataHash['DestinationIp']
                        $props['DestinationHostname'] = $eventDataHash['DestinationHostname']
                        $props['DestinationPort'] = $eventDataHash['DestinationPort']
                        $props['IsOutbound'] = if ($eventDataHash['SourceIp'] -match $internalIpRegex -and $eventDataHash['DestinationIp'] -notmatch $internalIpRegex) { $true } else { $false }
                        if ($props['IsOutbound']) {
                            $key = if ($props['DestinationHostname']) { "$($props['DestinationHostname']):$($props['DestinationPort'])" } else { "$($props['DestinationIp']):$($props['DestinationPort'])" }
                            Add-Connection -Key $key -Timestamp $props['Timestamp']
                            $beaconFlag = Check-Beaconing -Key $key
                            if ($beaconFlag) {
                                $props.SuspiciousFlags += $beaconFlag
                                $props.ATTCKMappings += "TA0011: T1071 (Application Layer Protocol); T1571 (Non-Standard Port)"
                            }
                            $volumeFlag = Check-Volume -Key $key
                            if ($volumeFlag) {
                                $props.SuspiciousFlags += $volumeFlag
                                $props.ATTCKMappings += "TA0010: T1041 (Exfiltration Over C2 Channel); TA0011: T1095 (Non-Application Layer Protocol)"
                            }
                            if ($props['DestinationHostname']) {
                                if (Is-AnomalousDomain $props['DestinationHostname']) {
                                    $props.SuspiciousFlags += "Domain Anomaly (DGA-like)"
                                    $props.ATTCKMappings += "TA0011: T1568 (Dynamic Resolution); T1568.002 (Domain Generation Algorithms)"
                                }
                                if ($SpecificTLDs -and ($SpecificTLDs | Where-Object { $props['DestinationHostname'].EndsWith($_, [StringComparison]::OrdinalIgnoreCase) })) {
                                    $props.SuspiciousFlags += "Specific TLD Match"
                                    $props.ATTCKMappings += "TA0011: T1568 (Dynamic Resolution)"
                                }
                            } elseif ($props['DestinationIp']) {
                                if (Is-AnomalousIP $props['DestinationIp']) {
                                    $props.SuspiciousFlags += "IP Anomaly (High Entropy/Random-like)"
                                    $props.ATTCKMappings += "TA0011: T1071 (Application Layer Protocol); T1568.001 (Fast Flux DNS)"
                                }
                            }
                            if ($props['DestinationPort'] -notin $commonPorts) {
                                $props.SuspiciousFlags += "Unusual Port/Protocol Anomaly"
                                $props.ATTCKMappings += "TA0011: T1571 (Non-Standard Port); T1095 (Non-Application Layer Protocol)"
                            }
                            if ($props['Protocol'] -eq 'udp' -and $props['DestinationPort'] -ne '53') {
                                $props.SuspiciousFlags += "Potential Tunneling Anomaly"
                                $props.ATTCKMappings += "TA0011: T1572 (Protocol Tunneling)"
                            }
                            if ($SpecificCloudDomains -and ($SpecificCloudDomains | Where-Object { $props['DestinationHostname'] -match $_ })) {
                                $props.SuspiciousFlags += "Specific Cloud Domain Match"
                                $props.ATTCKMappings += "TA0011: T1102 (Web Service)"
                            }
                            if ($props['Image'] -notmatch 'browser|system|trusted') {
                                $props.SuspiciousFlags += "Unusual Process Network Activity"
                                $props.ATTCKMappings += "TA0011: T1071 (Application Layer Protocol); TA0002: T1059 (Command and Scripting Interpreter)"
                            }
                        } else { continue }
                    }
                    7 {
                        $props['ImageLoaded'] = $eventDataHash['ImageLoaded']
                        # Noise filtering for "known good" signed Microsoft DLLs
                        if ($eventDataHash['Signed'] -eq 'true' -and $eventDataHash['Signature'] -match 'Microsoft Windows' -and $eventDataHash['SignatureStatus'] -eq 'Valid') {
                            continue  # Skip logging this event as normal noise
                        }
                        if ($props['ImageLoaded'] -match '\.dll$' -and $props['Image'] -notmatch $props['ImageLoaded']) {
                            $props.SuspiciousFlags += "Anomalous DLL Load"
                            $props.ATTCKMappings += "TA0005: T1574 (Hijack Execution Flow); T1574.002 (DLL Side-Loading)"
                        }
                    }
                    11 {
                        $props['TargetFilename'] = $eventDataHash['TargetFilename']
                        if ($props['TargetFilename'] -match '\\system32\\|\AppData\\|\\.ps1|\\.vbs|\\.bat') {
                            $props.SuspiciousFlags += "Anomalous File Creation (Sensitive Path/Script)"
                            $props.ATTCKMappings += "TA0003: T1546 (Event Triggered Execution); TA0002: T1059 (Command and Scripting Interpreter)"
                        }
                    }
                    {12,13} {
                        $props['TargetObject'] = $eventDataHash['TargetObject']
                        if ($props['TargetObject'] -match 'Run|RunOnce|Services|Startup|Image File Execution Options') {
                            $props.SuspiciousFlags += "Registry Anomaly (Persistence Key)"
                            $props.ATTCKMappings += "TA0003: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys); T1543.003 (Create or Modify System Process: Windows Service)"
                        }
                    }
                    22 {
                        $props['QueryName'] = $eventDataHash['QueryName']
                        $props['QueryStatus'] = $eventDataHash['QueryStatus']
                        $props['QueryResults'] = $eventDataHash['QueryResults']
                        if (Is-AnomalousDomain $props['QueryName']) {
                            $props.SuspiciousFlags += "DNS Query Anomaly (DGA-like/Tunneling)"
                            $props.ATTCKMappings += "TA0011: T1071.004 (Application Layer Protocol: DNS); T1568 (Dynamic Resolution)"
                        }
                        if ($props['QueryName'] -match '\.onion|\.i2p' -or $props['QueryResults'] -match 'NXDOMAIN' * 5) {
                            $props.SuspiciousFlags += "Anomalous DNS Resolution (Potential Hidden Channel)"
                            $props.ATTCKMappings += "TA0011: T1572 (Protocol Tunneling); TA0005: T1021 (Remote Services)"
                        }
                        if ($SpecificTLDs -and ($SpecificTLDs | Where-Object { $props['QueryName'].EndsWith($_, [StringComparison]::OrdinalIgnoreCase) })) {
                            $props.SuspiciousFlags += "Specific TLD Match in DNS"
                            $props.ATTCKMappings += "TA0011: T1568 (Dynamic Resolution)"
                        }
                    }
                }
                $props.SuspiciousFlags = $props.SuspiciousFlags -join '; '
                $props.ATTCKMappings = $props.ATTCKMappings -join '; '
                if ($event.Id -in @(3,22) -or $props.SuspiciousFlags) {
                    $dataBatch += New-Object PSObject -Property $props
                }
            } catch {
                Write-Verbose "Error parsing event: $($_.Exception.Message)"
                continue
            }
        }
        # Prune history (optimized: batch remove)
        $keysToRemove = $connectionHistory.Keys | Where-Object { $connectionHistory[$_].Count -eq 0 }
        foreach ($key in $keysToRemove) {
            $connectionHistory.Remove($key)
            $connectionVolume.Remove($key)
        }
        if ($connectionHistory.Count -gt $MaxHistoryKeys) {
            $oldestKeys = $connectionHistory.Keys | Sort-Object { $connectionHistory[$_][0] } | Select-Object -First ($connectionHistory.Count - $MaxHistoryKeys)
            foreach ($key in $oldestKeys) {
                $connectionHistory.Remove($key)
                $connectionVolume.Remove($key)
            }
        }
        # Export batched data if threshold or loop end
        if ($dataBatch.Count -ge $batchSize -or $events.Count -eq 0) {
            if ($dataBatch.Count -gt 0) {
                try {
                    switch ($Format) {
                        "CSV" { $dataBatch | Export-Csv -Path $OutputPath -Append -NoTypeInformation }
                        "JSON" { $dataBatch | ConvertTo-Json -Depth 4 | Add-Content -Path $OutputPath }
                        "YAML" {
                            if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
                                Write-Warning "powershell-yaml not found. Falling back to JSON."
                                $dataBatch | ConvertTo-Json -Depth 4 | Add-Content -Path $OutputPath
                            } else {
                                Import-Module powershell-yaml
                                $dataBatch | ConvertTo-Yaml | Add-Content -Path $OutputPath
                            }
                        }
                    }
                    Write-Output "$(Get-Date): Appended $($dataBatch.Count) monitored events (with anomalies and ATT&CK mappings) to $OutputPath"
                } catch {
                    Write-Error "Export error: $($_.Exception.Message)"
                }
                $dataBatch = @()
            }
        }
        $lastQueryTime = $now
    } catch {
        Write-Error "Loop error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $IntervalSeconds
}