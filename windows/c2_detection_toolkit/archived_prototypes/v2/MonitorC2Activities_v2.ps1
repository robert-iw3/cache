<#
.SYNOPSIS
    Standalone Native PowerShell C2 Monitor (No Python Dependencies).
    Monitors Sysmon events for C2, Beaconing, and Persistence with MITRE ATT&CK mappings.
    Optimized: Compiled Regex, XML Fast-Path filtering, O(1) Queues.
    Features: In-memory .NET math for Beaconing (Variance/Jitter), DLL Sideloading, DGA, and Registry persistence.

.DESCRIPTION
    Loads settings from config.ini (if exists), but strictly respects Command-Line Overrides.
    Config Priority: CLI Arguments > Config.ini > Script Defaults.

    Detection Logic:
    - Beaconing: Uses .NET math to calculate Interval Standard Deviation and Jitter Consistency.
    - Sideloading: Alerts on System Binaries loading Non-System DLLs.
    - Context: Includes a new 'Details' field (User, Registry Values, DNS Results) for correlation.

    Config.ini example:
    [Anomaly]
    DomainEntropyThreshold=3.5
    [Specifics]
    TLDs=.ru,.cn

.PARAMETER OutputPath
    Path to output file (default: C:\Temp\C2Monitoring.csv).

.PARAMETER Format
    Output format: CSV (default) or JSON. (YAML removed for standalone compatibility).

.PARAMETER IntervalSeconds
    Polling interval (default: 10).

.PARAMETER MinConnectionsForBeacon
    Min connections before calculating variance (default: 5).

.PARAMETER MaxBeaconStdDev
    Threshold (seconds) for "Perfect" machine-like beaconing (default: 5.0).

.PARAMETER JitterTolerance
    Percentage (0.0-1.0) of interval deviation allowed for "Jittered" beacon detection (default: 0.2).

.PARAMETER BeaconWindowMinutes
    Time window to track connections for beaconing analysis (default: 60).

.PARAMETER MaxHistoryKeys
    Max number of active connection streams to track in memory (default: 2000).

.PARAMETER VolumeThreshold
    Connection count threshold for volume anomaly (default: 50).

.PARAMETER DomainEntropyThreshold
    Entropy threshold for domain anomaly (default: 3.8).

.PARAMETER DomainLengthThreshold
    Length threshold for domain anomaly (default: 30).

.PARAMETER NumericRatioThreshold
    Numeric ratio threshold for domain/IP anomaly (default: 0.4).

.PARAMETER VowelRatioThreshold
    Minimum vowel ratio for domain anomaly (default: 0.2).

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
    .\MonitorC2Activities_v2.ps1 -SpecificTLDs @('.ru', '.cn') -JitterTolerance 0.3
    .\MonitorC2Activities_v2.ps1 -OutputPath "C:\Logs\C2Log.json" -Format JSON
    .\MonitorC2Activities_v2.ps1 -MaxBeaconStdDev 2.0 -MinConnectionsForBeacon 10

.NOTES
    Author: Robert Weber

    Updates (v2):
    - Architecture: Pure .NET (No Python required).
    - Logic: Fixed Event 12/13 Switch syntax and Regex Flag compatibility.
    - Logic: Fixed Event 7 (Sideloading) false positives.
    - Feature: Added 'Details' column for deeper context.
    - Config: Fixed precedence (CLI now correctly overrides Config.ini).
#>

param (
    [string]$OutputPath = "C:\Temp\C2Monitoring.csv",
    [ValidateSet("CSV", "JSON")][string]$Format = "CSV",

    # Polling & Math Config
    [int]$IntervalSeconds = 10,
    [int]$MinConnectionsForBeacon = 5,
    [int]$BeaconWindowMinutes = 60,
    [int]$MaxHistoryKeys = 2000,
    [double]$MaxBeaconStdDev = 5.0,
    [double]$JitterTolerance = 0.2,

    # Anomaly Thresholds
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

# Compiled Regex (Comma separated flags)
$Regex_InternalIP = [regex]::new('^((10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)|(127\.)|(169\.254\.))', 'Compiled')
$Regex_NonDigit   = [regex]::new('[^0-9]', 'Compiled')
$Regex_Encoded    = [regex]::new('-EncodedCommand|-enc|IEX|Invoke-Expression|DownloadString', 'Compiled, IgnoreCase')
$Regex_Defense    = [regex]::new('Set-MpPreference.*-Disable|sc delete|net stop', 'Compiled, IgnoreCase')
$Regex_SysPaths   = [regex]::new('System32|SysWOW64|WinSxS', 'Compiled, IgnoreCase')
$Regex_MS_Signed  = [regex]::new('Signed="true".*Signature="Microsoft Windows".*SignatureStatus="Valid"', 'Compiled')

$log2 = [Math]::Log(2)
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")
$connectionHistory = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()

# --- 2. CONFIGURATION ENGINE ---

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

# --- 3. MATH & ANALYSIS FUNCTIONS ---

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

function Test-Beaconing {
    param ([datetime[]]$timestamps)

    if ($timestamps.Count -lt $MinConnectionsForBeacon) { return $null }

    $intervals = [System.Collections.Generic.List[double]]::new()
    for ($i = 1; $i -lt $timestamps.Count; $i++) {
        $delta = ($timestamps[$i] - $timestamps[$i-1]).TotalSeconds
        $intervals.Add($delta)
    }

    if ($intervals.Count -eq 0) { return $null }

    $sum = 0; $intervals | ForEach-Object { $sum += $_ }
    $avg = $sum / $intervals.Count

    $sumSqDiff = 0
    foreach ($val in $intervals) { $sumSqDiff += [Math]::Pow(($val - $avg), 2) }
    $variance = $sumSqDiff / $intervals.Count
    $stdDev = [Math]::Sqrt($variance)

    if ($stdDev -le $MaxBeaconStdDev) {
        return "Perfect Beacon Detected (StdDev: $($stdDev.ToString('N2'))s, Interval: ~$($avg.ToString('N0'))s)"
    }

    $consistentCount = 0
    $lower = $avg * (1.0 - $JitterTolerance)
    $upper = $avg * (1.0 + $JitterTolerance)
    foreach ($val in $intervals) { if ($val -ge $lower -and $val -le $upper) { $consistentCount++ } }

    $ratio = $consistentCount / $intervals.Count
    if ($ratio -ge 0.6) {
        return "Jittered Beacon Detected (Consistency: $(($ratio * 100).ToString('N0'))%, Interval: ~$($avg.ToString('N0'))s)"
    }

    return $null
}

# --- 4. MAIN MONITORING LOOP ---

$logName = "Microsoft-Windows-Sysmon/Operational"
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) { New-Item -Path $outputDir -ItemType Directory -Force | Out-Null }

$lastQueryTime = (Get-Date).AddMinutes(-1)

Write-Host "[-] Starting Native C2 Monitor (Enhanced Context)..." -ForegroundColor Cyan
Write-Host "    Mode: Standalone (No Python)." -ForegroundColor Gray

while ($true) {
    try {
        $now = Get-Date
        if (-not $lastQueryTime) { $lastQueryTime = $now.AddMinutes(-1) }

        $filter = @{ LogName = $logName; ID = 1,3,7,11,12,13,22; StartTime = $lastQueryTime }
        $events = try { Get-WinEvent -FilterHashtable $filter -ErrorAction Stop } catch { $null }

        if ($events) {
            foreach ($event in $events) {
                $rawXml = $event.ToXml()
                if ($event.Id -eq 7 -and $Regex_MS_Signed.IsMatch($rawXml)) { continue }

                $xmlData = [xml]$rawXml
                $eventDataHash = @{}
                foreach ($node in $xmlData.Event.EventData.Data) { $eventDataHash[$node.Name] = $node.'#text' }

                # Base Props with NEW 'Details' Field
                $props = [ordered]@{
                    EventType = switch ($event.Id) { 1 {"ProcessCreate"} 3 {"NetworkConnect"} 7 {"ImageLoad"} 11 {"FileCreate"} 12 {"RegistryEvent"} 13 {"RegistryEvent"} 22 {"DnsQuery"} default {$event.Id} }
                    Timestamp = $event.TimeCreated
                    Image = $eventDataHash['Image']
                    User = $eventDataHash['User'] # Capture User Context
                    Details = "" # Placeholder for specific event details
                    SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                    ATTCKMappings = [System.Collections.Generic.List[string]]::new()

                    # Raw Fields (kept for filtering, but 'Details' will summarize them)
                    CommandLine = $eventDataHash['CommandLine']
                    DestinationIp = $eventDataHash['DestinationIp']
                    DestinationHostname = $eventDataHash['DestinationHostname']
                }

                switch ($event.Id) {
                    1 { # Process Create
                        $props.Details = "Cmd: $($props.CommandLine)"

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
                    3 { # Network Connect
                        $dst = if ($props['DestinationHostname']) { "$($props['DestinationHostname'])" } else { "$($props['DestinationIp'])" }
                        $port = $eventDataHash['DestinationPort']
                        $props.Details = "Dest: $dst Port: $port Protocol: $($eventDataHash['Protocol'])"

                        if ($props['DestinationHostname'] -and (Is-AnomalousDomain $props['DestinationHostname'])) {
                            $props.SuspiciousFlags.Add("High Entropy Domain (Network)")
                            $props.ATTCKMappings.Add("TA0011: T1568.002")
                        }

                        # Beacon Logic
                        $isOutbound = ($Regex_InternalIP.IsMatch($eventDataHash['SourceIp']) -and -not $Regex_InternalIP.IsMatch($eventDataHash['DestinationIp']))
                        if ($isOutbound) {
                            $key = "$dst`:$port"
                            if (-not $connectionHistory.ContainsKey($key)) { $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new() }
                            $connectionHistory[$key].Enqueue($now)

                            while ($connectionHistory[$key].Count -gt 0 -and $connectionHistory[$key].Peek() -lt $now.AddMinutes(-$BeaconWindowMinutes)) {
                                [void]$connectionHistory[$key].Dequeue()
                            }

                            $alert = Test-Beaconing $connectionHistory[$key].ToArray()
                            if ($alert) {
                                $props.SuspiciousFlags.Add($alert)
                                $props.ATTCKMappings.Add("TA0011: T1071")
                            }
                        }
                    }
                    7 { # Image Load
                        $props.Details = "Loaded: $($eventDataHash['ImageLoaded'])"
                        if ($Regex_SysPaths.IsMatch($props['Image']) -and -not $Regex_SysPaths.IsMatch($props['ImageLoaded'])) {
                            $props.SuspiciousFlags.Add("Anomalous DLL Load (Sideloading Risk)")
                            $props.ATTCKMappings.Add("TA0005: T1574.002")
                        }
                    }
                    11 { # File Create
                        $props.Details = "Created: $($eventDataHash['TargetFilename'])"
                        if ($eventDataHash['TargetFilename'] -match '\.ps1$|\.vbs$|\.bat$|\.exe$') {
                            $props.SuspiciousFlags.Add("Executable/Script File Created")
                            $props.ATTCKMappings.Add("TA0002: T1059")
                        }
                    }
                    { $_ -in 12, 13 } { # Registry
                        # Capture the details of WHAT was set
                        $details = "Key: $($eventDataHash['TargetObject'])"
                        if ($eventDataHash['Details']) { $details += " Value: $($eventDataHash['Details'])" }
                        $props.Details = $details

                        if ($eventDataHash['TargetObject'] -match 'Run|RunOnce|Services|Startup') {
                            $props.SuspiciousFlags.Add("Persistence Registry Key Modified")
                            $props.ATTCKMappings.Add("TA0003: T1547.001")
                        }
                    }
                    22 { # DNS
                        $props.Details = "Query: $($eventDataHash['QueryName']) Result: $($eventDataHash['QueryResults'])"
                        $qName = $eventDataHash['QueryName']

                        if (Is-AnomalousDomain $qName) {
                            $props.SuspiciousFlags.Add("DGA DNS Query Detected")
                            $props.ATTCKMappings.Add("TA0011: T1568.002")
                        }
                        if ($SpecificTLDs -and ($SpecificTLDs | Where-Object { $qName.EndsWith($_) })) {
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

        # Cleanup History
        if ($connectionHistory.Count -gt $MaxHistoryKeys) {
            $keys = $connectionHistory.Keys | Select-Object -First 100
            foreach ($k in $keys) { [void]$connectionHistory.Remove($k) }
        }

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