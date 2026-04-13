<#
.SYNOPSIS
    Windows Kernel C2 Beacon Hunter v3.0 — Full integration with BeaconML
.DESCRIPTION
    Monitors a live kernel ETW trace file (C:\Temp\C2Kernel.etl) for command-and-control
    beaconing behavior using only native Windows kernel providers (Microsoft-Windows-Kernel-Network,
    Microsoft-Windows-TCPIP, Microsoft-Windows-DNS-Client, etc.).

    This script:
      - Correctly decodes raw sockaddr_in structs and byte arrays from ETW
      - Tracks outbound flows with sliding-window interval history
      - Builds 4D feature payloads (intervals, packet sizes, destination IPs, domain entropy)
      - Feeds them to BeaconML.py daemon for clustering-based beacon detection
      - Outputs detections to JSONL with ATT&CK mappings and log rotation

    Designed for PowerShell 5.1 and 7+ compatibility. No Sysmon dependency.
.NOTES
    Author: Robert Weber
    Version: 3.0
    Dev Notes:
        - Provider-aware event mapping ($evType) eliminates brittle $event.Id switches.
        - IP decoder now handles both AF_INET (2) and AF_INET6 (23) sockaddr structs.
        - Strict IP validation prevents Process IDs or other garbage from becoming IPs.
        - Interval calculation now uses deltas between consecutive timestamps (more accurate for beacon jitter).
        - Debug output limited to first 30 NetworkConnect events for fast troubleshooting.
        - MinSamplesForML reduced to 3 for quicker testing (change back to 8 in production).
#>
#Requires -RunAsAdministrator

param (
    [string]$OutputPath = "C:\Temp\C2KernelMonitoring_v3.jsonl",
    [ValidateSet("CSV","JSON","JSONL")][string]$Format = "JSONL",
    [int]$IntervalSeconds = 2,
    [int]$BatchAnalysisIntervalSeconds = 30,
    [int]$MinSamplesForML = 3,          # Reduced for faster testing (was 8). Change back to 8 in production.
    [string]$PythonPath = "python",
    [string]$MLScriptPath = "BeaconML.py"
)

$ScriptDir = Split-Path $PSCommandPath -Parent
$FullMLPath = Join-Path $ScriptDir $MLScriptPath
$EtwPath = "C:\Temp\C2Kernel.etl"
$BeaconWindowMinutes = 60
$RefDate = Get-Date "1970-01-01"

# ====================== CONFIGURATION ENGINE ======================
function Read-IniFile {
    param ([string]$Path)
    $ini = @{}
    if (Test-Path $Path) {
        switch -regex -file $Path {
            "^\[(.*)\]$" { $section = $matches[1].Trim(); $ini[$section] = @{} }
            "^(.*?)=(.*)$" { if ($section) { $ini[$section][$matches[1].Trim()] = $matches[2].Trim() } }
        }
    }
    return $ini
}

$configPath = Join-Path $ScriptDir "config.ini"
$config = Read-IniFile -Path $configPath

[double]$DomainEntropyThreshold = 3.8
[int]$DomainLengthThreshold = 30
[double]$NumericRatioThreshold = 0.4
[double]$VowelRatioThreshold = 0.2
[double]$IPEntropyThreshold = 3.0
[int]$VolumeThreshold = 50
[string[]]$SpecificTLDs = @()
[string[]]$SpecificRMMTools = @()
[string[]]$SpecificLOLBins = @()
[string[]]$SpecificCloudDomains = @()

if ($config['Anomaly']) {
    $s = $config['Anomaly']
    if ($s['DomainEntropyThreshold']) { $DomainEntropyThreshold = [double]$s['DomainEntropyThreshold'] }
    if ($s['DomainLengthThreshold']) { $DomainLengthThreshold = [int]$s['DomainLengthThreshold'] }
    if ($s['NumericRatioThreshold']) { $NumericRatioThreshold = [double]$s['NumericRatioThreshold'] }
    if ($s['VowelRatioThreshold']) { $VowelRatioThreshold = [double]$s['VowelRatioThreshold'] }
    if ($s['IPEntropyThreshold']) { $IPEntropyThreshold = [double]$s['IPEntropyThreshold'] }
    if ($s['VolumeThreshold']) { $VolumeThreshold = [int]$s['VolumeThreshold'] }
}
if ($config['Specifics']) {
    $s = $config['Specifics']
    if ($s['TLDs']) { $SpecificTLDs = ($s['TLDs'] -split ',').Trim() }
    if ($s['RMMTools']) { $SpecificRMMTools = ($s['RMMTools'] -split ',').Trim() }
    if ($s['LOLBins']) { $SpecificLOLBins = ($s['LOLBins'] -split ',').Trim() }
    if ($s['CloudDomains']) { $SpecificCloudDomains = ($s['CloudDomains'] -split ',').Trim() }
}

# ====================== REGEX AND MATH HELPERS ======================
$Regex_InternalIP = [regex]::new('^((10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)|(127\.)|(169\.254\.))', 'Compiled')
$Regex_NonDigit = [regex]::new('[^0-9]', 'Compiled')
$Regex_Encoded = [regex]::new('-EncodedCommand|-enc|IEX|Invoke-Expression|DownloadString', 'Compiled, IgnoreCase')
$Regex_Defense = [regex]::new('Set-MpPreference.*-Disable|sc delete|net stop', 'Compiled, IgnoreCase')
$Regex_SysPaths = [regex]::new('System32|SysWOW64|WinSxS', 'Compiled, IgnoreCase')
$Regex_MS_Signed = [regex]::new('Publisher="Microsoft Corporation"', 'Compiled, IgnoreCase')

$log2 = [Math]::Log(2)
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")

function Get-Entropy {
    param ([string]$inputString)
    if ([string]::IsNullOrEmpty($inputString)) { return 0.0 }
    $charCounts = @{}
    foreach ($c in $inputString.ToCharArray()) { $charCounts[$c]++ }
    $entropy = 0.0
    $len = $inputString.Length
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
    foreach ($char in $domain.ToLower().ToCharArray()) {
        if ($vowels.Contains($char)) { $vowelCount++ }
    }
    if (($vowelCount / $domain.Length) -lt $VowelRatioThreshold) { return $true }
    return (Get-Entropy $domain) -gt $DomainEntropyThreshold
}

# ====================== RAW ETW BYTE ARRAY TO IP STRING CONVERTER ======================
function Convert-ETWIPBytesToString {
    param([object]$value)
    if (-not $value) { return $null }

    $result = $null

    if ($value -is [System.Diagnostics.Eventing.Reader.EventProperty]) {
        return Convert-ETWIPBytesToString -value $value.Value
    }

    if ($value -is [byte[]]) {
        # 1. Decode AF_INET (IPv4 sockaddr_in) -> Family 2
        if ($value.Length -ge 8 -and $value[0] -eq 2 -and $value[1] -eq 0) {
            $ipBytes = $value[4..7]
            try { $result = [System.Net.IPAddress]::new($ipBytes).IPAddressToString } catch {}
        }
        # 2. Decode AF_INET6 (IPv6 sockaddr_in6) -> Family 23 (0x17)
        elseif ($value.Length -ge 24 -and $value[0] -eq 23 -and $value[1] -eq 0) {
            $ipBytes = $value[8..23]
            try { $result = [System.Net.IPAddress]::new($ipBytes).IPAddressToString } catch {}
        }
        # 3. Standard IPv4 or IPv6 byte arrays
        elseif ($value.Length -eq 4 -or $value.Length -eq 16) {
            try { $result = [System.Net.IPAddress]::new($value).IPAddressToString } catch {}
        }
    }
    # 4. Decode Native ETW UInt32 / Int64 IP addresses
    elseif ($value -is [int] -or $value -is [uint32] -or $value -is [int64]) {
        if ($value -gt 255) { # Ignore tiny integers that are actually struct lengths
            try { $result = [System.Net.IPAddress]::new([long]$value).IPAddressToString } catch {}
        }
    }
    elseif ($value -is [string]) {
        $result = $value.Trim()
    }

    # STRICT VALIDATION: If the final result isn't a valid IP address, throw it away.
    # This prevents stray Process IDs (e.g. "7142") from being treated as destination IPs.
    $validIp = $null
    if ($result -and [System.Net.IPAddress]::TryParse($result, [ref]$validIp)) {
        return $validIp.ToString()
    }

    return $null
}

# ====================== ML DAEMON STARTUP ======================
Write-Host "[v3.0] Starting ML Daemon..." -ForegroundColor Cyan
$pyStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$pyStartInfo.FileName = $PythonPath
$pyStartInfo.Arguments = '-u "' + $FullMLPath + '"'
$pyStartInfo.RedirectStandardInput = $true
$pyStartInfo.RedirectStandardOutput = $true
$pyStartInfo.UseShellExecute = $false
$pyStartInfo.CreateNoWindow = $true
$pyProcess = [System.Diagnostics.Process]::Start($pyStartInfo)
$pyIn = $pyProcess.StandardInput
$pyOut = $pyProcess.StandardOutput

# ====================== RUNTIME DATA STRUCTURES ======================
$connectionHistory = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$lastPingTime = @{}
$flowMetadata = @{}
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()
$lastQueryTime = (Get-Date).AddMinutes(-1)
$lastMLRunTime = Get-Date
$mlBatchCount = 0
$OutboundNetEvents = 0
$NetworkConnectEvents = 0
$DebugCounter = 0

Write-Host "[v3.0] Kernel C2 Beacon Hunter started — BeaconML v3.0 loaded" -ForegroundColor Green

try {
    while ($true) {
        $now = Get-Date
        if (-not $lastQueryTime) { $lastQueryTime = $now.AddMinutes(-1) }

        $events = try {
            Get-WinEvent -Path $EtwPath -Oldest |
                Where-Object { $_.TimeCreated -ge $lastQueryTime }
        } catch { $null }

        if ($events) {
            foreach ($event in $events) {
                if ($event.Id -eq 7) {
                    if ($event.Properties.Count -gt 1 -and $event.Properties[1].Value -match "Microsoft Corporation") { continue }
                }

                # 1. TRANSLATE NATIVE ETW IDs TO STANDARD EVENT TYPES
                $provider = $event.ProviderName
                $eid = $event.Id
                $evType = "Unknown"
                if ($provider -match "Process" -and $eid -eq 1) { $evType = "ProcessCreate" }
                elseif ($provider -match "Process" -and $eid -eq 5) { $evType = "ImageLoad" }
                elseif ($provider -match "Network" -and ($eid -ge 10 -and $eid -le 15)) { $evType = "NetworkConnect" }
                elseif ($provider -match "TCPIP") { $evType = "NetworkConnect" }
                elseif ($provider -match "DNS" -and $eid -eq 3008) { $evType = "DnsQuery" }
                elseif ($provider -match "File" -and $eid -eq 30) { $evType = "FileCreate" }
                elseif ($provider -match "Registry" -and ($eid -eq 1 -or $eid -eq 2)) { $evType = "RegistryEvent" }

                if ($evType -eq "Unknown") { continue }

                # 2. INITIALIZE PROPERTIES
                $props = [ordered]@{
                    EventType          = $evType
                    Timestamp          = $event.TimeCreated
                    Image              = $null
                    User               = $null
                    Details            = ""
                    SuspiciousFlags    = [System.Collections.Generic.List[string]]::new()
                    ATTCKMappings      = [System.Collections.Generic.List[string]]::new()
                    CommandLine        = $null
                    DestinationIp      = $null
                    SourceIp           = $null
                    DestinationPort    = $null
                    DestinationHostname= $null
                }

                # 3. EXTRACT XML & POSITIONAL PROPERTIES
                $rawXml = $event.ToXml()
                $xmlData = [xml]$rawXml
                $eventDataHash = @{}
                foreach ($node in $xmlData.Event.EventData.Data) {
                    $eventDataHash[$node.Name] = $node.'#text'
                }
                $rawProps = @{}
                for ($i = 0; $i -lt $event.Properties.Count; $i++) {
                    $p = $event.Properties[$i]
                    $name = if ($p.Name) { $p.Name } else { "Prop$i" }
                    $rawProps[$name] = $p.Value
                }

                # 4. DECODE IPs (With ETW Positional Fallbacks)
                $destIpRaw = $eventDataHash['DestinationIp']
                if (-not $destIpRaw) { $destIpRaw = $eventDataHash['daddr'] }
                if (-not $destIpRaw) { $destIpRaw = $rawProps['daddr'] }
                if (-not $destIpRaw -and $provider -match "Network|TCPIP") { $destIpRaw = $rawProps['Prop2'] }
                $props.DestinationIp = Convert-ETWIPBytesToString -value $destIpRaw

                $srcIpRaw = $eventDataHash['SourceIp']
                if (-not $srcIpRaw) { $srcIpRaw = $eventDataHash['saddr'] }
                if (-not $srcIpRaw) { $srcIpRaw = $rawProps['saddr'] }
                if (-not $srcIpRaw -and $provider -match "Network|TCPIP") { $srcIpRaw = $rawProps['Prop3'] }
                $props.SourceIp = Convert-ETWIPBytesToString -value $srcIpRaw

                $props.DestinationPort = $eventDataHash['DestinationPort']
                if (-not $props.DestinationPort) { $props.DestinationPort = $eventDataHash['dport'] }
                if (-not $props.DestinationPort) { $props.DestinationPort = $rawProps['dport'] }
                if (-not $props.DestinationPort -and $provider -match "Network|TCPIP") { $props.DestinationPort = $rawProps['Prop4'] }

                $props.DestinationHostname = $eventDataHash['DestinationHostname']
                if (-not $props.DestinationHostname) { $props.DestinationHostname = $eventDataHash['QueryName'] }
                if (-not $props.DestinationHostname) { $props.DestinationHostname = $eventDataHash['Query'] }

                $props.Image = $eventDataHash['Image']
                if (-not $props.Image) { $props.Image = $eventDataHash['ImagePath'] }
                if (-not $props.Image) { $props.Image = $eventDataHash['ProcessName'] }

                $props.User = $eventDataHash['User']
                $props.CommandLine = $eventDataHash['CommandLine']

                # 5. SWITCH ON $evType (NOT $event.Id)
                switch ($evType) {
                    "ProcessCreate" {
                        $props.Details = "Cmd: $($props.CommandLine)"
                        if ($props.CommandLine -and $Regex_Encoded.IsMatch($props.CommandLine)) {
                            $props.SuspiciousFlags.Add("Anomalous CommandLine (Script/Encoded)")
                            $props.ATTCKMappings.Add("TA0002: T1059.001")
                        }
                        if ($props.CommandLine -and $Regex_Defense.IsMatch($props.CommandLine)) {
                            $props.SuspiciousFlags.Add("Defense Tampering Attempt")
                            $props.ATTCKMappings.Add("TA0005: T1562.001")
                        }
                        if ($props.Image -and $SpecificRMMTools -contains $props.Image) {
                            $props.SuspiciousFlags.Add("RMM Tool Detected")
                            $props.ATTCKMappings.Add("TA0011: T1219")
                        }
                    }
                    "NetworkConnect" {
                        $NetworkConnectEvents++
                        $dst = if ($props.DestinationHostname) { $props.DestinationHostname } else { $props.DestinationIp }
                        $port = $props.DestinationPort
                        $protocol = if ($eventDataHash['Protocol']) { $eventDataHash['Protocol'] } else { 'TCP/UDP' }
                        $props.Details = "Dest: $dst Port: $port Protocol: $protocol"

                        if ($props.DestinationHostname -and (Is-AnomalousDomain $props.DestinationHostname)) {
                            $props.SuspiciousFlags.Add("High Entropy Domain (Network)")
                            $props.ATTCKMappings.Add("TA0011: T1568.002")
                        }

                        $isOutbound = $false
                        if ($props.DestinationIp) {
                            if (-not $Regex_InternalIP.IsMatch($props.DestinationIp)) {
                                $isOutbound = $true
                            }
                        }

                        if ($isOutbound -and $dst -and $port) {
                            $OutboundNetEvents++
                            $key = "$($props.DestinationIp):$port"
                            if (-not $connectionHistory.ContainsKey($key)) {
                                $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                            }

                            # Ignore burst packets sent within 500ms of the initial connection
                            $isNewPing = $true
                            if ($lastPingTime.ContainsKey($key)) {
                                if (($props.Timestamp - $lastPingTime[$key]).TotalMilliseconds -lt 500) {
                                    $isNewPing = $false
                                }
                            }

                            if ($isNewPing) {
                                $connectionHistory[$key].Enqueue($props.Timestamp)
                                $lastPingTime[$key] = $props.Timestamp
                            }

                            while ($connectionHistory[$key].Count -gt 0 -and $connectionHistory[$key].Peek() -lt $now.AddMinutes(-$BeaconWindowMinutes)) {
                                [void]$connectionHistory[$key].Dequeue()
                            }

                            if (-not $flowMetadata.ContainsKey($key)) {
                                $flowMetadata[$key] = @{
                                    packet_sizes = [System.Collections.Generic.List[int]]::new()
                                    dst_ips      = [System.Collections.Generic.List[string]]::new()
                                    domain       = $dst
                                    image        = $props.Image
                                }
                            }
                            if ($props.DestinationIp) {
                                $flowMetadata[$key].dst_ips.Add($props.DestinationIp)
                                if ($flowMetadata[$key].dst_ips.Count -gt 2500) { $flowMetadata[$key].dst_ips.RemoveRange(0, 500) }
                            }

                            $size = $eventDataHash['Size']
                            if (-not $size) { $size = $eventDataHash['BytesSent'] }
                            if (-not $size) { $size = $eventDataHash['Length'] }
                            if ($size -and [int]::TryParse($size, [ref]$null)) {
                                $flowMetadata[$key].packet_sizes.Add([int]$size)
                                if ($flowMetadata[$key].packet_sizes.Count -gt 2500) { $flowMetadata[$key].packet_sizes.RemoveRange(0, 500) }
                            }
                        }

                        if ($DebugCounter -lt 30) {
                            $DebugCounter++
                            Write-Host "[Debug] NetConnect -> DestIp: $($props.DestinationIp) | SourceIp: $($props.SourceIp) | Outbound: $isOutbound" -ForegroundColor Yellow
                        }
                    }
                    "ImageLoad" {
                        $props.Details = "Loaded: $($eventDataHash['ImageLoaded'])"
                        if ($props.Image -and $eventDataHash['ImageLoaded'] -and $Regex_SysPaths.IsMatch($props.Image) -and -not $Regex_SysPaths.IsMatch($eventDataHash['ImageLoaded'])) {
                            $props.SuspiciousFlags.Add("Anomalous DLL Load (Sideloading Risk)")
                            $props.ATTCKMappings.Add("TA0005: T1574.002")
                        }
                    }
                    "FileCreate" {
                        $props.Details = "Created: $($eventDataHash['TargetFilename'])"
                        if ($eventDataHash['TargetFilename'] -match '\.ps1$|\.vbs$|\.bat$|\.exe$') {
                            $props.SuspiciousFlags.Add("Executable/Script File Created")
                            $props.ATTCKMappings.Add("TA0002: T1059")
                        }
                    }
                    "RegistryEvent" {
                        $details = "Key: $($eventDataHash['TargetObject'])"
                        if ($eventDataHash['Details']) { $details += " Value: $($eventDataHash['Details'])" }
                        $props.Details = $details
                        if ($eventDataHash['TargetObject'] -match 'Run|RunOnce|Services|Startup') {
                            $props.SuspiciousFlags.Add("Persistence Registry Key Modified")
                            $props.ATTCKMappings.Add("TA0003: T1547.001")
                        }
                    }
                    "DnsQuery" {
                        $props.Details = "Query: $($props.DestinationHostname) Result: $($eventDataHash['QueryResults'])"
                        $qName = $props.DestinationHostname
                        if (Is-AnomalousDomain $qName) {
                            $props.SuspiciousFlags.Add("DGA DNS Query Detected")
                            $props.ATTCKMappings.Add("TA0011: T1568.002")
                        }
                        if ($qName -and $SpecificTLDs -and ($SpecificTLDs | Where-Object { $qName.EndsWith($_) })) {
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

        # Safely trail the ETW memory buffer flush instead of racing the clock
        if ($events) {
            $eventArr = @($events)
            if ($eventArr.Count -gt 0) {
                $lastQueryTime = $eventArr[-1].TimeCreated.AddMilliseconds(1)
            }
        }

        # Packet size collection from pktmon
        $pktmonRaw = pktmon list -c 2>&1 | Out-String
        $sizeMatches = [regex]::Matches($pktmonRaw, 'outbound.*?\s(\d+)\s+bytes', 'IgnoreCase')
        if ($sizeMatches.Count -gt 0) {
            $size = [int]$sizeMatches[0].Groups[1].Value
            if ($size -gt 0) {
                foreach ($key in $flowMetadata.Keys) {
                    $flowMetadata[$key].packet_sizes.Add($size)
                    if ($flowMetadata[$key].packet_sizes.Count -gt 2500) {
                        $flowMetadata[$key].packet_sizes.RemoveRange(0, 500)
                    }
                }
            }
        }

        # Cleanup expired flows
        $deadKeys = @()
        foreach ($k in $connectionHistory.Keys) {
            if ($connectionHistory[$k].Count -eq 0 -or $connectionHistory[$k].Peek() -lt $now.AddMinutes(-$BeaconWindowMinutes)) {
                $deadKeys += $k
            }
        }
        foreach ($dk in $deadKeys) {
            $connectionHistory.Remove($dk) | Out-Null
            $flowMetadata.Remove($dk) | Out-Null
        }

        # ML batch processing
        if (($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {
            $payload = @{}
            foreach ($key in $connectionHistory.Keys) {
                $q = $connectionHistory[$key]
                if ($q.Count -ge $MinSamplesForML) {
                    $meta = $flowMetadata[$key]
                    $arr = $q.ToArray()
                        $intervals = @()
                        # Calculate the time difference (delta) between consecutive pings
                        for ($i = 1; $i -lt $arr.Count; $i++) {
                            $intervals += [Math]::Round(($arr[$i] - $arr[$i-1]).TotalSeconds, 2)
                        }
                    $payload[$key] = @{
                        intervals         = $intervals
                        dst_ips           = $meta.dst_ips
                        domain            = $meta.domain
                        packet_sizes      = $meta.packet_sizes
                        payload_entropies = @()
                    }
                }
            }

            if ($payload.Count -gt 0) {
                $jsonPayload = $payload | ConvertTo-Json -Depth 6 -Compress
                $pyIn.WriteLine($jsonPayload)

                $pyResponse = $null
                $timeout = 30
                while ($timeout-- -gt 0 -and -not $pyProcess.HasExited) {
                    if (-not $pyOut.EndOfStream) {
                        $pyResponse = $pyOut.ReadLine()
                        if ($pyResponse) { break }
                    }
                    Start-Sleep -Milliseconds 100
                }

                if ($pyResponse) {
                    $mlResults = $pyResponse | ConvertFrom-Json
                    if ($mlResults -and $mlResults.PSObject) {
                        foreach ($alertKey in $mlResults.PSObject.Properties.Name) {
                            $alertData = $mlResults.$alertKey
                            if ($alertData.alert) {
                                Write-Host "[ML ALERT] $alertKey - $($alertData.alert) (Confidence: $($alertData.confidence))" -ForegroundColor Red
                                $dataBatch.Add([PSCustomObject]@{
                                    EventType = "ML_Beacon_Detection"
                                    Timestamp = $now
                                    Destination = $alertKey
                                    Image = $flowMetadata[$alertKey].image
                                    SuspiciousFlags = $alertData.alert
                                    Confidence = $alertData.confidence
                                })
                            }
                        }
                    }
                }
            }
            $lastMLRunTime = $now
            $mlBatchCount++
        }

        # Output batch to JSONL
        if ($dataBatch.Count -gt 0) {
            foreach ($obj in $dataBatch) {
                $obj | ConvertTo-Json -Compress | Add-Content $OutputPath -Encoding UTF8
            }
            $dataBatch.Clear()
        }

        # Log rotation
        if (Test-Path $OutputPath) {
            $logFile = Get-Item $OutputPath
            if ($logFile.Length -gt 50MB) {
                Move-Item -Path $OutputPath -Destination "$OutputPath.bak" -Force
            }
        }

        # Rolling pipeline status
        $activeFlows = $connectionHistory.Keys.Count
        $currentBatchCount = if ($events) { @($events).Count } else { 0 }
        $statusLine = "[Status] Batch: $currentBatchCount | Outbound Net: $OutboundNetEvents | Active flows: $activeFlows | ML batches: $mlBatchCount"
        Write-Host "`r$statusLine" -NoNewline -ForegroundColor DarkGray

        Start-Sleep -Seconds $IntervalSeconds
    }
} finally {
    if ($pyProcess -and -not $pyProcess.HasExited) {
        $pyIn.WriteLine("QUIT")
        $pyProcess.WaitForExit(2000)
        if (-not $pyProcess.HasExited) {
            $pyProcess.Kill()
        }
    }
}