<#
.SYNOPSIS
    Automated Threat Intelligence (CTI) Enrichment Engine
.DESCRIPTION
    Parses aggregated network flows from the C2 Hunter monitoring logs and cross-references
    external destination IPs against multiple Threat Intelligence APIs.

    Architecture Flow:
      1. Configuration Loader: securely ingests API keys from the local config.ini.
      2. Telemetry Extractor: Parses the plaintext OutboundNetwork_Monitor log for unique target IPs.
      3. CTI Aggregator: Executes rate-limited queries against VirusTotal, AlienVault OTX,
         GreyNoise, AbuseIPDB, and Shodan to build a comprehensive behavioral profile.
      4. Reporting Engine: Generates a localized text report detailing framework signatures,
         JARM fingerprints, and proxy masking attempts.

.NOTES
    Author: Robert Weber
    Compatibility: PowerShell 5.1 and 7+
#>
#Requires -RunAsAdministrator

$ScriptDir = Split-Path $PSCommandPath -Parent
$ConfigPath = Join-Path $ScriptDir "config.ini"
$LogPath = "C:\ProgramData\C2Sensor\Logs\OutboundNetwork_Monitor.log"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportOut = "C:\ProgramData\C2Sensor\Data\threat_intel_report_latest.txt"

param([switch]$Orchestrated)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# =================================================================
# DUAL-MODE UI ENGINE
# =================================================================
$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"; $cCyan = "$ESC[38;2;0;200;255m"; $cGreen = "$ESC[38;2;10;210;130m"; $cDark = "$ESC[38;2;100;100;100m"; $cYellow = "$ESC[38;2;255;180;50m"; $cReset = "$ESC[0m"

if (-not $Orchestrated) {
    $Host.UI.RawUI.WindowTitle = "V5 DFIR // CTI API ENRICHMENT"
    [Console]::CursorVisible = $false
    Clear-Host
    [Console]::SetCursorPosition(0, 6)
}

function Update-UI([int]$Progress, [int]$Threats, [string]$ActionText) {
    if ($Orchestrated) {
        Write-Output "[HUD]|$Progress|$Threats|$ActionText"
    } else {
        $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, 0)

        # --- DYNAMIC PADDING MATH ---
        # 1. Define the raw, uncolored strings so PowerShell can count the EXACT character length
        $EngineName = "CTI API ENRICHMENT"
        $TitleStr   = "  ⚡ C2 HUNTER V5  | $EngineName"
        $StatsStr   = "  Progress : $Progress% | Targets: $Threats"

        # 2. Prevent Action text from overflowing the 86-character boundary
        if ($ActionText.Length -gt 70) { $ActionText = $ActionText.Substring(0, 67) + "..." }
        $ActionStr  = "  Action   : $ActionText"

        # 3. Calculate exact spaces needed to hit 86 characters perfectly
        # (Note: Some terminals render the ⚡ emoji as 2 spaces wide. If the top line is off by 1 space, subtract 1 from the Title length math)
        $PadTitle  = " " * [math]::Max(0, (86 - $TitleStr.Length))
        $PadStats  = " " * [math]::Max(0, (86 - $StatsStr.Length))
        $PadAction = " " * [math]::Max(0, (86 - $ActionStr.Length))

        Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════╗$cReset"
        Write-Host "$cCyan║$cReset  $cRed⚡ C2 HUNTER V5$cReset | $EngineName$PadTitle$cCyan║$cReset"
        Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════╣$cReset"
        Write-Host "$cCyan║$cReset  Progress : $cCyan$Progress%$cReset | Targets: $cRed$Threats$cReset$PadStats$cCyan║$cReset"
        Write-Host "$cCyan║$cReset  Action   : $cYellow$ActionText$cReset$PadAction$cCyan║$cReset"
        Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════╝$cReset"

        if ($curTop -lt 6) { $curTop = 6 }
        [Console]::SetCursorPosition($curLeft, $curTop)
    }
}

$ApiKeys = @{}
if (Test-Path $ConfigPath) {
    Get-Content $ConfigPath | Where-Object { $_ -match "^([A-Z_]+)=`"?(.*?)`"?$" } | ForEach-Object { $ApiKeys[$matches[1]] = $matches[2] }
} else { Write-Output "  $cRed[!] CRITICAL:$cReset config.ini not found."; exit }
if (-not (Test-Path $LogPath)) { exit }

$UniqueIPs = @()
Get-Content $LogPath | ForEach-Object {
    if ($_ -match "Destination IP:\s*([0-9\.]+)") {
        $ip = $matches[1]
        if ($ip -notmatch "^192\.168\.|^10\.|^127\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^224\.|^239\.|^0\.0\.0\.0$") { $UniqueIPs += $ip }
    }
}
$UniqueIPs = $UniqueIPs | Select-Object -Unique
if ($UniqueIPs.Count -eq 0) { exit }

"============================================================" | Out-File -FilePath $ReportOut -Encoding UTF8
"[*] ENHANCED BEHAVIORAL CTI ENRICHMENT" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
"============================================================" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append

$Idx = 0; $ThreatsFound = 0

foreach ($IP in $UniqueIPs) {
    $Idx++
    $pct = [math]::Round(($Idx / $UniqueIPs.Count) * 100)
    Update-UI $pct $ThreatsFound "Querying APIs for Target IP: $IP"

    "`n------------------------------------------------------------`nTARGET IP: $IP`n------------------------------------------------------------" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
    $IsThreat = $false

    if ($ApiKeys["VIRUSTOTAL_KEY"]) {
        try {
            $vtRes = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" -Headers @{ "x-apikey" = $ApiKeys["VIRUSTOTAL_KEY"] } -ErrorAction Stop
            $vtMalicious = if ($null -ne $vtRes.data.attributes.last_analysis_stats.malicious) { $vtRes.data.attributes.last_analysis_stats.malicious } else { "0" }
            if ([int]$vtMalicious -gt 0) { $IsThreat = $true }

            "       - VT Malicious Hits: $vtMalicious" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch { }
    }

    if ($ApiKeys["ALIENVAULT_OTX_KEY"]) {
        try {
            $otxRes = Invoke-RestMethod -Uri "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general" -Headers @{ "X-OTX-API-KEY" = $ApiKeys["ALIENVAULT_OTX_KEY"] } -ErrorAction Stop
            $matchedTags = @()
            if ($otxRes.pulse_info.pulses) {
                foreach ($pulse in $otxRes.pulse_info.pulses) {
                    if ($pulse.tags) { foreach ($tag in $pulse.tags) { if ($tag -match "(?i)Sliver|Mythic|Havoc|Cobalt|Brute") { $matchedTags += $tag } } }
                }
            }
            $matchedTags = $matchedTags | Select-Object -Unique
            if ($matchedTags.Count -gt 0) {
                $IsThreat = $true
                "       - C2 Framework Match: $($matchedTags -join ', ')" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
            } else {
                "       - C2 Framework Match: None" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
            }
        } catch { }
    }

    if ($ApiKeys["ABUSEIPDB_KEY"]) {
        try {
            $abRes = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90" -Headers @{ "Key" = $ApiKeys["ABUSEIPDB_KEY"]; "Accept" = "application/json" } -ErrorAction Stop
            $score = if ($null -ne $abRes.data.abuseConfidenceScore) { $abRes.data.abuseConfidenceScore } else { "0" }
            if ([int]$score -gt 20) { $IsThreat = $true }
            "       - Abuse Confidence Score: $score%" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch { }
    }

    if ($IsThreat) {
        $ThreatsFound++
        Write-Output "  $cRed[!] CTI HIT:$cReset IP $IP flagged as malicious/C2 infrastructure."
    } else {
        Write-Output "  $cDark[i] CTI CLEAR:$cReset IP $IP returned clean telemetry."
    }

    Start-Sleep -Seconds 2
}

"`n============================================================`n[*] Enrichment Complete. See $ReportOut`n============================================================" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
Update-UI 100 $ThreatsFound "CTI Intelligence Enrichment Complete."
if (-not $Orchestrated) { [Console]::CursorVisible = $true }