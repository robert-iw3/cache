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

# ====================== CONFIGURATION & INITIALIZATION ======================
$ScriptDir = Split-Path $PSCommandPath -Parent
$ConfigPath = Join-Path $ScriptDir "config.ini"
$LogPath = "C:\Temp\OutboundNetwork_Monitor.log"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportOut = Join-Path $ScriptDir "threat_intel_report_$Timestamp.txt"

# Enforce TLS 1.2+ for secure API communication in legacy PowerShell 5.1 environments
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[*] ENHANCED BEHAVIORAL CTI ENRICHMENT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Parses the INI configuration file to securely extract API keys into a hash table
$ApiKeys = @{}
if (Test-Path $ConfigPath) {
    Get-Content $ConfigPath | Where-Object { $_ -match "^([A-Z_]+)=`"?(.*?)`"?$" } | ForEach-Object {
        $ApiKeys[$matches[1]] = $matches[2]
    }
} else {
    Write-Host "[!] Error: config.ini not found in $ScriptDir" -ForegroundColor Red
    exit
}

if (-not (Test-Path $LogPath)) {
    Write-Host "[!] Error: Outbound monitor log not found at $LogPath" -ForegroundColor Red
    exit
}

# ====================== TELEMETRY EXTRACTION ======================
# Extracts all unique Destination IPs from the aggregated flow log, bypassing local/broadcast addresses.
$UniqueIPs = @()
Get-Content $LogPath | ForEach-Object {
    if ($_ -match "Destination IP:\s*([0-9\.]+)") {
        $ip = $matches[1]
        if ($ip -notmatch "^192\.168\.|^10\.|^127\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^224\.|^239\.|^0\.0\.0\.0$") {
            $UniqueIPs += $ip
        }
    }
}
$UniqueIPs = $UniqueIPs | Select-Object -Unique

if ($UniqueIPs.Count -eq 0) {
    Write-Host "[+] No remote external IPs found to investigate." -ForegroundColor Green
    exit
}

"============================================================" | Out-File -FilePath $ReportOut -Encoding UTF8
"[*] ENHANCED BEHAVIORAL CTI ENRICHMENT" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
"============================================================" | Out-File -FilePath $ReportOut -Encoding UTF8 -Append

# ====================== CTI AGGREGATION LOOP ======================
foreach ($IP in $UniqueIPs) {
    $header = "`n------------------------------------------------------------`nTARGET IP: $IP`n------------------------------------------------------------"
    Write-Host $header -ForegroundColor Yellow
    $header | Out-File -FilePath $ReportOut -Encoding UTF8 -Append

    # 1. VirusTotal: Reputation and Categorization
    if ($ApiKeys["VIRUSTOTAL_KEY"]) {
        Write-Host "    -> Querying VirusTotal..." -ForegroundColor Gray
        try {
            $vtHeaders = @{ "x-apikey" = $ApiKeys["VIRUSTOTAL_KEY"] }
            $vtRes = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" -Headers $vtHeaders -ErrorAction Stop

            $vtMalicious = $vtRes.data.attributes.last_analysis_stats.malicious
            $vtMalicious = if ($null -ne $vtMalicious) { $vtMalicious } else { "0" }

            $vtCats = "None"
            if ($vtRes.data.attributes.categories) {
                $cats = @()
                foreach ($prop in $vtRes.data.attributes.categories.PSObject.Properties) { $cats += $prop.Value }
                if ($cats.Count -gt 0) { $vtCats = $cats -join ", " }
            }

            $outVt1 = "       - VT Malicious Hits: $vtMalicious"
            $outVt2 = "       - Behavior/Categories: $vtCats"
            Write-Host $outVt1; Write-Host $outVt2
            $outVt1, $outVt2 | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch { Write-Host "       [!] VirusTotal Query Failed: $($_.Exception.Message)" -ForegroundColor DarkRed }
    }

    # 2. AlienVault OTX: Framework Identification via Pulse Tagging
    if ($ApiKeys["ALIENVAULT_OTX_KEY"]) {
        Write-Host "    -> Querying AlienVault OTX..." -ForegroundColor Gray
        try {
            $otxHeaders = @{ "X-OTX-API-KEY" = $ApiKeys["ALIENVAULT_OTX_KEY"] }
            $otxRes = Invoke-RestMethod -Uri "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general" -Headers $otxHeaders -ErrorAction Stop

            $frameworkRegex = "(?i)Sliver|Mythic|Havoc|Empire|Cobalt|Metasploit|Brute|Deery|Nighthawk|Covenant|Manjusaka|PoshC2|Merlin|SharpC2|Koadic|Viper|S3cret|Godzilla|Behinder|Chisel|Ligolo|Insecure|Venom|Xray"
            $matchedTags = @()

            if ($otxRes.pulse_info -and $otxRes.pulse_info.pulses) {
                foreach ($pulse in $otxRes.pulse_info.pulses) {
                    if ($pulse.tags) {
                        foreach ($tag in $pulse.tags) {
                            if ($tag -match $frameworkRegex) { $matchedTags += $tag }
                        }
                    }
                }
            }

            $matchedTags = $matchedTags | Select-Object -Unique
            if ($matchedTags.Count -gt 0) {
                $otxOut = "       - C2 Framework Match: $($matchedTags -join ', ')"
            } else {
                $pulseCount = if ($otxRes.pulse_info.count) { $otxRes.pulse_info.count } else { "0" }
                $otxOut = "       - C2 Framework Match: No specific framework match (Associated Pulses: $pulseCount)"
            }

            Write-Host $otxOut
            $otxOut | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch { Write-Host "       [!] OTX Query Failed: $($_.Exception.Message)" -ForegroundColor DarkRed }
    }

    # 3. AbuseIPDB: Community Confidence Scoring
    if ($ApiKeys["ABUSEIPDB_KEY"]) {
        Write-Host "    -> Querying AbuseIPDB..." -ForegroundColor Gray
        try {
            $abHeaders = @{ "Key" = $ApiKeys["ABUSEIPDB_KEY"]; "Accept" = "application/json" }
            $abRes = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90" -Headers $abHeaders -ErrorAction Stop
            $score = if ($null -ne $abRes.data.abuseConfidenceScore) { $abRes.data.abuseConfidenceScore } else { "0" }

            $abOut = "       - Abuse Confidence Score: $score%"
            Write-Host $abOut
            $abOut | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch { Write-Host "       [!] AbuseIPDB Query Failed: $($_.Exception.Message)" -ForegroundColor DarkRed }
    }

    # 4. GreyNoise: Proxies, VPNs, and Internet Scanning Noise Masking
    if ($ApiKeys["GREYNOISE_KEY"]) {
        Write-Host "    -> Querying GreyNoise..." -ForegroundColor Gray
        try {
            $gnHeaders = @{ "key" = $ApiKeys["GREYNOISE_KEY"] }
            $gnRes = Invoke-RestMethod -Uri "https://api.greynoise.io/v3/community/$IP" -Headers $gnHeaders -ErrorAction Stop

            $gnVpn = if ($null -ne $gnRes.vpn) { $gnRes.vpn } else { "False" }
            $gnTor = if ($null -ne $gnRes.tor) { $gnRes.tor } else { "False" }
            $gnClass = if ($null -ne $gnRes.classification) { $gnRes.classification } else { "Unknown" }

            $outGn1 = "       - GreyNoise Class: $gnClass"
            $outGn2 = "       - Proxy Masking: VPN:$gnVpn | TOR:$gnTor"
            Write-Host $outGn1; Write-Host $outGn2
            $outGn1, $outGn2 | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch {
            # GreyNoise returns 404 for IPs they haven't observed scanning the internet. Handled gracefully.
            $outGn = "       - GreyNoise Class: Unobserved (Not currently scanning the internet)"
            Write-Host $outGn
            $outGn | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        }
    }

    # 5. Shodan: JARM Fingerprints and Infrastructure Products
    if ($ApiKeys["SHODAN_KEY"]) {
        Write-Host "    -> Querying Shodan..." -ForegroundColor Gray
        try {
            $shRes = Invoke-RestMethod -Uri "https://api.shodan.io/shodan/host/$IP?key=$($ApiKeys['SHODAN_KEY'])" -ErrorAction Stop

            $jarmTags = @()
            if ($shRes.tags) {
                foreach ($tag in $shRes.tags) { if ($tag -match "jarm") { $jarmTags += $tag } }
            }
            $jarmOut = if ($jarmTags.Count -gt 0) { $jarmTags -join ", " } else { "None" }

            $products = @()
            if ($shRes.data) {
                foreach ($item in $shRes.data) { if ($item.product) { $products += $item.product } }
            }
            $products = $products | Select-Object -Unique
            $prodOut = if ($products.Count -gt 0) { $products -join ", " } else { "None" }

            $outSh1 = "       - JARM TLS Fingerprint: $jarmOut"
            $outSh2 = "       - Fingerprinted Products: $prodOut"
            Write-Host $outSh1; Write-Host $outSh2
            $outSh1, $outSh2 | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        } catch {
            # Shodan returns 404 for IPs not in their scan database.
            $outSh = "       - Shodan: No infrastructure records found."
            Write-Host $outSh
            $outSh | Out-File -FilePath $ReportOut -Encoding UTF8 -Append
        }
    }

    # Rate limiting delay to respect community API tiers
    Start-Sleep -Seconds 2
}

$footer = "`n============================================================`n[*] Enrichment Complete. See $ReportOut`n============================================================"
Write-Host $footer -ForegroundColor Cyan
$footer | Out-File -FilePath $ReportOut -Encoding UTF8 -Append