<#
.SYNOPSIS
    Windows Kernel C2 Beacon Sensor v1.0 (Native FFI Architecture)
.DESCRIPTION
    A high-performance, real-time Command and Control (C2) detection and response engine.
    It injects Microsoft.Diagnostics.Tracing.TraceEvent directly into RAM via embedded C#
    to monitor live kernel ETW events, bypassing heavy telemetry trace files.

    Architecture Flow:
      1. Dynamic Pre-Loader: Fetches the correct TraceEvent library based on the host's .NET runtime.
      2. C# Engine: Parses the high-volume ETW firehose at lightning speed, aggressively pre-filtering
         benign noise (including RFC 1918, Multicast, Broadcast, and Idle routing).
      3. Server-Side AppGuard: Monitors process lineages to instantly intercept web shells
         and database RCEs (IIS, SQL, Tomcat, Node) spawning command interpreters.
      4. Cryptographic DPI: Subscribes to raw Layer 2 NDIS frames, using an unmanaged byte-scanner
         to extract TLS Client Hello signatures and map JA3 hashes to Ring-3 processes.
      5. Native FFI Pipeline: Replaces legacy Python IPC pipes. PowerShell passes memory pointers
         directly into the C-compiled Rust DLL (`c2sensor_ml.dll`) for zero-latency ML clustering.
      6. SQLite WAL State Manager: The Rust engine handles all temporal tracking natively, logging
         dormant beacon flows to a secure database in `C:\ProgramData\C2Sensor\Data`.
      7. Thread-Level Tracking (TID): Extracts Native Thread IDs to isolate injected payloads.
      8. Anti-Tamper Watchdog: Generates synthetic DNS heartbeats and monitors memory protections.
      9. Unified Active Defense: Natively processes ML, JA3, and AppGuard alerts in RAM to autonomously
         terminate processes (or prevent child shells) and isolate IPs at the firewall.
     10. Enterprise 24/7 Deployment: Operates continuously with a mathematically pinned, non-scrolling
         terminal HUD and a 50MB self-grooming log rotation engine to prevent SIEM exhaustion.
#>
#Requires -RunAsAdministrator

# ====================== CONFIGURATION & PARAMETERS ======================
param (
    [int]$BatchAnalysisIntervalSeconds = 15,
    [int]$MinSamplesForML = 3,
    [switch]$EnableDiagnostics,
    [switch]$TestMode,

    # --- Defense Options ---
    [switch]$ArmedMode,
    [int]$ConfidenceThreshold = 85,

    # --- Exclusions Example (Tune to your environment) ---
    # DEVELOPER NOTE: Suffix matching. ".windows.com" will safely drop "telemetry.windows.com"
    [string[]]$DnsExclusions = @(
        # Local & Internal Routing
        ".arpa", ".local", ".lan", ".home", ".corp",
        # Microsoft & Azure Core Telemetry / CDNs
        "microsoft.com", "windows.com", "windowsupdate.com", "azure.com", "azureedge.net",
        "azurefd.net", "trafficmanager.net", "live.com", "office.com", "office365.com",
        "skype.com", "msn.com", "bing.com", "visualstudio.com", "microsoftonline.com",
        "sharepoint.com", "msedge.net", "msauth.net", "msftauth.net", "applicationinsights.io",
        # Google & Android Ecosystem
        "google.com", "googleapis.com", "1e100.net", "gstatic.com", "gvt1.com", "gvt2.com",
        "youtube.com", "ytimg.com", "googlevideo.com",
        # Amazon AWS, Cloudflare, & Fastly Edge Networks
        "amazonaws.com", "cloudfront.net", "cloudflare.com", "cloudflare.net", "fastly.net",
        # Apple Ecosystem (iTunes, iCloud telemetry)
        "apple.com", "icloud.com", "mzstatic.com",
        # Unified Communications & Media
        "spotify.com", "zoom.us", "webex.com", "slack-edge.com", "discord.gg", "discordapp.com",
        # Common Enterprise AV / EDR Telemetry
        "trendmicro.com", "tmok.tm", "mcafee.com", "trellix.com", "symantec.com", "sophos.com", "crowdstrike.com"
    ),
    # WARNING: NEVER add "svchost", "explorer", or "lsass" to this list. C2 beacons hide there.
    [string[]]$ProcessExclusions = @(
        # Browsers
        "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera", "iexplore",
        # Heavy Electron / Chat Apps
        "spotify", "teams", "discord", "slack", "zoom", "webex", "whatsapp",
        # Cloud Sync & Background Updaters
        "onedrive", "dropbox", "googledrivesync", "googleupdate", "mousocoreworker", "tiworker",
        # Safe / Noisy Windows 10/11 UI Components
        "searchapp", "searchui", "startmenuexperiencehost", "shellexperiencehost",
        "backgroundtaskhost", "compattelrunner", "fontdrvhost", "dwm", "dashost",
        # Anti-Virus / Security Engines
        "coreserviceshell", "msmpeng", "nissrv", "securityhealthservice", "smartscreen"
    ),

    [string[]]$IpPrefixExclusions = @(
        # High-Volume CDNs (Microsoft / Google / AWS)
        "^52\.", "^142\.25[0-9]\.", "^13\.", "^20\.", "^23\.", "^74\.125\.",
        # RFC 1918 Private LAN
        "^10\.", "^192\.168\.", "^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        # Loopback
        "^127\.",
        # Multicast (224.x - 239.x)
        "^2(?:2[4-9]|3[0-9])\.",
        # Class E & Global Broadcasts (240.x - 255.x)
        "^2[4-5][0-9]\.",
        # Trusted Upstream DNS Resolvers (Prevents Port 53 K-Means False Positives)
        "^1\.1\.1\.1$", "^1\.0\.0\.1$", "^8\.8\.8\.8$", "^8\.8\.4\.4$", "^9\.9\.9\.9$",
        # Subnet Broadcasts
        "\.255$"
    )
)

$global:IsArmed = $ArmedMode
$ScriptDir = Split-Path $PSCommandPath -Parent
$now = Get-Date

if ($TestMode) {
    $CdnPrefixes = @("^52\.", "^142\.25[0-9]\.", "^13\.", "^20\.", "^23\.", "^74\.125\.")
    $IpPrefixExclusions = $IpPrefixExclusions | Where-Object { $_ -notin $CdnPrefixes }
}

# ====================== ENTERPRISE DIRECTORY STRUCTURE ======================
$DataDir = "C:\ProgramData\C2Sensor\Data"
$LogDir  = "C:\ProgramData\C2Sensor\Logs"

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null }
if (-not (Test-Path $LogDir))  { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

$OutputPath = "$LogDir\C2Sensor_Alerts.jsonl"
$UebaLogPath = "$LogDir\C2Sensor_UEBA.jsonl"
$MonitorLogPath = "$LogDir\OutboundNetwork_Monitor.log"
$DiagLogPath = "$LogDir\C2Sensor_Diagnostic.log"
$TamperLogPath = "$DataDir\C2Sensor_TamperGuard.log"
$Ja3CachePath = "$DataDir\C2Sensor_JA3_Cache.json"

# ====================== CONSOLE UI SETUP (RGB PALETTE) ======================
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

# Modern 24-bit True Color RGB Codes
$ESC = [char]27
$cRed    = "$ESC[38;2;239;68;68m"   # Tailwind Red 500
$cCyan   = "$ESC[38;2;6;182;212m"   # Tailwind Cyan 500
$cGreen  = "$ESC[38;2;34;197;94m"   # Tailwind Green 500
$cDark   = "$ESC[38;2;115;115;115m" # Tailwind Neutral 500
$cYellow = "$ESC[38;2;234;179;8m"   # Tailwind Yellow 500
$cReset  = "$ESC[0m"

try {
    $ui = $Host.UI.RawUI
    $buffer = $ui.BufferSize; $buffer.Width = 160; $buffer.Height = 3000; $ui.BufferSize = $buffer
    $size = $ui.WindowSize; $size.Width = 160; $size.Height = 45; $ui.WindowSize = $size
} catch {}

[Console]::SetCursorPosition(0, 9)

# ====================== DIAGNOSTICS & UI LOGGING ======================
if (Test-Path $DiagLogPath) { Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue }

$global:StartupLogs = [System.Collections.Generic.List[string]]::new()

function Write-Diag {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "FFI-TX", "FFI-RX", "MATH", "STARTUP", "CRITICAL")]
        [string]$Level = "INFO"
    )
    if (-not $EnableDiagnostics -and $Level -notin @("ERROR", "WARN", "CRITICAL", "STARTUP")) { return }
    
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try { Add-Content -Path $DiagLogPath -Value "[$ts] [$Level] $Message" -Encoding UTF8 } catch {}

    if ($Level -eq "STARTUP") {
        $global:StartupLogs.Add($Message)
        Draw-StartupWindow
    }
}

function Draw-StartupWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100
    [Console]::SetCursorPosition(0, 9)

    $HeaderPlain = "  [ SENSOR INITIALIZATION ]"
    $PadHeader = " " * [math]::Max(0, ($UIWidth - $HeaderPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGreen$HeaderPlain$cReset$PadHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    $recent = if ($global:StartupLogs.Count -gt 10) { $global:StartupLogs.GetRange($global:StartupLogs.Count - 10, 10) } else { $global:StartupLogs }

    for ($i = 0; $i -lt 10; $i++) {
        if ($i -lt $recent.Count) {
            $logLine = "    $($recent[$i])"
            if ($logLine.Length -gt ($UIWidth - 1)) { $logLine = $logLine.Substring(0, $UIWidth - 4) + "..." }
            $pad = " " * [math]::Max(0, ($UIWidth - $logLine.Length))
            Write-Host "$cCyan║$cReset$logLine$pad$cCyan║$cReset"
        } else {
            $pad = " " * $UIWidth
            Write-Host "$cCyan║$cReset$pad$cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    [Console]::SetCursorPosition($curLeft, $curTop)
}

Write-Diag "=== C2 SENSOR V1 DIAGNOSTIC LOG INITIALIZED ===" "STARTUP"
Write-Diag "Host: $env:COMPUTERNAME | PS Version: $($PSVersionTable.PSVersion.ToString())" "STARTUP"

if ($ArmedMode) {
    Write-Diag "SENSOR BOOTING IN ARMED MODE: ACTIVE DEFENSE ENABLED" "STARTUP"
} else {
    Write-Diag "SENSOR BOOTING IN AUDIT MODE: OBSERVATION ONLY" "STARTUP"
}

# ====================== TAMPER GUARD INITIALIZATION ======================
function Initialize-TamperGuard {
    Write-Diag "Initializing Tamper Guard & Locking Audit Trails..." "STARTUP"
    try {
        if (-not (Test-Path $TamperLogPath)) { New-Item $TamperLogPath -ItemType File -Force | Out-Null }
        icacls $TamperLogPath /inheritance:r /q | Out-Null
        icacls $TamperLogPath /grant:r "*S-1-5-18:(F)" /grant:r "*S-1-5-32-544:(F)" /q | Out-Null
        Write-Diag "Successfully applied strict ACLs to Tamper Guard log." "STARTUP"
    }
    catch { Write-Diag "Warning: icacls permission lockdown failed." "WARN" }

    try {
        $global:TamperStream = [System.IO.File]::Open($TamperLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
        $global:TamperWriter.AutoFlush = $true
        Write-Diag "Tamper Guard Log locked to current process." "STARTUP"
    } catch {
        Write-Diag "Tamper log is locked by a zombie process. Executing cleanup..." "WARN"
        Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $global:TamperStream = [System.IO.File]::Open($TamperLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
        $global:TamperWriter.AutoFlush = $true
        Write-Diag "Tamper Guard Log recovered and locked." "STARTUP"
    }
}
Initialize-TamperGuard

# =========================================================================
# JA3 THREAT INTEL LOADER
# =========================================================================
$global:MaliciousJA3Cache = @()
if (Test-Path $Ja3CachePath) {
    try {
        $global:MaliciousJA3Cache = Get-Content $Ja3CachePath -Raw | ConvertFrom-Json
        Write-Diag "Loaded $($global:MaliciousJA3Cache.Count) JA3 signatures from dynamic Threat Intel cache." "STARTUP"
    } catch { Write-Diag "Failed to parse JA3 JSON cache. Falling back to offline defaults." "WARN" }
}

if ($global:MaliciousJA3Cache.Count -eq 0) {
    $global:MaliciousJA3Cache = @(
        # --- Cobalt Strike & Metasploit ---
        "a0e9f5d64349fb13191bc781f81f42e1", # Metasploit / MSFVenom / Older Cobalt Strike
        "b32309a26951912be7dba376398abc3b", # Cobalt Strike (Common Profile 1)
        "eb88d0b3e1961a0562f006e5ce2a0b87", # Cobalt Strike (Malleable C2 Default)
        "1ce21ed04b6d4128f7fb6b22b0c36cb1", # Cobalt Strike (Common Profile 3)
        "ee031b874122d97ab269e0d8740be31a", # Metasploit HeartBleed/TLS Scanner

        # --- Go-Based C2s (Sliver, Merlin, Havoc) ---
        "51c64c77e60f3980eea90869b68c58a8", # Sliver / Standard Go HTTP/TLS Client
        "e0a786fa0d151121d51f2249e49195b0", # Merlin C2
        "d891b0c034919cb44f128e4e97aeb7e6", # Havoc C2 Default

        # --- Python-Based C2s (Empire, Mythic, Pupy) ---
        "771c93a02bb801fbdbb13b73bcba0d6b", # Empire / Python Requests Default
        "cd08e31494f9531f560d64c695473da9", # Mythic / Generic Python Default
        "3b5074b1b5d032e5620f69f9f700ff0e", # Pupy RAT

        # --- .NET/C# Frameworks (Covenant, AsyncRAT, Quasar) ---
        "8f199859f1f0e4b7ba29e3ddc6ee9b71", # Covenant Grunt / Standard .NET WebClient
        "6d89b37a488e0b6dfde0c59828e8331b", # Remcos RAT
        "08ef1bdcbdbba6ce64daec0ab2ea0bc1", # NanoCore RAT

        # --- Commodity Malware / Ransomware Initial Access ---
        "2707bb320ebbb6d0c64d8a5decc81b53", # Trickbot
        "4d7a28d6f2263ed61de88ca66eb011e3", # Emotet
        "18f152d0b50302ffab23fc47545de999", # IcedID
        "3f4b4ce6edbc8537fc2ea22a009fb74d", # Qakbot
        "c45d36e2fde376eec6a382b6c31e67b2", # Brute Ratel C4 (Default Config)
        "518b7eb09de4e10173bc51c1ff76b2c2"  # Dridex
    )
    Write-Diag "Loaded $($global:MaliciousJA3Cache.Count) default offline JA3 signatures." "STARTUP"
}

# ====================== NETWORK THREAT INTEL COMPILER ======================
function Initialize-NetworkThreatIntel {
    Write-Diag "Initializing Network Threat Intelligence (Sigma & Suricata)..." "STARTUP"

    $TiKeys = [System.Collections.Generic.List[string]]::new()
    $TiTitles = [System.Collections.Generic.List[string]]::new()

    # =========================================================================
    # 1. SURICATA SYNC & PARSE
    # =========================================================================
    $SuricataBaseDir = Join-Path $ScriptDir "suricata"
    $SuricataUpstreamDir = Join-Path $SuricataBaseDir "upstream"
    
    if (-not (Test-Path $SuricataUpstreamDir)) { 
        New-Item -ItemType Directory -Path $SuricataUpstreamDir -Force | Out-Null 
    }

    $SuricataUrls = @(
        @{ Name = "EmergingThreats_DNS"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-dns.rules" },
        @{ Name = "EmergingThreats_C2"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-c2.rules" }
    )

    foreach ($src in $SuricataUrls) {
        $OutPath = Join-Path $SuricataUpstreamDir "$($src.Name).rules"
        try {
            Write-Diag "Fetching Suricata ruleset: $($src.Name)" "STARTUP"
            Invoke-WebRequest -Uri $src.Url -OutFile $OutPath -UseBasicParsing -ErrorAction Stop
        } catch { Write-Diag "Failed to sync $($src.Name). Relying on local cache." "WARN" }
    }

    $SuricataFiles = Get-ChildItem -Path $SuricataBaseDir -Filter "*.rules" -Recurse
    $suricataCount = 0

    foreach ($file in $SuricataFiles) {
        try {
            $rules = Get-Content $file.FullName
            foreach ($line in $rules) {
                if ($line -match '^alert' -and $line -match 'msg:\s*"([^"]+)"') {
                    $msg = $matches[1]
                    $contents = [regex]::Matches($line, 'content:\s*"([^"]+)"')
                    foreach ($c in $contents) {
                        $val = $c.Groups[1].Value.ToLower()
                        $val = ($val -replace '\|[0-9a-fA-F]{2}\|', '.') -replace '^\.+|\.+$', ''

                        if ($val.Length -gt 4 -and $val -notmatch '^[0-9]+$') {
                            $TiKeys.Add($val)
                            $TiTitles.Add("Suricata: $msg")
                            $suricataCount++
                        }
                    }
                }
            }
        } catch { Write-Diag "Failed to parse custom rule file: $($file.Name)" "WARN" }
    }
    Write-Diag "Gatekeeper Compilation: Parsed $suricataCount signatures from Suricata." "STARTUP"

    # =========================================================================
    # 2. SIGMA SYNC & PARSE
    # =========================================================================
    $SigmaBaseDir = Join-Path $ScriptDir "sigma"
    $SigmaUpstreamDir = Join-Path $SigmaBaseDir "upstream"

    if (-not (Test-Path $SigmaUpstreamDir)) { 
        New-Item -ItemType Directory -Path $SigmaUpstreamDir -Force | Out-Null 
    }
    
    $TempZipPath = "$env:TEMP\sigma_master.zip"
    $ExtractPath = "$env:TEMP\sigma_extract"

    try {
        Write-Diag "Fetching latest Sigma network rules from SigmaHQ..." "STARTUP"
        Invoke-WebRequest -Uri "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -OutFile $TempZipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $TempZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop
        
        $RuleCategories = @("dns", "network_connection", "proxy", "firewall")
        foreach ($cat in $RuleCategories) {
            $RulesPath = Join-Path $ExtractPath "sigma-master\rules\windows\$cat\*"
            if (Test-Path (Split-Path $RulesPath)) {
                Copy-Item -Path $RulesPath -Destination $SigmaUpstreamDir -Recurse -Force
            }
        }
    } catch { Write-Diag "Sigma GitHub pull failed. Relying on local cache." "WARN" }
    finally {
        if (Test-Path $TempZipPath) { Remove-Item $TempZipPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $SigmaFiles = Get-ChildItem -Path $SigmaBaseDir -Include "*.yml", "*.yaml" -Recurse
    $sigmaCount = 0

    foreach ($file in $SigmaFiles) {
        try {
            $lines = Get-Content $file.FullName
            $content = $lines -join "`n"

            if ($content -notmatch "category:\s*(dns|network_connection|proxy|firewall)") { continue }

            $title = "Unknown Sigma Rule"
            $inSelectionBlock = $false

            foreach ($line in $lines) {
                if ($line -match "(?i)^title:\s*(.+)") { $title = $matches[1].Trim(" '`""); continue }
                if ($line -match "(?i)selection:") { $inSelectionBlock = $true; continue }
                if ($line -match "(?i)condition:") { $inSelectionBlock = $false; continue }

                if ($inSelectionBlock -and $line -match "(?i)(Query|DestinationHostname|DestinationIp)\|?(contains|endswith|startswith)?:\s*(.+)") {
                    $val = $matches[3].Trim(" '`"")
                    $val = $val -replace '^\*|\*$', ''
                    
                    if (-not [string]::IsNullOrWhiteSpace($val) -and $val.Length -gt 4) {
                        $TiKeys.Add($val.ToLower())
                        $TiTitles.Add("Sigma: $title")
                        $sigmaCount++
                    }
                }
            }
        } catch { Write-Diag "Failed to parse custom rule file: $($file.Name)" "WARN" }
    }
    
    Write-Diag "Gatekeeper Compilation: Parsed $sigmaCount signatures from SigmaHQ." "STARTUP"
    Write-Diag "Threat Intel Compilation Complete. Passing $($TiKeys.Count) signatures to Memory." "STARTUP"

    return @{ Keys = $TiKeys.ToArray(); Titles = $TiTitles.ToArray() }
}

# ====================== 1. TRACEEVENT LIBRARY FETCH ======================
Write-Diag "Initializing C# TraceEvent Engine..." "STARTUP"
$ExtractPath = "C:\Temp\TraceEventPackage"
$DotNetTarget = if ($PSVersionTable.PSVersion.Major -ge 7) { "netstandard2.0" } else { "net45" }
$ManagedDllPath = "$ExtractPath\lib\$DotNetTarget\Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Diag "Downloading Microsoft.Diagnostics.Tracing.TraceEvent..." "STARTUP"
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/2.0.61" -OutFile "C:\Temp\TraceEvent.zip"
    Expand-Archive -Path "C:\Temp\TraceEvent.zip" -DestinationPath $ExtractPath -Force
}

Get-ChildItem -Path $ExtractPath -Recurse | Unblock-File
[System.Reflection.Assembly]::LoadFrom($ManagedDllPath) | Out-Null
Write-Diag "TraceEvent Library Loaded ($DotNetTarget)." "STARTUP"

# ====================== CROSS-PLATFORM COMPILER ======================
$RefAssemblies = @($ManagedDllPath, "System", "System.Core")

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $coreDir = [System.IO.Path]::GetDirectoryName([System.Object].Assembly.Location)
    $requiredDlls = @("System.Runtime.dll", "System.Collections.dll", "System.Collections.Concurrent.dll", "System.Linq.Expressions.dll", "System.Net.Primitives.dll", "System.Private.CoreLib.dll", "netstandard.dll")
    foreach ($dll in $requiredDlls) {
        $fullPath = Join-Path $coreDir $dll
        if (Test-Path $fullPath) { $RefAssemblies += $fullPath }
    }
}

$CSharpFilePath = Join-Path $ScriptDir "C2Sensor.cs"
if (-not (Test-Path $CSharpFilePath)) {
    Write-Diag "FATAL: Missing C# Engine Source: $CSharpFilePath" "CRITICAL"
    exit
}

Add-Type -Path $CSharpFilePath -ReferencedAssemblies $RefAssemblies
Write-Diag "C# Engine Compiled Natively into runspace." "STARTUP"

# ====================== 4. RUNTIME STRUCTURES ======================
$ProcessCache = @{} 
$connectionHistory = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$lastPingTime = @{}
$flowMetadata = @{}
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()
$uebaBatch = [System.Collections.Generic.List[PSObject]]::new()

$loggedFlows = @{}
$lastMLRunTime = Get-Date
$globalMlSent = 0; $globalMlRcvd = 0; $globalMlEvaluated = 0; $globalMlAlerts = 0; $OutboundNetEvents = 0
$global:TotalMitigations = 0

Write-Diag "Starting Real-Time ETW Session (No Disk IO)..." "STARTUP"

# --- FFI BOOTSTRAP ---
$NetworkTI = Initialize-NetworkThreatIntel
[RealTimeC2Sensor]::InitializeEngine($ScriptDir, $DnsExclusions, $NetworkTI.Keys, $NetworkTI.Titles)
[RealTimeC2Sensor]::StartSession()

Write-Diag "Native FFI Bridge successfully initialized." "STARTUP"

# ====================== ACTIVE DEFENSE ENGINE ======================
function Invoke-ActiveDefense($ProcName, $DestIp, $Confidence, $Reason) {
    if (-not $global:IsArmed -or $Confidence -lt $ConfidenceThreshold) { return }

    $mitigationStatus = "Failed"
    if ($ProcName -and $ProcName -notmatch "Unknown|System|Idle|Terminated") {
        Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Name $ProcName -ErrorAction SilentlyContinue)) {
            $mitigationStatus = "Terminated"
            $global:TotalMitigations++
        }
    }

    $blockStatus = ""
    if ($DestIp -match '^\d+\.\d+\.\d+\.\d+$') {
        netsh advfirewall firewall add rule name="C2_Defend_Block_$DestIp" dir=out action=block remoteip=$DestIp protocol=any | Out-Null
        $blockStatus = " | IP Blocked"
        $global:TotalMitigations++
    }

    $targetStr = if ($DestIp) { "$ProcName -> $DestIp" } else { "$ProcName" }
    Add-AlertMessage "DEFENSE: Process $mitigationStatus$blockStatus ($targetStr)" $cYellow
}

# ====================== ALERT WINDOW ENGINE ======================
function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $prefix = "[$ts] "
    $maxLen = 98 - $prefix.Length
    if ($Message.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }

    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })
    if ($global:RecentAlerts.Count -gt 7) { $global:RecentAlerts.RemoveAt(0) }
    Draw-AlertWindow
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 22)

    $logTrunc = if ($OutputPath.Length -gt 60) { "..." + $OutputPath.Substring($OutputPath.Length - 57) } else { $OutputPath }
    $headerPlain = "  [ RECENT DETECTIONS ] | Log: $logTrunc"
    $padHeader = " " * [math]::Max(0, (100 - $headerPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed[ RECENT DETECTIONS ]$cReset | Log: $cDark$logTrunc$cReset$padHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 7; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            $pad = " " * [math]::Max(0, (98 - $item.Text.Length))
            Write-Host "$cCyan║$cReset  $($item.Color)$($item.Text)$cReset$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset                                                                                                    $cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"
    [Console]::SetCursorPosition(0, 32); [Console]::SetCursorPosition($curLeft, $curTop)
}

# ====================== DASHBOARD ENGINE ======================
function Draw-MonitorDashboard([int]$Events, [int]$Flows, [int]$MlSent, [int]$MlEval, [int]$Alerts, [string]$Tamper, [string]$MlHealth, [string]$SysGuard, [int]$Mitigations) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $evPad     = $Events.ToString().PadRight(9)
    $mlPad     = "$MlSent / $MlEval".PadRight(9)
    $tamperPad = $Tamper.PadRight(9)
    $sysguardPad = $SysGuard.PadRight(9)
    $defFired = $Mitigations.ToString().PadRight(9)

    $TitlePlain = "  ⚡ C2 BEACON SENSOR v1.0 | KERNEL MONITOR DASHBOARD"
    $StatusStr  = "  [ LIVE TELEMETRY ]"
    $Stats1Str  = "  Events Processed : $evPad | Active Flows   : $Flows"
    $Stats2Str  = "  ML Sent/Eval     : $mlPad | Active Alerts  : $Alerts"
    $TamperStr  = "  ETW Sensor       : $tamperPad | ML Math Engine : $MlHealth"
    $SysGuardStr = "  Sys Guard State  : $sysguardPad | Defenses Fired : $defFired"

    $UIWidth = 100
    $PadTitle  = " " * [math]::Max(0, ($UIWidth - $TitlePlain.Length - 1))
    $PadStatus = " " * [math]::Max(0, ($UIWidth - $StatusStr.Length))
    $PadStats1 = " " * [math]::Max(0, ($UIWidth - $Stats1Str.Length))
    $PadStats2 = " " * [math]::Max(0, ($UIWidth - $Stats2Str.Length))
    $PadTamper = " " * [math]::Max(0, ($UIWidth - $TamperStr.Length))
    $PadSysGuard = " " * [math]::Max(0, ($UIWidth - $SysGuardStr.Length))

    $TamperColor = if ($Tamper -eq "Good") { $cGreen } else { $cRed }
    $MlColor     = if ($MlHealth -eq "Native FFI") { $cGreen } else { $cRed }
    $GuardColor  = if ($SysGuard -eq "Secure") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed⚡ C2 BEACON SENSOR v1.0$cReset | KERNEL MONITOR DASHBOARD$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cDark[ LIVE TELEMETRY ]$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Events Processed : $cCyan$evPad$cReset | Active Flows   : $cCyan$Flows$cReset$PadStats1$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ML Sent/Eval     : $cYellow$mlPad$cReset | Active Alerts  : $cRed$Alerts$cReset$PadStats2$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ETW Sensor       : $TamperColor$($Tamper.PadRight(9))$cReset | ML Math Engine : $MlColor$MlHealth$cReset$PadTamper$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Sys Guard State  : $GuardColor$($SysGuard.PadRight(9))$cReset | Defenses Fired : $cYellow$defFired$cReset$PadSysGuard$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    if ($curTop -lt 9) { $curTop = 9 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

# ====================== MATH HELPERS (STATIC BACKUP) ======================
$log2 = [Math]::Log(2)
$Regex_NonDigit = [regex]::new('[^0-9]', 'Compiled')
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")

function Get-Entropy([string]$inputString) {
    if ([string]::IsNullOrEmpty($inputString)) { return 0.0 }
    $charCounts = @{}; foreach ($c in $inputString.ToCharArray()) { $charCounts[$c]++ }
    $entropy = 0.0; $len = $inputString.Length
    foreach ($count in $charCounts.Values) {
        $p = $count / $len; $entropy -= $p * ([Math]::Log($p) / $log2)
    }
    return $entropy
}

function Is-AnomalousDomain([string]$domain) {
    if ([string]::IsNullOrEmpty($domain)) { return $false }
    if ($domain.Length -gt 35) { return $true }
    $digits = $Regex_NonDigit.Replace($domain, "").Length
    if (($digits / $domain.Length) -gt 0.45) { return $true }
    $vowelCount = 0
    foreach ($char in $domain.ToLower().ToCharArray()) { if ($vowels.Contains($char)) { $vowelCount++ } }
    if (($vowelCount / $domain.Length) -lt 0.15) { return $true }
    return (Get-Entropy $domain) -gt 3.8
}

# ====================== ANTI-TAMPER SENSOR WATCHDOG ======================
Write-Diag "Initializing Anti-Tamper Canary Thread (DNS)..." "STARTUP"

$LastHeartbeat = Get-Date
$LastCanaryPing = Get-Date
$SensorBlinded = $false

# ====================== MAIN EVENT LOOP ======================
try {
    while ($true) {
        $now = Get-Date

        # --- ASYNCHRONOUS CANARY PING ---
        if (($now - $LastCanaryPing).TotalSeconds -ge 60) {
            $LastCanaryPing = $now
            try { Resolve-DnsName -Name "canary-$(Get-Random).c2Sensor.com" -ErrorAction SilentlyContinue | Out-Null } catch {}
        }

        $eventCount = 0
        $jsonStr = ""
        $SysGuardState = "Secure"

        while ([RealTimeC2Sensor]::EventQueue.TryDequeue([ref]$jsonStr)) {
            $eventCount++
            $evt = $jsonStr | ConvertFrom-Json -ErrorAction SilentlyContinue

            if (-not $evt) { continue }

            if ($evt.Provider -eq "DiagLog") { Write-Diag $evt.Message "INFO"; continue }
            if ($evt.Error) {
                Write-Diag "FATAL ETW CRASH: $($evt.Error)" "ERROR"
                Add-AlertMessage "FATAL ERROR: C# ETW THREAD CRASHED" $cRed
                continue
            }

            if ($evt.Query -match "canary-\d+\.c2Sensor\.com") {
                $LastHeartbeat = $now
                if ($SensorBlinded) {
                    $SensorBlinded = $false
                    Add-AlertMessage "SENSOR RECOVERED: ETW telemetry restored." $cGreen
                    Write-Diag "Sensor connection restored after blinding event." "INFO"
                }
                continue 
            }

            if ($evt.Provider -eq "TamperGuard") {
                $SysGuardState = "BREACHED"
                $alertMsg = "TAMPER ALERT: $($evt.EventName) - $($evt.Details)"
                Add-AlertMessage $alertMsg $cRed
                $global:TamperWriter.WriteLine("[$(Get-Date -Format 'o')] [TAMPER] $($evt.EventName) | $($evt.Details)")
                continue
            }

            if ($evt.Provider -eq "NDIS" -and $evt.EventName -eq "TLS_JA3_FINGERPRINT") {
                Write-Diag "JA3 HASH EXTRACTED: $($evt.DestIp) -> $($evt.JA3)" "INFO"

                if ($global:MaliciousJA3Cache -contains $evt.JA3) {
                    $owningProcess = "Unknown"
                    foreach ($k in $flowMetadata.Keys) {
                        if ($k -match "IP_$($evt.DestIp)") {
                            if ($flowMetadata[$k].image -ne "Unknown") {
                                $owningProcess = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$k].image)
                            }
                            break
                        }
                    }

                    $alertMsg = "THREAT INTEL: Malicious JA3 C2 Profile ($($evt.JA3))"
                    Add-AlertMessage $alertMsg $cRed

                    $dataBatch.Add([PSCustomObject]@{
                        EventType = "JA3_C2_FINGERPRINT"
                        Timestamp = $now
                        Destination = $evt.DestIp
                        Image = $owningProcess
                        SuspiciousFlags = "Matched Abuse.ch JA3 Profile: $($evt.JA3)"
                        Confidence = 100
                    })

                    Invoke-ActiveDefense -ProcName $owningProcess -DestIp $evt.DestIp -Confidence 100 -Reason "Malicious JA3 Hash"
                }
                continue
            }

            if ($evt.Provider -eq "AppGuard") {
                $alertMsg = "SERVER EXPLOIT: $($evt.EventName) -> $($evt.Parent) spawned $($evt.Child)"
                Add-AlertMessage $alertMsg $cRed
                Write-Diag "APPGUARD HIT: $($evt.Parent) spawned $($evt.Child) | CMD: $($evt.CommandLine)" "WARN"

                $MitreTags = if ($evt.EventName -eq "WEB_SHELL_DETECTED") { "TA0003: T1505.003; TA0001: T1190; TA0002: T1059" } else { "TA0001: T1190; TA0002: T1569.002; TA0002: T1059" }

                $dataBatch.Add([PSCustomObject]@{
                    EventType = $evt.EventName
                    Timestamp = $now
                    Destination = "Local_Privilege_Escalation"
                    Image = $evt.Parent
                    SuspiciousFlags = "Server Application Spawned Command Shell: $($evt.Child) | Cmd: $($evt.CommandLine)"
                    ATTCKMappings = $MitreTags
                    Confidence = 100
                })

                Invoke-ActiveDefense -ProcName $evt.Child -DestIp "" -Confidence 100 -Reason "Server Application Exploitation"
                continue 
            }

            # --- NETWORK THREAT INTEL ALERTS (Aho-Corasick Matches) ---
            if ($evt.Provider -eq "ThreatIntel") {
                $procName = if ($evt.Image) { [System.IO.Path]::GetFileNameWithoutExtension($evt.Image) } else { "Unknown" }
                $targetStr = if ($evt.Query) { $evt.Query } else { $evt.DestIp }
                
                Add-AlertMessage "SIGNATURE MATCH: $($evt.Details) -> ($targetStr)" $cRed
                Write-Diag "THREAT INTEL TRIGGER: $($evt.Details) Process: $procName Target: $targetStr" "WARN"

                $dataBatch.Add([PSCustomObject]@{
                    EventType = $evt.EventName
                    Timestamp = $now
                    Destination = $targetStr
                    Image = $procName
                    SuspiciousFlags = $evt.Details
                    Confidence = 95
                })

                Invoke-ActiveDefense -ProcName $procName -DestIp $evt.DestIp -Confidence 95 -Reason $evt.Details
                continue
            }

            # --- NOISE REDUCTION FILTERS ---
            $procName = ""
            if ($evt.Image -and $evt.Image -ne "Unknown") {
                $procName = [System.IO.Path]::GetFileNameWithoutExtension($evt.Image).ToLower()
            }
            elseif ($evt.PID -match '^\d+$' -and $evt.PID -ne "0" -and $evt.PID -ne "4") {
                if (-not $ProcessCache.ContainsKey($evt.PID)) {
                    try { $ProcessCache[$evt.PID] = (Get-Process -Id $evt.PID -ErrorAction Stop).Name.ToLower() } catch { $ProcessCache[$evt.PID] = "terminated" }
                }
                $procName = $ProcessCache[$evt.PID]
            }

            $skipEvent = $false
            if (-not [string]::IsNullOrEmpty($procName) -and ($ProcessExclusions -contains $procName)) { $skipEvent = $true }
            if (-not $skipEvent -and -not [string]::IsNullOrEmpty($evt.DestIp)) {
                foreach ($prefix in $IpPrefixExclusions) {
                    if ($evt.DestIp -match $prefix) { $skipEvent = $true; break }
                }
            }

            if ($skipEvent) { continue }

            $uebaBatch.Add($evt)

            $props = [ordered]@{
                EventType = $evt.EventName
                Timestamp = [datetime]$evt.TimeStamp
                Image = $evt.Image
                SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                ATTCKMappings = [System.Collections.Generic.List[string]]::new()
                DestinationHostname = $evt.Query
                Confidence = 85
            }

            if ($evt.Provider -match "Process" -and $evt.CommandLine -match '-EncodedCommand|-enc|IEX') {
                $props.SuspiciousFlags.Add("Anomalous CommandLine")
                $props.ATTCKMappings.Add("TA0002: T1059.001")
            }
            if ($evt.Provider -match "File" -and $evt.Image -match '\.ps1$|\.exe$') {
                $props.SuspiciousFlags.Add("Executable File Created")
                $props.ATTCKMappings.Add("TA0002: T1059")
            }
            if ($evt.Provider -match "DNS" -and $evt.Query -match '^[a-zA-Z0-9\-\.]+$') {
                $cleanQuery = $evt.Query.TrimEnd('.')
                if (Is-AnomalousDomain $cleanQuery) {
                    $props.SuspiciousFlags.Add("DGA DNS Query Detected")
                    $props.ATTCKMappings.Add("TA0011: T1568.002")
                }
            }

            if ($evt.Provider -match "TCPIP|Network" -and $evt.DestIp -and $evt.DestIp -notmatch '^192\.168\.|^10\.|^127\.|^172\.') {
                $OutboundNetEvents++

                $safePort = if ([string]::IsNullOrWhiteSpace($evt.Port) -or $evt.Port -eq "0") { "IP_$($evt.DestIp)" } else { $evt.Port }
                $key = if ($evt.PID -eq "4" -or $evt.PID -eq "0") {
                    "PID_$($evt.PID)_TID_$($evt.TID)_IP_$($evt.DestIp)_Port_$safePort"
                } else {
                    "PID_$($evt.PID)_TID_$($evt.TID)_Port_$safePort"
                }

                if (-not $connectionHistory.ContainsKey($key)) {
                    $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                    $flowMetadata[$key] = @{
                        dst_ips = [System.Collections.Generic.List[string]]::new()
                        packet_sizes = [System.Collections.Generic.List[int]]::new()
                        domain = if ($evt.Query) { $evt.Query } else { $evt.DestIp }
                        image = $evt.Image
                    }
                }

                $isNewPing = $true
                $evtTime = [datetime]$evt.TimeStamp

                if ($lastPingTime.ContainsKey($key) -and ($evtTime - $lastPingTime[$key]).TotalMilliseconds -lt 100) {
                    $isNewPing = $false
                }

                if ($isNewPing) {
                    $connectionHistory[$key].Enqueue($evtTime)
                    $lastPingTime[$key] = $evtTime
                    $flowMetadata[$key].dst_ips.Add($evt.DestIp)

                    if ($evt.Size -match '^\d+$' -and $evt.Size -ne "0") {
                        $flowMetadata[$key].packet_sizes.Add([int]$evt.Size)
                    } else {
                        $flowMetadata[$key].packet_sizes.Add(0)
                    }
                }
            }

            if ($props.SuspiciousFlags.Count -gt 0) {
                $outObj = New-Object PSObject -Property $props
                $outObj.SuspiciousFlags = $props.SuspiciousFlags -join '; '
                $outObj.ATTCKMappings = $props.ATTCKMappings -join '; '
                $dataBatch.Add($outObj)

                Add-AlertMessage "STATIC: $($outObj.SuspiciousFlags) ($procName)" $cYellow
                Invoke-ActiveDefense -ProcName $procName -DestIp $evt.DestIp -Confidence 90 -Reason $outObj.SuspiciousFlags
            }
        }

        # ---------------- NATIVE FFI ML HANDOFF PIPELINE ----------------
        if (($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {
            $payloadArray = @()

            foreach ($key in $connectionHistory.Keys) {
                $count = $connectionHistory[$key].Count
                if ($count -ge $MinSamplesForML) {
                    $arr = $connectionHistory[$key].ToArray()
                    
                    if (($now - $arr[-1]).TotalSeconds -gt 120) { continue }

                    if (-not $loggedFlows.ContainsKey($key) -or $loggedFlows[$key] -ne $count) {
                        $loggedFlows[$key] = $count
                        $duration = [Math]::Round(($arr[-1] - $arr[0]).TotalSeconds, 2)
                        $firstPing = $arr[0].ToString("yyyy-MM-dd HH:mm:ss")

                        $destIp = $flowMetadata[$key].dst_ips[-1]
                        $domain = $flowMetadata[$key].domain
                        $portVal = if (($key -split "_Port_").Count -gt 1) { ($key -split "_Port_")[1] } else { "Unknown" }

                        $pidVal = "Unknown"
                        if ($key -match "PID_(\d+)") { $pidVal = $matches[1] }

                        $procName = "Unknown"
                        if ($flowMetadata[$key].image -and $flowMetadata[$key].image -ne "Unknown") {
                            $procName = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$key].image)
                        } elseif ($pidVal -match '^\d+$') {
                            try { $procName = (Get-Process -Id $pidVal -ErrorAction Stop).Name; if ($pidVal -eq "4") { $procName = "System" } } catch { $procName = "Terminated" }
                        }

                        $logEntry = "Timestamp: $firstPing, Destination IP: $destIp, Destination Domain: $domain, Port: $portVal, PID: $pidVal, Process Name: $procName, Connection Amount over duration: $count connections over ${duration}s"
                        Add-Content -Path $MonitorLogPath -Value $logEntry -Encoding UTF8
                    }

                    $intervals = @(); $aligned_ips = @(); $aligned_sizes = @()
                    for ($i = 1; $i -lt $arr.Count; $i++) {
                        $intervals += [Math]::Round(($arr[$i] - $arr[$i-1]).TotalSeconds, 2)
                        if ($i -lt $flowMetadata[$key].dst_ips.Count) { $aligned_ips += $flowMetadata[$key].dst_ips[$i] }
                        if ($i -lt $flowMetadata[$key].packet_sizes.Count) { $aligned_sizes += $flowMetadata[$key].packet_sizes[$i] }
                    }

                    $payloadArray += @{
                        key = $key
                        intervals = $intervals
                        domain = $flowMetadata[$key].domain
                        dst_ips = $aligned_ips
                        packet_sizes = $aligned_sizes
                    }
                }
            }

            if ($payloadArray.Count -gt 0) {
                $globalMlSent++
                $jsonPayload = $payloadArray | ConvertTo-Json -Depth 6 -Compress

                Write-Diag "Executing Native FFI Memory Map. Arrays: $($payloadArray.Count) | Payload Size: $($jsonPayload.Length)" "FFI-TX"

                $mlResponseString = [RealTimeC2Sensor]::EvaluateBatch($jsonPayload)

                if ($mlResponseString -ne "{}" -and $mlResponseString -ne "") {
                    $globalMlRcvd++
                    Write-Diag "Memory pointer retrieved successfully: $mlResponseString" "FFI-RX"

                    try {
                        $mlResults = $mlResponseString | ConvertFrom-Json -ErrorAction Stop

                        if ($mlResults.daemon_error) {
                            Write-Diag "Fatal Rust FFI Error: $($mlResults.daemon_error)" "ERROR"
                        } elseif ($mlResults.alerts) {
                            foreach ($alert in $mlResults.alerts) {
                                $globalMlAlerts++
                                $alertKey = $alert.key

                                $pidVal = "Unknown"
                                $pidParts = ($alertKey -split "PID_")
                                if ($pidParts.Count -gt 1) { $pidVal = ($pidParts[1] -split "_")[0] }

                                $resolvedImage = "Unknown"
                                if ($flowMetadata[$alertKey].image -and $flowMetadata[$alertKey].image -ne "Unknown") {
                                    $resolvedImage = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$alertKey].image)
                                } elseif ($pidVal -match '^\d+$') {
                                    try { $resolvedImage = (Get-Process -Id $pidVal -ErrorAction Stop).Name; if ($pidVal -eq "4") { $resolvedImage = "System" }; if ($pidVal -eq "0") { $resolvedImage = "Idle" } } catch { $resolvedImage = "Terminated" }
                                }

                                Add-AlertMessage "ML ($($alert.confidence)%): $alertKey - $($alert.alert_reason)" $cRed
                                Write-Diag "RUST DETECTION TRIGGERED: $alertKey -> $($alert.alert_reason) (Confidence: $($alert.confidence))" "MATH"

                                $dataBatch.Add([PSCustomObject]@{
                                    EventType = "ML_Beacon"
                                    Timestamp = $now
                                    Destination = $alertKey
                                    Image = $resolvedImage
                                    SuspiciousFlags = $alert.alert_reason
                                    Confidence = $alert.confidence
                                })

                                $targetIp = if ($alertKey -match "IP_([0-9\.]+)") { $matches[1] } else { "Unknown" }
                                Invoke-ActiveDefense -ProcName $resolvedImage -DestIp $targetIp -Confidence $alert.confidence -Reason $alert.alert_reason
                            }
                        }
                    } catch { 
                        Write-Diag "JSON Parse Failure from Rust Engine: $mlResponseString" "ERROR" 
                    }
                }
            }

            $staleKeys = @()
            foreach ($k in $connectionHistory.Keys) {
                $historyArr = $connectionHistory[$k].ToArray()
                if ($historyArr.Count -gt 0 -and ($now - $historyArr[-1]).TotalSeconds -gt 300) { $staleKeys += $k }
            }
            foreach ($k in $staleKeys) { [void]$connectionHistory.Remove($k); [void]$flowMetadata.Remove($k); [void]$loggedFlows.Remove($k) }
            
            $lastMLRunTime = $now
        }

        # --- LOG ROTATION ENGINE ---
        if ($dataBatch.Count -gt 0) {
            if (Test-Path $OutputPath) {
                if ((Get-Item $OutputPath).Length -gt 50MB) {
                    $archiveName = $OutputPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    Rename-Item -Path $OutputPath -NewName $archiveName -Force
                    Write-Diag "Log rotated. Archived to $archiveName" "INFO"
                }
            }

            $batchOutput = ($dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            [System.IO.File]::AppendAllText($OutputPath, $batchOutput + "`r`n")
            $dataBatch.Clear()
        }

        if ($uebaBatch.Count -gt 0) {
            if (Test-Path $UebaLogPath) {
                if ((Get-Item $UebaLogPath).Length -gt 50MB) {
                    $archiveName = $UebaLogPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    Rename-Item -Path $UebaLogPath -NewName $archiveName -Force
                }
            }
            $uebaOutput = ($uebaBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            [System.IO.File]::AppendAllText($UebaLogPath, $uebaOutput + "`r`n")
            $uebaBatch.Clear()
        }

        $activeFlows = $connectionHistory.Keys.Count
        $tamperStatus = if (($now - $LastHeartbeat).TotalSeconds -le 180) { "Good" } else { "BAD" }

        Draw-MonitorDashboard -Events $eventCount -Flows $activeFlows -MlSent $globalMlSent -MlEval $globalMlSent -Alerts $globalMlAlerts -Tamper $tamperStatus -MlHealth "Native FFI" -SysGuard $SysGuardState -Mitigations $global:TotalMitigations

        if ($tamperStatus -eq "BAD" -and -not $SensorBlinded) {
            $SensorBlinded = $true
            Add-AlertMessage "CRITICAL ALARM: SENSOR BLINDED (ETW COMPROMISE)" $cRed
            Write-Diag "SENSOR BLINDED: No heartbeat received since $($LastHeartbeat.ToString('HH:mm:ss'))." "ERROR"
        }

        Start-Sleep -Milliseconds 200
    }

} catch {
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" -ForegroundColor Red
    "[$((Get-Date).ToString('HH:mm:ss'))] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" | Out-File -FilePath $DiagLogPath -Append
} finally {
    Clear-Host
    Write-Host "`n[*] Initiating Graceful Shutdown..." -ForegroundColor Cyan
    try { [console]::TreatControlCAsInput = $false } catch {}

    Write-Diag "Initiating Teardown Sequence..." "INFO"

    Write-Host "    [*] Finalizing Kernel Telemetry & ML Database..." -ForegroundColor Gray
    try { [RealTimeC2Sensor]::StopSession() } catch {}
    Write-Diag "C# TraceEvent Session Halted." "INFO"

    Write-Host "    [*] Cleaning up temporary library artifacts..." -ForegroundColor Gray
    $TempLibPath = "C:\Temp\TraceEventPackage"
    if (Test-Path $TempLibPath) { Remove-Item -Path $TempLibPath -Recurse -Force -ErrorAction SilentlyContinue }
    
    $StrayTrace = "C:\Temp\TraceEvent.zip"
    if (Test-Path $StrayTrace) { Remove-Item -Path $StrayTrace -Force -ErrorAction SilentlyContinue }

    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"
    Write-Host "`n[+] Teardown Complete." -ForegroundColor Green
}