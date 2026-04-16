<#
.SYNOPSIS
    Windows Kernel C2 Beacon Sensor v2.0 beta (Native FFI Architecture)
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
        "windows.net", "akadns.net", "akamaized.net", "akamaiedge.net", "msocdn.com",
        # Google & Android Ecosystem
        "google.com", "googleapis.com", "1e100.net", "gstatic.com", "gvt1.com", "gvt2.com",
        "youtube.com", "ytimg.com", "googlevideo.com",
        # Amazon AWS, Cloudflare, & Fastly Edge Networks
        "amazonaws.com", "cloudfront.net", "cloudflare.com", "cloudflare.net", "fastly.net",
        # Apple Ecosystem (iTunes, iCloud telemetry)
        "apple.com", "icloud.com", "mzstatic.com",
        # Development & Telemetry (Fixes VS Code DGA False Positives)
        "github.com", "githubusercontent.com", "sentry.io", "vscode.dev", "vsassets.io", "adobe.com", "acrobat.com",
        # PKI & Certificate Revocation (Fixes svchost DGA False Positives)
        "digicert.com", "symcb.com", "sectigo.com", "crl.com", "ocsp.com", "lencr.org", "pki.goog",
        # Unified Communications & Media
        "zoom.us", "webex.com", "slack-edge.com", "discord.gg", "discordapp.com",
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
    ),

    # ====================== APPGUARD CONFIGURATION ======================
    [string[]]$WebDaemons = @(
        "w3wp", "iisexpress", "httpd", "nginx", "lighttpd", "caddy", "traefik", "envoy", "haproxy",
        "tomcat", "tomcat7", "tomcat8", "tomcat9", "java", "javaw",
        "node", "dotnet", "python", "python3", "php", "php-cgi", "ruby"
    ),

    [string[]]$DbDaemons = @(
        "sqlservr", "mysqld", "mariadbd", "postgres", "oracle", "tnslsnr", "db2sysc", "fbserver",
        "mongod", "redis-server", "memcached", "couchdb", "influxd", "arangod"
    ),

    [string[]]$ShellInterpreters = @(
        "cmd", "powershell", "pwsh", "wscript", "cscript", "bash", "sh", "whoami",
        "csc", "cvtres", "certutil", "wmic", "rundll32", "regsvr32", "msbuild", "bitsadmin"
    ),

    [string[]]$SuspiciousPaths = @(
        "\\temp\\", "\\programdata\\", "\\inetpub\\wwwroot\\", "\\appdata\\", "\\users\\public\\"
    )
)

$global:IsArmed = $ArmedMode
$ScriptDir = Split-Path $PSCommandPath -Parent
$now = Get-Date

if ($TestMode) {
    $CdnPrefixes = @("^52\.", "^142\.25[0-9]\.", "^13\.", "^20\.", "^23\.", "^74\.125\.")
    $IpPrefixExclusions = $IpPrefixExclusions | Where-Object { $_ -notin $CdnPrefixes }
}

# Alert Metadata
$activeRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($activeRoute) {
    $global:HostIP = (Get-NetIPAddress -InterfaceIndex $activeRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}
if (-not $global:HostIP) { $global:HostIP = "Unknown" }
$global:SensorUser = "$env:USERDOMAIN\$env:USERNAME".Replace("\", "\\")
$global:ComputerName = $env:COMPUTERNAME

function Submit-SensorAlert {
    param(
        [string]$Type,
        [string]$Destination,
        [string]$Image,
        [string]$Flags,
        [int]$Confidence,
        [string]$AttckMapping = "N/A",
        [string]$EventId = ([guid]::NewGuid().ToString()),
        [string]$RawJson = $null,
        [int]$LearningHit = 0
    )

    # 1. Deduplication Logic
    $dedupKey = "$($Type)_$($Destination)_$($Flags)_$($Image)"
    if ($global:cycleAlerts.ContainsKey($dedupKey)) {
        $global:cycleAlerts[$dedupKey].Count++
        return
    }

    # 2. Targeted UEBA Telemetry Persistence
    if ($RawJson -and $Type -eq "ThreatIntel_Match") {
        $injectStr = "`"EventID`":`"$EventId`", `"ComputerName`":`"$global:ComputerName`", `"HostIP`":`"$global:HostIP`", `"SensorUser`":`"$global:SensorUser`", `"LearningHit`":$LearningHit, "
        $enrichedJson = $RawJson.Insert(1, $injectStr)
        $global:uebaBatch.Add($enrichedJson)
    }

    # 3. Standardized Object Construction
    $alertObj = [PSCustomObject][ordered]@{
        EventID         = $EventId
        Count           = 1
        Timestamp_Local = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        Timestamp_UTC   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        ComputerName    = $global:ComputerName
        HostIP          = $global:HostIP
        SensorUser      = $global:SensorUser
        EventType       = $Type
        Destination     = $Destination
        Image           = $Image
        SuspiciousFlags = $Flags
        ATTCKMappings   = $AttckMapping
        Confidence      = $Confidence
        Action          = if ($global:IsArmed -and $Confidence -ge $ConfidenceThreshold) { "Mitigated" } else { "Logged" }
    }

    # 4. Queue for Batch Logging & HUD
    $global:cycleAlerts[$dedupKey] = $alertObj

    # 5. Immediate Active Defense (If Armed)
    if ($alertObj.Action -eq "Mitigated") {
        Invoke-ActiveDefense -ProcName $Image -DestIp $Destination -Confidence $Confidence -Reason $Flags
    }
}

# Disable Windows QuickEdit Mode to prevent accidental process freezing
$QuickEditCode = @"
using System;
using System.Runtime.InteropServices;
public class ConsoleConfig {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static void DisableQuickEdit() {
        IntPtr consoleHandle = GetStdHandle(-10); // STD_INPUT_HANDLE
        if (GetConsoleMode(consoleHandle, out uint consoleMode)) {
            consoleMode &= ~0x0040U; // Strip ENABLE_QUICK_EDIT_MODE
            SetConsoleMode(consoleHandle, consoleMode);
        }
    }
}
"@
Add-Type -TypeDefinition $QuickEditCode
[ConsoleConfig]::DisableQuickEdit()

# ====================== ENTERPRISE DIRECTORY STRUCTURE ======================
$DataDir = "C:\ProgramData\C2Sensor\Data"
$LogDir  = "C:\ProgramData\C2Sensor\Logs"
$StagingDir = "C:\ProgramData\C2Sensor\Staging"

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null }
if (-not (Test-Path $LogDir))  { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
if (-not (Test-Path $StagingDir)) { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }

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

$ESC      = [char]27
$cCyan    = "$ESC[38;2;0;255;255m"
$cGreen   = "$ESC[38;2;57;255;20m"
$cOrange  = "$ESC[38;2;255;103;0m"
$cGold    = "$ESC[38;2;255;215;0m"
$cYellow  = "$ESC[38;2;255;255;51m"
$cRed     = "$ESC[38;2;255;49;49m"
$cWhite   = "$ESC[38;2;255;255;255m"
$cDark    = "$ESC[38;2;80;80;80m"
$cReset   = "$ESC[0m$ESC[40m"

try {
    $ui = $Host.UI.RawUI
    $buffer = $ui.BufferSize; $buffer.Width = 160; $buffer.Height = 3000; $ui.BufferSize = $buffer
    $size = $ui.WindowSize; $size.Width = 160; $size.Height = 58; $ui.WindowSize = $size
} catch {}

[Console]::SetCursorPosition(0, 9)

# UEBA Temporal Feedback Cache
$global:UebaLearningCache = [System.Collections.Generic.Dictionary[string, int]]::new()

# ====================== DIAGNOSTICS & UI LOGGING ======================
if (Test-Path $DiagLogPath) { Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue }

$global:DiagStream = [System.IO.File]::Open($DiagLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
$global:DiagWriter = New-Object System.IO.StreamWriter($global:DiagStream)
$global:DiagWriter.AutoFlush = $true

$global:StartupLogs = [System.Collections.Generic.List[string]]::new()

function Write-Diag {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "FFI-TX", "FFI-RX", "MATH", "STARTUP", "CRITICAL")]
        [string]$Level = "INFO"
    )
    if (-not $global:EnableDiagnostics -and $Level -notin @("ERROR", "WARN", "CRITICAL", "STARTUP")) { return }

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try { $global:DiagWriter.WriteLine("[$ts] [$Level] $Message") } catch {}

    if ($Level -eq "STARTUP") {
        $global:StartupLogs.Add($Message)
        Draw-StartupWindow
    }
}

function Draw-StartupWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100
    [Console]::SetCursorPosition(0, 37)

    $cGreen = "$([char]27)[38;2;57;255;20m"
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

Write-Diag "=== C2 SENSOR V2 DIAGNOSTIC LOG INITIALIZED ===" "STARTUP"
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
        if (-not (Test-Path $TamperLogPath)) { New-Item $TamperLogPath -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null }
        icacls $TamperLogPath /inheritance:r /q 2>&1 | Out-Null
        icacls $TamperLogPath /grant:r "*S-1-5-18:(F)" /grant:r "*S-1-5-32-544:(F)" /q 2>&1 | Out-Null
        Write-Diag "Successfully applied strict ACLs to Tamper Guard log." "STARTUP"
    } catch { Write-Diag "Warning: icacls permission lockdown failed." "WARN" }

    try {
        $global:TamperStream = [System.IO.File]::Open($TamperLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
        $global:TamperWriter.AutoFlush = $true
        Write-Diag "Tamper Guard Log locked to current process." "STARTUP"
    } catch {
        Write-Diag "Tamper log is locked. Executing aggressive cleanup..." "WARN"
        Get-Process powershell, pwsh -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        try {
            $global:TamperStream = [System.IO.File]::Open($TamperLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
            $global:TamperWriter.AutoFlush = $true
            Write-Diag "Tamper Guard Log recovered and locked." "STARTUP"
        } catch {
            Write-Diag "Tamper Guard Log completely locked. Operating without disk ledger." "WARN"
            $global:TamperWriter = $null
        }
    }
}
Initialize-TamperGuard

# =========================================================================
# JA3 THREAT INTEL LOADER (ABUSE.CH SSLBL)
# =========================================================================
$global:MaliciousJA3Cache = [System.Collections.Generic.HashSet[string]]::new()
$Ja3CacheAgeHours = 24
$needsJa3Download = $true

if (Test-Path $Ja3CachePath) {
    $age = ((Get-Date) - (Get-Item $Ja3CachePath).LastWriteTime).TotalHours
    if ($age -lt $Ja3CacheAgeHours) {
        $needsJa3Download = $false
    }
}

if ($needsJa3Download) {
    Write-Diag "Fetching latest JA3 Fingerprints from abuse.ch SSLBL..." "STARTUP"
    try {
        $csvData = Invoke-WebRequest -Uri "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv" -UseBasicParsing -ErrorAction Stop
        $hashes = [System.Collections.Generic.List[string]]::new()

        # Parse the CSV and extract only the 32-character MD5 hashes, ignoring comments
        foreach ($line in ($csvData.Content -split "`n")) {
            if ($line -match "^([a-fA-F0-9]{32}),") {
                $hashes.Add($matches[1].ToLower())
            }
        }

        if ($hashes.Count -gt 0) {
            $hashes | ConvertTo-Json -Compress | Out-File -FilePath $Ja3CachePath -Encoding UTF8 -Force
            Write-Diag "Successfully synced $($hashes.Count) JA3 signatures from abuse.ch." "STARTUP"
        }
    } catch {
        Write-Diag "Failed to pull JA3 from abuse.ch. Relying on local cache/defaults." "WARN"
    }
}

# Load the Cache into the O(1) HashSet
if (Test-Path $Ja3CachePath) {
    try {
        $cachedJa3 = Get-Content $Ja3CachePath -Raw | ConvertFrom-Json
        foreach ($hash in $cachedJa3) { [void]$global:MaliciousJA3Cache.Add($hash) }
        Write-Diag "Loaded $($global:MaliciousJA3Cache.Count) JA3 signatures from dynamic Threat Intel cache." "STARTUP"
    } catch { Write-Diag "Failed to parse JA3 JSON cache. Falling back to offline defaults." "WARN" }
}

# Fallback to Hardcoded Offline Signatures
if ($global:MaliciousJA3Cache.Count -eq 0) {
    $offlineDefaults = @(
        "a0e9f5d64349fb13191bc781f81f42e1", # Metasploit / MSFVenom
        "b32309a26951912be7dba376398abc3b", # Cobalt Strike (Common Profile 1)
        "eb88d0b3e1961a0562f006e5ce2a0b87", # Cobalt Strike (Malleable C2 Default)
        "1ce21ed04b6d4128f7fb6b22b0c36cb1", # Cobalt Strike (Common Profile 3)
        "ee031b874122d97ab269e0d8740be31a", # Metasploit HeartBleed/TLS Scanner
        "51c64c77e60f3980eea90869b68c58a8", # Sliver / Standard Go HTTP/TLS Client
        "e0a786fa0d151121d51f2249e49195b0", # Merlin C2
        "d891b0c034919cb44f128e4e97aeb7e6", # Havoc C2 Default
        "771c93a02bb801fbdbb13b73bcba0d6b", # Empire / Python Requests Default
        "cd08e31494f9531f560d64c695473da9", # Mythic / Generic Python Default
        "3b5074b1b5d032e5620f69f9f700ff0e", # Pupy RAT
        "8f199859f1f0e4b7ba29e3ddc6ee9b71", # Covenant Grunt / Standard .NET WebClient
        "6d89b37a488e0b6dfde0c59828e8331b", # Remcos RAT
        "08ef1bdcbdbba6ce64daec0ab2ea0bc1", # NanoCore RAT
        "2707bb320ebbb6d0c64d8a5decc81b53", # Trickbot
        "4d7a28d6f2263ed61de88ca66eb011e3", # Emotet
        "18f152d0b50302ffab23fc47545de999", # IcedID
        "3f4b4ce6edbc8537fc2ea22a009fb74d", # Qakbot
        "c45d36e2fde376eec6a382b6c31e67b2", # Brute Ratel C4 (Default Config)
        "518b7eb09de4e10173bc51c1ff76b2c2"  # Dridex
    )
    foreach ($hash in $offlineDefaults) { [void]$global:MaliciousJA3Cache.Add($hash) }
    Write-Diag "Loaded $($global:MaliciousJA3Cache.Count) default offline JA3 signatures." "STARTUP"
}

# ====================== NETWORK THREAT INTEL COMPILER ======================
function Initialize-NetworkThreatIntel {
    Write-Diag "Initializing Network Threat Intelligence (Suricata)..." "STARTUP"

    $TiKeys = [System.Collections.Generic.List[string]]::new()
    $TiTitles = [System.Collections.Generic.List[string]]::new()

    # Cache marker file – if it exists and is < 24h old, skip the download
    $CacheMarker = Join-Path $ScriptDir "threatintel.cache"
    $CacheAgeHours = 24
    $needsDownload = $true

    if (Test-Path $CacheMarker) {
        $age = ((Get-Date) - (Get-Item $CacheMarker).LastWriteTime).TotalHours
        if ($age -lt $CacheAgeHours) {
            $needsDownload = $false
            Write-Diag "Using cached Threat Intel (rules < $CacheAgeHours hours old)" "STARTUP"
        }
    }

    # =========================================================================
    # 1. SURICATA SYNC & PARSE
    # =========================================================================
    $SuricataBaseDir = Join-Path $ScriptDir "suricata"
    $SuricataUpstreamDir = Join-Path $SuricataBaseDir "upstream"

    if ($needsDownload -or -not (Test-Path $SuricataUpstreamDir)) {
        if (-not (Test-Path $SuricataUpstreamDir)) {
            New-Item -ItemType Directory -Path $SuricataUpstreamDir -Force | Out-Null
        }

        $SuricataUrls = @(
            # --- Emerging Threats (ET) Rulesets (Versioned for Suricata 8.0.4) ---
            @{ Name = "ET_DNS"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-dns.rules" },
            @{ Name = "ET_C2";  Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-c2.rules" },
            @{ Name = "ET_Malware"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-malware.rules" },
            @{ Name = "ThreatView_CS_C2"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/threatview_CS_c2.rules" },

            # --- Active Botnet Nodes & Compromised Drop Zones ---
            @{ Name = "ET_BotCC"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-botcc.rules" },
            @{ Name = "ET_Compromised"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-compromised.rules" },

            # --- Adversary Infrastructure & C2 Trackers (Abuse.ch) ---
            @{ Name = "AbuseCH_FeodoTracker"; Url = "https://feodotracker.abuse.ch/downloads/feodotracker.rules" },
            @{ Name = "AbuseCH_ThreatFox"; Url = "https://threatfox.abuse.ch/downloads/threatfox_suricata.rules" },
            @{ Name = "AbuseCH_SSLBL_IP"; Url = "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.rules" }
        )

        foreach ($src in $SuricataUrls) {
            $OutPath = Join-Path $SuricataUpstreamDir "$($src.Name).rules"
            try {
                Write-Diag "Fetching Suricata ruleset: $($src.Name)" "STARTUP"
                Invoke-WebRequest -Uri $src.Url -OutFile $OutPath -UseBasicParsing -ErrorAction Stop
            } catch { Write-Diag "Failed to sync $($src.Name). Relying on local cache." "WARN" }
        }
    }

    $SuricataFiles = Get-ChildItem -Path $SuricataBaseDir -Filter "*.rules" -Recurse
    $suricataCount = 0

    foreach ($file in $SuricataFiles) {
        try {
            $rules = Get-Content $file.FullName
            foreach ($line in $rules) {
                if ($line -match '^alert' -and $line -match 'msg:\s*"([^"]+)"') {
                    $msg = $matches[1]
                    $NoisyIps = @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")

                    # --- SURICATA HEADER IP EXTRACTION ---
                    if ($line -match '->\s+\[?([0-9\.,]+)\]?\s+') {
                        $destIps = $matches[1] -split ','
                        foreach ($ip in $destIps) {
                             if ($ip -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" -and $ip -notin $NoisyIps) {
                                 $TiKeys.Add($ip); $TiTitles.Add("Suricata: $msg"); $suricataCount++
                             }
                        }
                    }

                    # --- SURICATA STRICT CONTENT PARSING ---
                    $contents = [regex]::Matches($line, 'content:\s*"([^"]+)"')
                    foreach ($c in $contents) {
                        $val = $c.Groups[1].Value.ToLower()
                        $val = ($val -replace '\|[0-9a-fA-F]{2}\|', '.') -replace '^\.+|\.+$', ''

                        if ($val -in $NoisyIps) { continue }

                        # IGNORE SAFE DOMAINS (Prevents DPI rules from banning legitimate tech infra)
                        $SafeDomains = @(
                            "google.com", "bing.com", "yahoo.com", "microsoft.com", "windows.com",
                            "adobe.com", "github.com", "apple.com", "ubuntu.com", "mozilla.org",
                            "cloudflare.com", "amazon.com", "aws.amazon.com", "office.com",
                            "localhost", "localdomain", "example.com"
                        )
                        $isSafe = $false
                        foreach ($safe in $SafeDomains) {
                            if ($val -eq $safe -or $val.EndsWith(".$safe")) { $isSafe = $true; break }
                        }
                        if ($isSafe) { continue }

                        # STRICT VALIDATION: Only allow valid IPv4 or FQDNs. 
                        $isIp = $val -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
                        $isDomain = $val -match "^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"

                        if ($isIp -or $isDomain) {
                            $cleanVal = $val
                            if ($isDomain -and -not $cleanVal.StartsWith(".")) { $cleanVal = ".$cleanVal" }
                            $TiKeys.Add($cleanVal); $TiTitles.Add("Suricata: $msg"); $suricataCount++
                        }
                    }
                }
            }
        } catch { Write-Diag "Failed to parse custom rule file: $($file.Name)" "WARN" }
    }
    Write-Diag "Gatekeeper Compilation: Parsed $suricataCount signatures from Suricata." "STARTUP"
    New-Item -Path $CacheMarker -ItemType File -Force | Out-Null
    Write-Diag "Threat Intel Compilation Complete. Passing $($TiKeys.Count) signatures to Memory." "STARTUP"
    $TiKeys | Out-File "$LogDir\Compiled_ThreatIntel.txt"
    return @{ Keys = $TiKeys.ToArray(); Titles = $TiTitles.ToArray() }
}

# ====================== 1. TRACEEVENT LIBRARY FETCH ======================
Write-Diag "Initializing C# TraceEvent Engine..." "STARTUP"

$DependenciesDir = "C:\ProgramData\C2Sensor\Dependencies"
$StagingDir      = "C:\ProgramData\C2Sensor\Staging"

if (-not (Test-Path $StagingDir))      { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }
if (-not (Test-Path $DependenciesDir)) { New-Item -ItemType Directory -Path $DependenciesDir -Force | Out-Null }

$ExtractPath = Join-Path $DependenciesDir "TE"
$DotNetTarget = if ($PSVersionTable.PSVersion.Major -ge 7) { "netstandard2.0" } else { "net45" }
$ManagedDllPath = "$ExtractPath\lib\$DotNetTarget\Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Diag "Downloading Microsoft.Diagnostics.Tracing.TraceEvent..." "STARTUP"
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    $ZipPath = Join-Path $StagingDir "TraceEvent.zip"
    try {
        Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.0.2" -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Diag "FATAL: TraceEvent download failed. Ensure internet access or place DLL manually." "CRITICAL"
        Write-Host "[!] Startup Failed: Unable to fetch TraceEvent library. Are you offline?" -ForegroundColor Red
        exit
    }
}

Get-ChildItem -Path $ExtractPath -Recurse | Unblock-File
[System.Reflection.Assembly]::LoadFrom($ManagedDllPath) | Out-Null
Write-Diag "TraceEvent Library Loaded ($DotNetTarget)." "STARTUP"

# ====================== CROSS-PLATFORM COMPILER ======================
$RefAssemblies = @(
    $ManagedDllPath,
    "System",
    "System.Core"
)

if ($PSVersionTable.PSVersion.Major -ge 7) {
    # Rely on Add-Type's internal resolver by providing simple assembly names.
    # Added Net.Primitives, Security.Cryptography, and Linq.Expressions as demanded by Roslyn.
    $RefAssemblies += @(
        "System.Runtime",
        "System.Collections",
        "System.Collections.Concurrent",
        "System.ObjectModel",
        "System.Security.Cryptography",
        "System.Security.Cryptography.Algorithms",
        "System.Security.Cryptography.Primitives",
        "System.Net.Primitives",
        "System.Linq.Expressions",
        "System.Private.CoreLib",
        "netstandard",
        "System.Text.RegularExpressions"
    )
}

$CSharpFilePath = Join-Path $ScriptDir "C2Sensor.cs"
if (-not (Test-Path $CSharpFilePath)) {
    Write-Diag "FATAL: Missing C# Engine Source: $CSharpFilePath" "CRITICAL"
    exit
}

Add-Type -Path $CSharpFilePath -ReferencedAssemblies $RefAssemblies
Write-Diag "C# Engine Compiled Natively into runspace." "STARTUP"

# ====================== 4. RUNTIME STRUCTURES ======================

# Thread-safe Process and Connection Tracking
$ProcessCache      = [System.Collections.Concurrent.ConcurrentDictionary[int, string]]::new()
$connectionHistory = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$flowMetadata      = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()

$global:TotalMitigations = 0
$global:globalMlSent = 0
$global:globalMlRcvd = 0
$global:globalMlAlerts = 0
$lastPingTime = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$OutboundNetEvents = 0

# High-Speed Batching Lists (Globalized for Submit-SensorAlert access)
$global:uebaBatch = [System.Collections.Generic.List[string]]::new()
$global:dataBatch = [System.Collections.Generic.List[PSCustomObject]]::new()

# Unified Deduplication Cache (Globalized to prevent null-expression crash)
$global:cycleAlerts = [System.Collections.Generic.Dictionary[string, object]]::new()

# Metrics Consolidation
$global:SensorStats = [PSCustomObject]@{
    MlSent      = 0
    MlRcvd      = 0
    Evaluated   = 0
    Alerts      = 0
    Mitigations = 0
    BootTime    = Get-Date
}

$dashboardDirty = $true
$lastMLRunTime = Get-Date
$lastCleanupTime = Get-Date
$lastLightGC = Get-Date
$lastUebaCleanup = Get-Date
$loggedFlows   = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
$SensorBlinded = $false
$LastEventReceived = Get-Date
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$LateralTrack = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$EgressTrack  = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$global:TotalLateralFlows = 0

# ============================================================== End

Write-Diag "Starting Real-Time ETW Session | Trace initiated... Follow the white rabbit. The Matrix has you, Neo...." "STARTUP"

# --- FFI BOOTSTRAP ---
$NetworkTI = Initialize-NetworkThreatIntel
[RealTimeC2Sensor]::InitializeEngine(
    $ScriptDir, 
    $DnsExclusions, 
    $ProcessExclusions, 
    $IpPrefixExclusions, 
    $NetworkTI.Keys, 
    $NetworkTI.Titles, 
    $WebDaemons, 
    $DbDaemons, 
    $ShellInterpreters, 
    $SuspiciousPaths
)
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
        $ruleName = "C2_Defend_Block_$DestIp"

        # Check if rule already exists (prevents bloat)
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            netsh advfirewall firewall add rule `
                name=$ruleName `
                dir=out `
                action=block `
                remoteip=$DestIp `
                protocol=any `
                description="C2Sensor Auto-Block - Confidence $Confidence - $Reason" | Out-Null

            $blockStatus = " | IP Blocked (new rule)"
            $global:TotalMitigations++
        }
        else {
            $blockStatus = " | IP Already Blocked"
        }
    }

    $targetStr = if ($DestIp) { "$ProcName -> $DestIp" } else { "$ProcName" }
    Add-AlertMessage "DEFENSE: Process $mitigationStatus$blockStatus ($targetStr)" $cYellow
}

# ====================== ALERT WINDOW ENGINE ======================
function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $prefix = "[$ts] "
    $maxLen = 98 - $prefix.Length

    # Safely strip ANSI color codes before calculating length
    $cleanText = $Message -replace "`e\[[0-9;]*m", ""
    if ($cleanText.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }

    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })

    if ($global:RecentAlerts.Count -gt 20) { $global:RecentAlerts.RemoveAt(0) }
    Draw-AlertWindow
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 10) # Slot perfectly under the 9-line Dashboard

    $logTrunc = if ($OutputPath.Length -gt 60) { "..." + $OutputPath.Substring($OutputPath.Length - 57) } else { $OutputPath }
    $headerPlain = "  [ LIVE THREAT TELEMETRY ] | Log: $logTrunc"
    $padHeader = " " * [math]::Max(0, (100 - $headerPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGreen[ LIVE THREAT TELEMETRY ]$cReset | Log: $cDark$logTrunc$cReset$padHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 20; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            $cleanText = $item.Text -replace "`e\[[0-9;]*m", ""
            $pad = " " * [math]::Max(0, (98 - $cleanText.Length))
            Write-Host "$cCyan║$cReset  $($item.Color)$($item.Text)$cReset$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset                                                                                                    $cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    # Anchor the cursor out of the way
    [Console]::SetCursorPosition(0, 36)
    [Console]::SetCursorPosition($curLeft, $curTop)
}

# ====================== DASHBOARD ENGINE ======================
function Draw-MonitorDashboard([int]$Events, [int]$Flows, [int]$Lateral, [int]$MlSent, [int]$Alerts, [string]$Tamper, [string]$MlHealth, [string]$SysGuard, [int]$Mitigations) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $evPad     = $Events.ToString().PadRight(9)
    $egressPad = $Flows.ToString().PadRight(5)
    $latPad    = $Lateral.ToString().PadRight(6)
    $mlPad     = "$MlSent / $MlSent".PadRight(9)
    $tamperPad = $Tamper.PadRight(9)
    $sysguardPad = $SysGuard.PadRight(9)
    $defFired = $Mitigations.ToString().PadRight(9)

    $TitlePlain = "  ⚡ C2 Beacon Sensor v2.0 | NetFlow Observability Dashboard"
    $StatusStr  = "  [ LIVE TELEMETRY ]"
    $Stats1Str  = "  Events Processed : $evPad | Active Egress  : $egressPad | Lateral P2P : $latPad"
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

    $TamperColor = if ($Tamper -eq "Good") { $cGreen } else { $cGold }
    $MlColor     = if ($MlHealth -eq "Native FFI") { $cGreen } else { $cGold }
    $GuardColor  = if ($SysGuard -eq "Secure") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGold⚡ C2 Beacon Sensor v2.0$cReset | NetFlow Observability Dashboard$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cOrange[ LIVE TELEMETRY ]$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Events Processed : $cCyan$evPad$cReset | Active Egress  : $cRed$egressPad$cReset | Lateral P2P : $cOrange$latPad$cReset$PadStats1$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ML Sent/Eval     : $cYellow$mlPad$cReset | Active Alerts  : $cGold$Alerts$cReset$PadStats2$cCyan║$cReset"
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

# ====================== MAIN EVENT LOOP ======================
Draw-AlertWindow

try {
    Write-Diag "    [*] Press 'Ctrl+C' or 'Q' to gracefully terminate the sensor." "STARTUP"
    while ($true) {
            $now = Get-Date
            $evtRef = $null
            $SysGuardState = "Secure"
            $eventCount = 0

            while ([RealTimeC2Sensor]::EventQueue.TryDequeue([ref]$evtRef)) {
                $evt = $evtRef
                $jsonStr = $evt.RawJson

                if (-not $evt) { continue }

                if ($evt.Provider -eq "DiagLog") { Write-Diag $evt.Message "INFO"; continue }
                if ($evt.Error) {
                    Write-Diag "FATAL ETW CRASH: $($evt.Error)" "ERROR"
                    Add-AlertMessage "FATAL ERROR: C# ETW THREAD CRASHED" $cRed
                    continue
                }

                $eventCount++
            if ($evt.Error) {
                Write-Diag "FATAL ETW CRASH: $($evt.Error)" "ERROR"
                Add-AlertMessage "FATAL ERROR: C# ETW THREAD CRASHED" $cRed
                continue
            }

            # --- NAMED PIPE DETECTION ---
            if ($evt.Provider -eq "P2P_Guard") {
                Submit-SensorAlert -Type "Lateral_Movement" -Destination "Local_Pipe" -Image $evt.Image -Flags "Malicious Named Pipe: $($evt.CommandLine)" -Confidence 95 -AttckMapping "T1570"
                continue
            }

            # --- TRAFFIC STATE TRACKING & PROXY NODE CORRELATION ---
            if ($evt.TrafficDirection) {
                $procKey = "$($evt.Image)_$($evt.PID)"

                if ($evt.TrafficDirection -eq "Lateral") {
                    $LateralTrack[$procKey] = $now
                    $global:TotalLateralFlows++
                } elseif ($evt.TrafficDirection -eq "Egress" -and $evt.DestIp) {
                    $EgressTrack[$procKey] = $now
                }

                # --- PROXY NODE CORRELATION ---
                if ($EgressTrack.ContainsKey($procKey) -and $LateralTrack.ContainsKey($procKey)) {
                    $timeDelta = [Math]::Abs(($EgressTrack[$procKey] - $LateralTrack[$procKey]).TotalSeconds)
                    if ($timeDelta -lt 60) {
                        Submit-SensorAlert -Type "Proxy_Node_Behavior" -Destination "Network_Bridge" -Image $evt.Image -Flags "Simultaneous Internal SMB/RPC and External Egress Routing" -Confidence 85 -AttckMapping "T1090.001"
                    }
                }
            }

            # --- TLS JA3 FINGERPRINT DETECTION ---
            if ($evt.Provider -eq "NDIS" -and $evt.EventName -eq "TLS_JA3_FINGERPRINT") {
                Write-Diag "JA3 HASH EXTRACTED: $($evt.DestIp) -> $($evt.JA3)" "INFO"

                if ($global:MaliciousJA3Cache.Contains($evt.JA3)) {
                    $owningProcess = "Unknown"
                    foreach ($k in $flowMetadata.Keys) {
                        if ($k -match "IP_$($evt.DestIp)") {
                            if ($flowMetadata[$k].image -ne "Unknown") {
                                $owningProcess = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$k].image)
                            }
                            break
                        }
                    }
                    Submit-SensorAlert -Type "JA3_C2_FINGERPRINT" -Destination $evt.DestIp -Image $owningProcess -Flags "Matched Abuse.ch JA3 Profile: $($evt.JA3)" -Confidence 100 -AttckMapping "T1071.001"
                }
                continue
            }

            # --- APPGUARD DETECTION ---
            if ($evt.Provider -eq "AppGuard") {
                Write-Diag "APPGUARD HIT: $($evt.Parent) spawned $($evt.Child) | CMD: $($evt.CommandLine)" "WARN"

                $MitreTags = if ($evt.EventName -eq "WEB_SHELL_DETECTED") { "T1505.003; T1190; T1059" } else { "T1190; T1569.002; T1059" }

                # Target the child process (shell) for mitigation to stop execution while logging the parent context
                Submit-SensorAlert -Type $evt.EventName -Destination "Local_Privilege_Escalation" -Image $evt.Child -Flags "Server App ($($evt.Parent)) Spawned Shell | Cmd: $($evt.CommandLine)" -Confidence 100 -AttckMapping $MitreTags
                continue
            }

            # --- NOISE REDUCTION FILTERS ---
            $procName = "Unknown"
            if (-not [string]::IsNullOrEmpty($evt.Image) -and $evt.Image -ne "Unknown") {
                $procName = [System.IO.Path]::GetFileNameWithoutExtension($evt.Image).ToLower()
            }
            elseif ($evt.PID -match '^\d+$' -and $evt.PID -ne "0" -and $evt.PID -ne "4") {
                $pidInt = [int]$evt.PID
                if (-not $ProcessCache.ContainsKey($pidInt)) {
                    try { 
                        $ProcessCache[$pidInt] = [System.Diagnostics.Process]::GetProcessById($pidInt).ProcessName.ToLower() 
                    } catch { 
                        $ProcessCache[$pidInt] = "terminated" 
                    }
                }
                $procName = $ProcessCache[$pidInt]
            }

            # --- SURICATA -> UEBA-DRIVEN ALERT ---
            if (-not [string]::IsNullOrEmpty($evt.ThreatIntel)) {
                $learningKey = "$procName|$($evt.ThreatIntel)"

                # Increment UEBA counter
                if (-not $global:UebaLearningCache.ContainsKey($learningKey)) {
                    $global:UebaLearningCache[$learningKey] = 0
                }
                $global:UebaLearningCache[$learningKey]++
                $tiHitCount = $global:UebaLearningCache[$learningKey]

                # Determine anomaly status and confidence
                $isAnomaly = $tiHitCount -ge 3
                $confidence = if ($isAnomaly) { 95 } else { 75 }

                $uebaContext = if ($tiHitCount -eq 1) { "NEW LEARNING" } elseif ($isAnomaly) { "CONFIRMED ANOMALY" } else { "LEARNING" }
                $enrichedFlags = "[$uebaContext] $($evt.ThreatIntel)"

                # Pre-evaluate the destination to prevent PowerShell parsing exceptions
                $targetDest = if ($evt.DestIp) { $evt.DestIp } else { $evt.Query }

                # Submit via centralized function.
                Submit-SensorAlert -Type "ThreatIntel_Match" `
                    -Destination $targetDest `
                    -Image $procName `
                    -Flags $enrichedFlags `
                    -Confidence $confidence `
                    -AttckMapping "T1071" `
                    -RawJson $jsonStr `
                    -LearningHit $tiHitCount
            }

            # Behavioral Property Logic (Static Rules)
            $props = [ordered]@{
                EventType = $evt.EventName
                Timestamp = [datetime]$evt.TimeStamp
                Image = $evt.Image
                SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                ATTCKMappings = [System.Collections.Generic.List[string]]::new()
                DestinationHostname = $evt.Query
                ThreatIntel = $evt.ThreatIntel
                Confidence = 85
            }

            if ($evt.Provider -eq "Microsoft-Windows-Kernel-Process" -and $evt.CommandLine -match '-EncodedCommand|-enc|IEX') {
                $props.SuspiciousFlags.Add("Anomalous CommandLine")
                $props.ATTCKMappings.Add("TA0002: T1059.001")
            }
            if ($evt.Provider -eq "Microsoft-Windows-Kernel-File" -and $evt.Image -match '\.ps1$|\.exe$') {
                $props.SuspiciousFlags.Add("Executable File Created")
                $props.ATTCKMappings.Add("TA0002: T1059")
            }
            if ($evt.Provider -eq "Microsoft-Windows-DNS-Client" -and $evt.Query) {
                if ($evt.Query.Length -gt 10 -and $evt.Query -match '^[a-zA-Z0-9\-\.]+$') {
                    $cleanQuery = $evt.Query.TrimEnd('.')
                    if (Is-AnomalousDomain $cleanQuery) {
                        $props.SuspiciousFlags.Add("DGA DNS Query Detected")
                        $props.ATTCKMappings.Add("TA0011: T1568.002")
                    }
                }
            }

            if ($evt.Provider -match "TCPIP|Network" -and 
                -not [string]::IsNullOrEmpty($evt.DestIp) -and 
                $evt.DestIp -notmatch '^192\.168\.|^10\.|^127\.|^172\.') {

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
                        dst_ips = [System.Collections.Generic.Queue[string]]::new()
                        packet_sizes = [System.Collections.Generic.Queue[int]]::new()
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
                    $flowMetadata[$key].dst_ips.Enqueue($evt.DestIp)

                    if ($evt.Size -match '^\d+$' -and $evt.Size -ne "0") {
                        $flowMetadata[$key].packet_sizes.Enqueue([int]$evt.Size)
                    } else {
                        $flowMetadata[$key].packet_sizes.Enqueue(0)
                    }

                    # STRICT SLIDING WINDOW
                    while ($connectionHistory[$key].Count -gt 100) {
                        [void]$connectionHistory[$key].Dequeue()
                    }
                    while ($flowMetadata[$key].dst_ips.Count -gt $connectionHistory[$key].Count) {
                        [void]$flowMetadata[$key].dst_ips.Dequeue()
                    }
                    while ($flowMetadata[$key].packet_sizes.Count -gt $connectionHistory[$key].Count) {
                        [void]$flowMetadata[$key].packet_sizes.Dequeue()
                    }
                }
            }

            # --- STATIC BEHAVIORAL FLUSH ---
            if ($props.SuspiciousFlags.Count -gt 0) {
                $safeDestStatic = if ($evt.DestIp) { $evt.DestIp } elseif ($evt.Query) { $evt.Query } else { "Unknown" }
                Submit-SensorAlert -Type "Static_Detection" -Destination $safeDestStatic -Image $procName -Flags ($props.SuspiciousFlags -join '; ') -Confidence 90 -AttckMapping ($props.ATTCKMappings -join '; ')
            }
        }

        # ---------------- NATIVE FFI ML HANDOFF PIPELINE ----------------
        if (($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {
            $payloadArray = [System.Collections.Generic.List[object]]::new()

            foreach ($key in $connectionHistory.Keys) {
                $count = $connectionHistory[$key].Count
                if ($count -ge $MinSamplesForML) {

                    if (($now - $lastPingTime[$key]).TotalSeconds -gt 120) { continue }

                    if (-not $loggedFlows.ContainsKey($key) -or $loggedFlows[$key] -ne $count) {
                        $loggedFlows[$key] = $count
                        $arr = $connectionHistory[$key].ToArray()

                        $duration = [Math]::Round(($arr[-1] - $arr[0]).TotalSeconds, 2)
                        $firstPing = $arr[0].ToString("yyyy-MM-dd HH:mm:ss")

                        $ipArr = $flowMetadata[$key].dst_ips.ToArray()
                        $sizeArr = $flowMetadata[$key].packet_sizes.ToArray()

                        $destIp = $ipArr[-1]
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

                        $intervals = [System.Collections.Generic.List[double]]::new()
                        $aligned_ips = [System.Collections.Generic.List[string]]::new()
                        $aligned_sizes = [System.Collections.Generic.List[int]]::new()

                        for ($i = 1; $i -lt $arr.Count; $i++) {
                            $intervals.Add([Math]::Round(($arr[$i] - $arr[$i-1]).TotalSeconds, 2))
                            if ($i -lt $ipArr.Length) { $aligned_ips.Add($ipArr[$i]) }
                            if ($i -lt $sizeArr.Length) { $aligned_sizes.Add($sizeArr[$i]) }
                        }

                        $payloadArray.Add(@{
                            key = $key
                            intervals = $intervals
                            domain = $flowMetadata[$key].domain
                            dst_ips = $aligned_ips
                            packet_sizes = $aligned_sizes
                        })
                    }
                }
            }

            if ($payloadArray.Count -gt 0) {
                $globalMlSent++
                $jsonPayload = $payloadArray | ConvertTo-Json -Depth 6 -Compress

                if (-not $jsonPayload.StartsWith("[")) { $jsonPayload = "[$jsonPayload]" }

                Write-Diag "Executing Native FFI Memory Map. Arrays: $($payloadArray.Count) | Payload Size: $($jsonPayload.Length)" "FFI-TX"

                $mlResponseString = [RealTimeC2Sensor]::EvaluateBatch($jsonPayload)

                if ($mlResponseString -ne "{}" -and $mlResponseString -ne "") {
                    $globalMlRcvd++
                    Write-Diag "FFI-RX: Received response from Rust engine" "FFI-RX"

                    try {
                        $mlResults = $mlResponseString | ConvertFrom-Json -ErrorAction Stop

                        if ($mlResults.daemon_error) {
                            Write-Diag "RUST ML ENGINE ERROR: $($mlResults.daemon_error)" "ERROR"
                            Add-AlertMessage "ML ENGINE ERROR: $($mlResults.daemon_error)" $cRed
                        } elseif ($mlResults.alerts) {
                            foreach ($alert in $mlResults.alerts) {
                                $globalMlAlerts++
                                $alertKey = $alert.key
                                $pidVal = "Unknown"; if ($alertKey -match "PID_(\d+)") { $pidVal = $matches[1] }

                                $resolvedImage = "Unknown"
                                if ($flowMetadata.ContainsKey($alertKey) -and $flowMetadata[$alertKey].image -ne "Unknown") {
                                    $resolvedImage = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$alertKey].image)
                                } elseif ($pidVal -match '^\d+$') {
                                    try { $resolvedImage = (Get-Process -Id $pidVal -ErrorAction Stop).Name } catch { $resolvedImage = "Terminated" }
                                }

                                $targetIp = "Unknown"; if ($alertKey -match "IP_([0-9\.]+)") { $targetIp = $matches[1] }

                                Submit-SensorAlert -Type "ML_Beacon" -Destination $targetIp -Image $resolvedImage -Flags $alert.alert_reason -Confidence $alert.confidence -AttckMapping "T1071"
                            }
                        }
                    } catch {
                        Write-Diag "JSON Parse Failure from Rust Engine: $mlResponseString" "ERROR"
                    }
                }
            }

            # === STALE FLOW CLEANUP ===
            if (($now - $lastCleanupTime).TotalSeconds -ge 60) {
                $staleKeys = [System.Collections.Generic.List[string]]::new()

                # Check $lastPingTime instead of converting queues to arrays (O(1) memory instead of O(N))
                foreach ($k in $lastPingTime.Keys) {
                    if (($now - $lastPingTime[$k]).TotalSeconds -gt 300) { 
                        $staleKeys.Add($k)
                    }
                }

                foreach ($k in $staleKeys) {
                    ([System.Collections.IDictionary]$connectionHistory).Remove($k)
                    ([System.Collections.IDictionary]$flowMetadata).Remove($k)
                    ([System.Collections.IDictionary]$loggedFlows).Remove($k)
                    ([System.Collections.IDictionary]$lastPingTime).Remove($k)
                }
                $lastCleanupTime = $now
            }

            # FLUSH DEDUPLICATED ALERTS TO HUD & JSONL
            foreach ($alert in $global:cycleAlerts.Values) {
                $global:dataBatch.Add($alert)
                $countTag = if ($alert.Count -gt 1) { " (x$($alert.Count))" } else { "" }

                # Render to HUD
                if ($alert.EventType -eq "JA3_C2_FINGERPRINT") {
                    Add-AlertMessage "JA3 FINGERPRINT: $($alert.Image) -> $($alert.Destination)$countTag" $cRed
                } elseif ($alert.Destination -eq "Local_Privilege_Escalation") {
                    Add-AlertMessage "APPGUARD BLOCK: $($alert.Image) spawned $($alert.SuspiciousFlags)$countTag" $cRed
                } elseif ($alert.EventType -eq "ML_Beacon") {
                    Add-AlertMessage "ML ($($alert.Confidence)%): $($alert.SuspiciousFlags) ($($alert.Image))$countTag" $cRed
                } else {
                    Add-AlertMessage "STATIC: $($alert.SuspiciousFlags) ($($alert.Image))$countTag" $cWhite
                }

                # Trigger Active Defense once per clustered threat
                if ($alert.Action -eq "Mitigated" -or $alert.Confidence -ge 90) {
                    if ($alert.Destination -ne "Local_Privilege_Escalation" -and 
                        $alert.EventType -ne "ThreatIntel_Match") {
                        Invoke-ActiveDefense -ProcName $alert.Image -DestIp $alert.Destination -Confidence $alert.Confidence -Reason $alert.SuspiciousFlags
                    }
                }
            }

            $global:cycleAlerts.Clear() # IMPORTANT: Empty the cache for the next 15-second cycle

            $lastMLRunTime = $now
        }

        # --- LOG ROTATION & GROOMING ENGINE ---
        if ($dataBatch.Count -gt 0) {
            if (Test-Path $OutputPath) {
                if ((Get-Item $OutputPath).Length -gt 50MB) {
                    $archiveName = $OutputPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    try { Move-Item -Path $OutputPath -Destination $archiveName -Force -ErrorAction Stop; Write-Diag "Alert log rotated." "INFO" } catch { Write-Diag "Alert log rotation failed: $($_.Exception.Message)" "WARN" }
                }
            }
            $batchOutput = ($dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            try { [System.IO.File]::AppendAllText($OutputPath, $batchOutput + "`r`n") } catch { }
            $dataBatch.Clear()
        }

        if ($uebaBatch.Count -gt 0) {
            if (Test-Path $UebaLogPath) {
                if ((Get-Item $UebaLogPath).Length -gt 50MB) {
                    $archiveName = $UebaLogPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    try { Move-Item -Path $UebaLogPath -Destination $archiveName -Force -ErrorAction Stop; Write-Diag "UEBA log rotated." "INFO" } catch { Write-Diag "UEBA log rotation failed: $($_.Exception.Message)" "WARN" }
                }
            }
            $uebaOutput = $uebaBatch -join "`r`n"
            try { [System.IO.File]::AppendAllText($UebaLogPath, $uebaOutput + "`r`n") } catch { }
            $uebaBatch.Clear()
        }

        # === DISK & MEMORY PROTECTION: GARBAGE COLLECTION ===
        if ($now.Minute -eq 0 -and $now.Second -lt 15) {
            # 1. Prune Stale Logs
            $RetentionDays = 3
            $staleLogs = Get-ChildItem -Path $LogDir -Filter "*.jsonl" | Where-Object { $_.LastWriteTime -lt $now.AddDays(-$RetentionDays) }
            foreach ($stale in $staleLogs) {
                Remove-Item -Path $stale.FullName -Force -ErrorAction SilentlyContinue
                Write-Diag "Disk Protection: Groomed stale log file -> $($stale.Name)" "INFO"
            }
        }

        # === LIGHT MEMORY PROTECTION: GARBAGE COLLECTION (every 60 seconds) ===
        if (($now - $lastLightGC).TotalSeconds -ge 60) {
            [System.GC]::Collect(1, [System.GCCollectionMode]::Optimized)
            $lastLightGC = $now
        }

        # === DEEP MEMORY PROTECTION: GARBAGE COLLECTION (every 30 minutes) ===
        if (($now - $lastUebaCleanup).TotalMinutes -ge 30 -or $global:UebaLearningCache.Count -gt 30000) {
            $global:UebaLearningCache.Clear()

            # Clear unbounded correlation trackers to prevent infinite growth
            $LateralTrack.Clear()
            $EgressTrack.Clear()
            $ProcessCache.Clear()

            # Instruct the .NET Garbage Collector to aggressively reclaim memory
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            $lastUebaCleanup = $now
            Write-Diag "Deep Memory protection executed. Caches flushed and GC forced." "INFO"
        }

        $activeFlows = $connectionHistory.Keys.Count

        if ($eventCount -gt 0) {
            $LastEventReceived = $now
        }

        $tamperStatus = "Good"

        # 1. C# session is still alive?
        if (-not [RealTimeC2Sensor]::IsSessionHealthy()) {
            $tamperStatus = "BAD"
        }

        # 2. No events received for more than 3 minutes?
        if (($now - $LastEventReceived).TotalMinutes -gt 3) {
            $tamperStatus = "BAD"
        }

        if ($dashboardDirty -or $eventCount -gt 0) {
            Draw-MonitorDashboard -Events $eventCount -Flows $activeFlows -Lateral $global:TotalLateralFlows -MlSent $globalMlSent -Alerts $globalMlAlerts -Tamper $tamperStatus -MlHealth "Native FFI" -SysGuard $SysGuardState -Mitigations $global:TotalMitigations
            $dashboardDirty = $false
        }

        if ($tamperStatus -eq "BAD") {
            if (-not $SensorBlinded) {
                $SensorBlinded = $true
                Add-AlertMessage "CRITICAL ALARM: SENSOR BLINDED. INITIATING AUTO-RECOVERY..." $cRed
                Write-Diag "SENSOR BLINDED: ETW thread unresponsive. Initiating auto-recovery." "ERROR"
            }

            # --- ACTIVE AUTO-RECOVERY ENGINE ---
            try {
                Write-Diag "Auto-Recovery: Tearing down dead ETW session..." "INFO"
                [RealTimeC2Sensor]::StopSession()

                # OS-LEVEL FAILSAFE: Force terminate the trace via logman to prevent Zombie lockups
                logman stop "C2RealTimeSession" -ets -ErrorAction SilentlyContinue

                Start-Sleep -Seconds 2

                Write-Diag "Auto-Recovery: Re-initializing native ETW session..." "INFO"
                [RealTimeC2Sensor]::StartSession()

                $LastEventReceived = $now # Reset the starvation timer
                $SensorBlinded = $false
                Add-AlertMessage "SENSOR RECOVERED: ETW SESSION RESTORED" $cGreen
            } catch {
                Write-Diag "Auto-Recovery failed: $($_.Exception.Message). Retrying next cycle." "ERROR"
            }
        }
        Start-Sleep -Milliseconds 200
    }

} catch {
    $errMsg = $_.Exception.Message
    $fullErr = $_.Exception | Format-List -Force | Out-String
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $errMsg" -ForegroundColor Red
    Write-Diag "ORCHESTRATOR FATAL CRASH: $errMsg`n$fullErr" "CRITICAL"
} finally {
    Clear-Host
    Write-Host "`n[*] Initiating Graceful Shutdown..." -ForegroundColor Cyan

    Write-Diag "Initiating Teardown Sequence..." "INFO"

    Write-Host "    [*] Finalizing Kernel Telemetry & ML Database..." -ForegroundColor Gray
    try { [RealTimeC2Sensor]::StopSession() } catch {}
    Write-Diag "C# TraceEvent Session Halted." "INFO"

    Write-Host "    [*] Cleaning up centralized library artifacts..." -ForegroundColor Gray
    $StagingPath = "C:\ProgramData\C2Sensor\Staging"
    if (Test-Path $StagingPath) {
        Remove-Item -Path "$StagingPath\*.zip" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$StagingPath\TraceEventPackage" -Recurse -Force -ErrorAction SilentlyContinue
    }

$TempLibPath = Join-Path "C:\ProgramData\C2Sensor\Dependencies" "TraceEvent"
    if (Test-Path $TempLibPath) { Remove-Item -Path $TempLibPath -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"

    if ($global:DiagWriter) { $global:DiagWriter.Close(); $global:DiagStream.Dispose() }
    if ($global:TamperWriter) { $global:TamperWriter.Close(); $global:TamperStream.Dispose() }

    Write-Host "`n[+] Teardown Complete." -ForegroundColor Green
}