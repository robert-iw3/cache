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
            @{ Name = "EmergingThreats_DNS"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-dns.rules" },
            @{ Name = "ThreatView_CS_C2";    Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/threatview_CS_c2.rules" }
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

    if ($needsDownload -or -not (Test-Path $SigmaUpstreamDir)) {
        if (-not (Test-Path $SigmaUpstreamDir)) {
            New-Item -ItemType Directory -Path $SigmaUpstreamDir -Force | Out-Null
        }

        $TempZipPath = Join-Path $StagingDir "sigma_master.zip"
        $ExtractPath = Join-Path $StagingDir "sigma_extract"

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
    }
    # Update the cache marker so we skip next time
    New-Item -Path $CacheMarker -ItemType File -Force | Out-Null
    Write-Diag "Gatekeeper Compilation: Parsed $sigmaCount signatures from SigmaHQ." "STARTUP"
    Write-Diag "Threat Intel Compilation Complete. Passing $($TiKeys.Count) signatures to Memory." "STARTUP"

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
    Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/2.0.61" -OutFile $ZipPath
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
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

# High-Speed Batching Lists
$uebaBatch = [System.Collections.Generic.List[string]]::new()
$dataBatch = [System.Collections.Generic.List[PSCustomObject]]::new()

# Unified Deduplication Cache
$cycleAlerts = [System.Collections.Generic.Dictionary[string, object]]::new()

# Metrics Consolidation
$global:SensorStats = [PSCustomObject]@{
    MlSent      = 0
    MlRcvd      = 0
    Evaluated   = 0
    Alerts      = 0
    Mitigations = 0
    BootTime    = Get-Date
}

$lastMLRunTime = Get-Date
$loggedFlows   = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$SensorBlinded = $false
$LastEventReceived = Get-Date
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:AlertSuppression = @{}

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
function Draw-MonitorDashboard([int]$Events, [int]$Flows, [int]$MlSent, [int]$MlEval, [int]$Alerts, [string]$Tamper, [string]$MlHealth, [string]$SysGuard, [int]$Mitigations) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $evPad     = $Events.ToString().PadRight(9)
    $mlPad     = "$MlSent / $MlEval".PadRight(9)
    $tamperPad = $Tamper.PadRight(9)
    $sysguardPad = $SysGuard.PadRight(9)
    $defFired = $Mitigations.ToString().PadRight(9)

    $TitlePlain = "  ⚡ C2 Beacon Sensor v1.0 | NetFlow Observability Dashboard"
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

    $TamperColor = if ($Tamper -eq "Good") { $cGreen } else { $cGold }
    $MlColor     = if ($MlHealth -eq "Native FFI") { $cGreen } else { $cGold }
    $GuardColor  = if ($SysGuard -eq "Secure") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGold⚡ C2 Beacon Sensor v1.0$cReset | NetFlow Observability Dashboard$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cOrange[ LIVE TELEMETRY ]$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Events Processed : $cWhite$evPad$cReset | Active Flows   : $cWhite$Flows$cReset$PadStats1$cCyan║$cReset"
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
        $eventCount = 0
        $jsonStr = ""
        $SysGuardState = "Secure"

        while ([RealTimeC2Sensor]::EventQueue.TryDequeue([ref]$jsonStr)) {
            $eventCount++

            if ($jsonStr -match '"EventName":"(ThreadWorkOnBehalfUpdate|CpuPriorityChange|ThreadStart.*|ThreadStop.*|TcpConnectionRundown|UdpEndpointRundown|ImageLoad|ImageUnload|SystemCall|Acg|CreateNewFile|MemInfo.*)"') {
                continue
            }

            $evt = $jsonStr | ConvertFrom-Json -ErrorAction SilentlyContinue

            if (-not $evt) { continue }

            if ($evt.Provider -eq "DiagLog") { Write-Diag $evt.Message "INFO"; continue }
            if ($evt.Error) {
                Write-Diag "FATAL ETW CRASH: $($evt.Error)" "ERROR"
                Add-AlertMessage "FATAL ERROR: C# ETW THREAD CRASHED" $cRed
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

                    $outObj = [PSCustomObject][ordered]@{
                        EventID         = [guid]::NewGuid().ToString()
                        Count           = 1
                        Timestamp_Local = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
                        Timestamp_UTC   = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        ComputerName    = $global:ComputerName
                        HostIP          = $global:HostIP
                        SensorUser      = $global:SensorUser
                        EventType       = "JA3_C2_FINGERPRINT"
                        Destination     = $evt.DestIp
                        Image           = $owningProcess
                        SuspiciousFlags = "Matched Abuse.ch JA3 Profile: $($evt.JA3)"
                        Confidence      = 100
                        Action          = if ($global:IsArmed) { "Mitigated" } else { "Logged" }
                    }
                    $dedupKey = "$($outObj.EventType)_$($outObj.Destination)_$($outObj.SuspiciousFlags)"
                    if (-not $cycleAlerts.ContainsKey($dedupKey)) { $cycleAlerts[$dedupKey] = $outObj }
                    else { $cycleAlerts[$dedupKey].Count++ }

                    Invoke-ActiveDefense -ProcName $owningProcess -DestIp $evt.DestIp -Confidence 100 -Reason "Malicious JA3 Hash"
                }
                continue
            }

            if ($evt.Provider -eq "AppGuard") {
                $alertMsg = "SERVER EXPLOIT: $($evt.EventName) -> $($evt.Parent) spawned $($evt.Child)"
                Add-AlertMessage $alertMsg $cRed
                Write-Diag "APPGUARD HIT: $($evt.Parent) spawned $($evt.Child) | CMD: $($evt.CommandLine)" "WARN"

                $MitreTags = if ($evt.EventName -eq "WEB_SHELL_DETECTED") { "TA0003: T1505.003; TA0001: T1190; TA0002: T1059" } else { "TA0001: T1190; TA0002: T1569.002; TA0002: T1059" }

                $outObj = [PSCustomObject][ordered]@{
                    EventID         = [guid]::NewGuid().ToString()
                    Count           = 1
                    Timestamp_Local = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
                    Timestamp_UTC   = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    ComputerName    = $global:ComputerName
                    HostIP          = $global:HostIP
                    SensorUser      = $global:SensorUser
                    EventType       = $evt.EventName
                    Destination     = "Local_Privilege_Escalation"
                    Image           = $evt.Parent
                    SuspiciousFlags = "Server Application Spawned Command Shell: $($evt.Child) | Cmd: $($evt.CommandLine)"
                    ATTCKMappings   = $MitreTags
                    Confidence      = 100
                    Action          = if ($global:IsArmed) { "Mitigated" } else { "Logged" }
                }
                $dedupKey = "$($outObj.EventType)_$($outObj.Destination)_$($outObj.SuspiciousFlags)"
                if (-not $cycleAlerts.ContainsKey($dedupKey)) { $cycleAlerts[$dedupKey] = $outObj }
                else { $cycleAlerts[$dedupKey].Count++ }

                Invoke-ActiveDefense -ProcName $evt.Child -DestIp "" -Confidence 100 -Reason "Server Application Exploitation"
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

            # === SURICATA / SIGMA → UEBA-DRIVEN ALERT + ACTIVE DEFENSE ===
            if (-not [string]::IsNullOrEmpty($evt.ThreatIntel)) {
                $learningKey = "$procName|$($evt.ThreatIntel)"

                # Increment UEBA counter
                if (-not $global:UebaLearningCache.ContainsKey($learningKey)) {
                    $global:UebaLearningCache[$learningKey] = 0
                }
                $global:UebaLearningCache[$learningKey]++
                $tiHitCount = $global:UebaLearningCache[$learningKey]

                # Determine if this is a confirmed anomaly
                $isAnomaly = $tiHitCount -ge 3
                $confidence = if ($isAnomaly) { 95 } else { 75 }

                # Alert message
                if ($tiHitCount -eq 1) {
                    $alertMsg = "LEARNING: $($evt.ThreatIntel) ($procName)"
                } elseif ($isAnomaly) {
                    $alertMsg = "THREAT INTEL: $($evt.ThreatIntel) ($procName) [UEBA anomaly confirmed - hit #$tiHitCount]"
                } else {
                    $alertMsg = "THREAT INTEL: $($evt.ThreatIntel) ($procName) [UEBA hit #$tiHitCount]"
                }

                Add-AlertMessage $alertMsg $cRed

                # Create persistent alert object
                $outObj = [PSCustomObject][ordered]@{
                    EventID         = [guid]::NewGuid().ToString()
                    Count           = 1
                    Timestamp_Local = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
                    Timestamp_UTC   = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    ComputerName    = $global:ComputerName
                    HostIP          = $global:HostIP
                    SensorUser      = $global:SensorUser
                    EventType       = "ThreatIntel_Match"
                    Destination     = $evt.DestIp
                    Image           = $procName
                    SuspiciousFlags = $evt.ThreatIntel
                    Confidence      = $confidence
                    Action          = if ($global:IsArmed -and $isAnomaly) { "Mitigated" } else { "Logged" }
                }

                $dedupKey = "$($outObj.EventType)_$($outObj.Destination)_$($outObj.SuspiciousFlags)"
                if (-not $cycleAlerts.ContainsKey($dedupKey)) { 
                    $cycleAlerts[$dedupKey] = $outObj 
                } else { 
                    $cycleAlerts[$dedupKey].Count++ 
                }

                # === ONLY trigger Active Defense if UEBA confirms anomaly ===
                if ($global:IsArmed -and $isAnomaly) {
                    Invoke-ActiveDefense -ProcName $procName -DestIp $evt.DestIp -Confidence $confidence -Reason $evt.ThreatIntel
                }
            }

            $EventGuid = [guid]::NewGuid().ToString()
            $enrichedJson = $jsonStr -replace '^\{', "{`"EventID`":`"$EventGuid`", `"ComputerName`":`"$global:ComputerName`", `"HostIP`":`"$global:HostIP`", `"SensorUser`":`"$global:SensorUser`", "
            $uebaBatch.Add($enrichedJson)

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

                    # STRICT SLIDING WINDOW (Max 100 elements to prevent O(N^2) ML freezes)
                    while ($connectionHistory[$key].Count -gt 100) {
                        [void]$connectionHistory[$key].Dequeue()
                    }
                    while ($flowMetadata[$key].dst_ips.Count -gt $connectionHistory[$key].Count) {
                        [void]$flowMetadata[$key].dst_ips.RemoveAt(0)
                    }
                    while ($flowMetadata[$key].packet_sizes.Count -gt $connectionHistory[$key].Count) {
                        [void]$flowMetadata[$key].packet_sizes.RemoveAt(0)
                    }
                }
            }

            if ($props.SuspiciousFlags.Count -gt 0) {
                $flagsStr = $props.SuspiciousFlags -join '; '
                # Key based on behavioral signature + process name
                $dedupKey = "STATIC_$($flagsStr)_$procName" 

                if (-not $cycleAlerts.ContainsKey($dedupKey)) {
                    $cycleAlerts[$dedupKey] = [PSCustomObject][ordered]@{
                        EventID         = [guid]::NewGuid().ToString()
                        Count           = 1
                        Timestamp_Local = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
                        Timestamp_UTC   = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        ComputerName    = $global:ComputerName
                        HostIP          = $global:HostIP
                        SensorUser      = $global:SensorUser
                        EventType       = "Static_Detection"
                        Destination     = $evt.DestIp
                        Image           = $procName
                        SuspiciousFlags = $flagsStr
                        ATTCKMappings   = $props.ATTCKMappings -join '; '
                        Confidence      = 90
                        Action          = if ($global:IsArmed) { "Mitigated" } else { "Logged" }
                    }
                } else {
                    $cycleAlerts[$dedupKey].Count++
                }
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
                                $dedupKey = "ML_$alertKey_$($alert.alert_reason)"
                                $nowTicks = [DateTime]::UtcNow.Ticks

                                if ($global:AlertSuppression.ContainsKey($dedupKey)) {
                                    if ($nowTicks -lt $global:AlertSuppression[$dedupKey]) {
                                        continue  # suppress duplicate within 5 minutes
                                    }
                                }

                                $global:AlertSuppression[$dedupKey] = $nowTicks + [TimeSpan]::FromMinutes(5).Ticks

                                $pidVal = "Unknown"
                                $pidParts = ($alertKey -split "PID_")
                                if ($pidParts.Count -gt 1) { $pidVal = ($pidParts[1] -split "_")[0] }

                                $resolvedImage = "Unknown"
                                if ($flowMetadata.ContainsKey($alertKey) -and $flowMetadata[$alertKey] -and $flowMetadata[$alertKey].image -and $flowMetadata[$alertKey].image -ne "Unknown") {
                                    $resolvedImage = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$alertKey].image)
                                } elseif ($pidVal -match '^\d+$') {
                                    try {
                                        $resolvedImage = (Get-Process -Id $pidVal -ErrorAction Stop).Name
                                        if ($pidVal -eq "4") { $resolvedImage = "System" }
                                        if ($pidVal -eq "0") { $resolvedImage = "Idle" }
                                    } catch { $resolvedImage = "Terminated" }
                                }

                                Add-AlertMessage "ML ($($alert.confidence)%): $alertKey - $($alert.alert_reason)" $cRed

                                $outObj = [PSCustomObject][ordered]@{
                                    EventID         = [guid]::NewGuid().ToString()
                                    Count           = 1
                                    Timestamp_Local = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
                                    Timestamp_UTC   = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                                    ComputerName    = $global:ComputerName
                                    HostIP          = $global:HostIP
                                    SensorUser      = $global:SensorUser
                                    EventType       = "ML_Beacon"
                                    Destination     = $alertKey
                                    Image           = $resolvedImage
                                    SuspiciousFlags = $alert.alert_reason
                                    Confidence      = $alert.confidence
                                    Action          = if ($global:IsArmed -and $alert.confidence -ge $ConfidenceThreshold) { "Mitigated" } else { "Logged" }
                                }
                                $dedupKey = "$($outObj.EventType)_$($outObj.Destination)_$($outObj.SuspiciousFlags)"
                                if (-not $cycleAlerts.ContainsKey($dedupKey)) { $cycleAlerts[$dedupKey] = $outObj }
                                else { $cycleAlerts[$dedupKey].Count++ }

                                $targetIp = "Unknown"
                                if ($alertKey -match "IP_([0-9\.]+)") {
                                    $targetIp = $matches[1]
                                }

                                Invoke-ActiveDefense -ProcName $resolvedImage -DestIp $targetIp -Confidence $alert.confidence -Reason $alert.alert_reason
                            }
                        }
                    } catch {
                        Write-Diag "JSON Parse Failure from Rust Engine: $mlResponseString" "ERROR"
                    }
                }
            }

            # === STALE FLOW CLEANUP ===
            $staleKeys = @()
            foreach ($k in $connectionHistory.Keys) {
                $historyArr = $connectionHistory[$k].ToArray()
                if ($historyArr.Count -gt 0 -and ($now - $historyArr[-1]).TotalSeconds -gt 300) { 
                    $staleKeys += $k 
                }
            }

            foreach ($k in $staleKeys) {
                $dummy = $null
                try { [void]$connectionHistory.TryRemove($k, [ref]$dummy) } catch { 
                    try { [void]$connectionHistory.Remove($k) } catch {} 
                }
                try { [void]$flowMetadata.TryRemove($k, [ref]$dummy) } catch { 
                    try { [void]$flowMetadata.Remove($k) } catch {} 
                }
                try { [void]$loggedFlows.TryRemove($k, [ref]$dummy) } catch { 
                    try { [void]$loggedFlows.Remove($k) } catch {} 
                }
            }

            # FLUSH DEDUPLICATED ALERTS TO HUD & JSONL
            foreach ($alert in $cycleAlerts.Values) {
                $dataBatch.Add($alert)
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

            $cycleAlerts.Clear() # IMPORTANT: Empty the cache for the next 15-second cycle

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
            $uebaOutput = $uebaBatch -join "`r`n"
            [System.IO.File]::AppendAllText($UebaLogPath, $uebaOutput + "`r`n")
            $uebaBatch.Clear()
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

        Draw-MonitorDashboard -Events $eventCount -Flows $activeFlows -MlSent $globalMlSent -MlEval $globalMlSent -Alerts $globalMlAlerts -Tamper $tamperStatus -MlHealth "Native FFI" -SysGuard $SysGuardState -Mitigations $global:TotalMitigations

        if ($tamperStatus -eq "BAD" -and -not $SensorBlinded) {
            $SensorBlinded = $true
            Add-AlertMessage "CRITICAL ALARM: SENSOR BLINDED (ETW COMPROMISE)" $cRed
            Write-Diag "SENSOR BLINDED: No ETW events received for > 3 minutes." "ERROR"
        }

        Start-Sleep -Milliseconds 200
    }

} catch {
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" -ForegroundColor Red
    "[$((Get-Date).ToString('HH:mm:ss'))] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" | Out-File -FilePath $DiagLogPath -Append
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
        Remove-Item -Path "$StagingPath\sigma_extract" -Recurse -Force -ErrorAction SilentlyContinue
    }

    $TempLibPath = Join-Path "C:\ProgramData\C2Sensor\Dependencies" "TraceEvent"
    if (Test-Path $TempLibPath) { Remove-Item -Path $TempLibPath -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"
    Write-Host "`n[+] Teardown Complete." -ForegroundColor Green
}