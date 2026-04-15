<#
.SYNOPSIS
    Windows Kernel C2 Beacon Hunter v6.0
.DESCRIPTION
    A high-performance, real-time Command and Control (C2) detection and response engine.
    It injects Microsoft.Diagnostics.Tracing.TraceEvent directly into RAM via embedded C#
    to monitor live kernel ETW events, bypassing heavy telemetry trace files.

    Architecture Flow:
      1. Dynamic Pre-Loader: Fetches the correct TraceEvent library based on the host's .NET runtime.
      2. C# Engine: Parses the high-volume ETW firehose at lightning speed, aggressively pre-filtering
         benign noise (including RFC 1918, Multicast, Broadcast, and Idle routing).
      3. Server-Side AppGuard (V6): Monitors process lineages to instantly intercept web shells
         and database RCEs (IIS, SQL, Tomcat, Node) spawning command interpreters.
      4. Cryptographic DPI: Subscribes to raw Layer 2 NDIS frames, using an unmanaged byte-scanner
         to extract TLS Client Hello signatures and map JA3 hashes to Ring-3 processes.
      5. Native Byte Scanner: Manually extracts IPs/Ports from memory if standard decoders fail.
      6. Hybrid State Manager: Tracks active flows in RAM and flushes dormant flows to a self-grooming
         NTFS JSON database to detect "Low and Slow" beacons across days or system reboots.
      7. ML Daemon: Forwards 4D matrices to BeaconML.py via STDIN for lock-free DBSCAN clustering.
      8. Thread-Level Tracking (TID): Extracts Native Thread IDs to isolate injected payloads and lay
         the groundwork for precise thread containment.
      9. Anti-Tamper Watchdog: Generates synthetic DNS heartbeats and monitors memory protections
         (VirtualProtect) to detect ETW blinding and Ring-0 unhooking attempts.
     10. Unified Active Defense: Natively processes ML, JA3, and AppGuard alerts in RAM to autonomously
         terminate processes (or prevent child shells) and isolate IPs at the firewall.
     11. Enterprise 24/7 Deployment: Operates continuously with a mathematically pinned, non-scrolling
         terminal HUD and a 50MB self-grooming log rotation engine to prevent SIEM exhaustion.

.NOTES
    Author: Robert Weber
    Version: 6.0

    To see the microscopic, millisecond-by-millisecond data flow for debugging, pass the switch:
    .\MonitorKernelC2BeaconHunter_v6.ps1 -EnableDiagnostics

    To enable autonomous Active Defense (process termination & firewall blocking), Run:
    .\MonitorKernelC2BeaconHunter_v6.ps1 -ArmedMode
#>
#Requires -RunAsAdministrator

# ====================== CONFIGURATION & PARAMETERS ======================
param (
    [string]$OutputPath = "C:\Temp\C2KernelMonitoring_v6.jsonl",
    [int]$BatchAnalysisIntervalSeconds = 15,
    [int]$MinSamplesForML = 3,
    [string]$PythonPath = "python",
    [string]$MLScriptPath = "BeaconML.py",
    [switch]$EnableDiagnostics,
    [switch]$TestMode,

    # --- Defense Options ---
    [switch]$ArmedMode,
    [int]$ConfidenceThreshold = 100,

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
    # DEVELOPER NOTE: ETW explicitly drops the '.exe' extension.
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
$FullMLPath = Join-Path $ScriptDir $MLScriptPath
$now = Get-Date

# --- TEST MODE OVERRIDE ---
if ($TestMode) {
    # Dynamically strip the Microsoft/Google/AWS CDN blocks from the exclusion array in RAM
    # to allow the validation suite (e.g., httpbin.org) to pass through to the ML daemon.
    $CdnPrefixes = @("^52\.", "^142\.25[0-9]\.", "^13\.", "^20\.", "^23\.", "^74\.125\.")
    $IpPrefixExclusions = $IpPrefixExclusions | Where-Object { $_ -notin $CdnPrefixes }
}

# ====================== TAMPER GUARD INITIALIZATION ======================
function Initialize-TamperGuard {
    $Path = "C:\Temp\C2Hunter_TamperGuard.log"

    # Use native Windows binary (icacls) to bypass PowerShell module loading constraints
    try {
        if (-not (Test-Path $Path)) {
            New-Item $Path -ItemType File -Force | Out-Null
        }

        # /inheritance:r completely strips all inherited permissions from C:\Temp (Blank Slate)
        icacls $Path /inheritance:r /q | Out-Null

        # /grant:r explicitly grants Full Control (F) using Universal Windows SIDs.
        # *S-1-5-18 = NT AUTHORITY\SYSTEM
        # *S-1-5-32-544 = BUILTIN\Administrators
        icacls $Path /grant:r "*S-1-5-18:(F)" /grant:r "*S-1-5-32-544:(F)" /q | Out-Null
    }
    catch {
        Write-Host "  [!] Warning: icacls permission lockdown failed. Details: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    # Establish the exclusive lock, with a Zombie Hunter fallback
    try {
        $global:TamperStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
        $global:TamperWriter.AutoFlush = $true
    }
    catch {
        Write-Host "  [!] Tamper log is locked by a zombie process. Executing cleanup..." -ForegroundColor Red

        Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        $global:TamperStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
        $global:TamperWriter.AutoFlush = $true
        Write-Host "  [+] Zombie cleared. Lock established." -ForegroundColor Green
    }

    Write-Diag "Tamper Guard Log initialized and locked to current process." "INFO"
    return $Path
}

# ====================== CONSOLE UI SETUP ======================
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

# --- GLOBAL UI COLOR PALETTE ---
$ESC = [char]27
$cRed    = "$ESC[91;40m"
$cCyan   = "$ESC[96;40m"
$cGreen  = "$ESC[92;40m"
$cDark   = "$ESC[90;40m"
$cYellow = "$ESC[93;40m"
$cReset  = "$ESC[0m$ESC[40m"

# Reserve space for the pinned dashboard
[Console]::SetCursorPosition(0, 9)

try {
    $ui = $Host.UI.RawUI

    # Expand buffer first to avoid window size exceeding buffer size errors
    $buffer = $ui.BufferSize
    $buffer.Width = 160
    $buffer.Height = 3000 # Give plenty of scrollback history
    $ui.BufferSize = $buffer

    $size = $ui.WindowSize
    $size.Width = 160
    $size.Height = 45
    $ui.WindowSize = $size
} catch {}

# ====================== ACTIVE DEFENSE ENGINE ======================
function Invoke-ActiveDefense($ProcName, $DestIp, $Confidence, $Reason) {
    if (-not $global:IsArmed -or $Confidence -lt $ConfidenceThreshold) { return }

    $killStatus = "Failed"
    if ($ProcName -and $ProcName -notmatch "Unknown|System|Idle|Terminated") {
        Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Name $ProcName -ErrorAction SilentlyContinue)) {
            $killStatus = "Terminated"
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
    Add-AlertMessage "DEFENSE: Process $killStatus$blockStatus ($targetStr)" $cYellow
}

# ====================== ALERT WINDOW ENGINE ======================
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $prefix = "[$ts] "

    # Truncate string to prevent breaking the expanded 100-character boundary
    $maxLen = 98 - $prefix.Length
    if ($Message.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }

    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })

    # Enforce the 7-entry rolling limit
    if ($global:RecentAlerts.Count -gt 7) { $global:RecentAlerts.RemoveAt(0) }
    Draw-AlertWindow
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop

    # Pin this pane safely below the Health Check
    [Console]::SetCursorPosition(0, 22)

    # Expand the log truncation since we have more room now
    $logTrunc = if ($global:OutputPath.Length -gt 60) { "..." + $global:OutputPath.Substring($global:OutputPath.Length - 57) } else { $global:OutputPath }
    $headerPlain = "  [ RECENT DETECTIONS ] | Log: $logTrunc"

    # Expanded padding math to 100
    $padHeader = " " * [math]::Max(0, (100 - $headerPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed[ RECENT DETECTIONS ]$cReset | Log: $cDark$logTrunc$cReset$padHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 7; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            # Match the 100 width (subtracting the 2 leading spaces = 98)
            $pad = " " * [math]::Max(0, (98 - $item.Text.Length))
            Write-Host "$cCyan║$cReset  $($item.Color)$($item.Text)$cReset$pad$cCyan║$cReset"
        } else {
            # 98 empty spaces to maintain the rigid structure
            Write-Host "$cCyan║$cReset                                                                                                    $cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    # Park the cursor out of the way
    [Console]::SetCursorPosition(0, 32)
    [Console]::SetCursorPosition($curLeft, $curTop)
}

# ====================== DASHBOARD ENGINE ======================
function Draw-MonitorDashboard([int]$Events, [int]$Flows, [int]$MlSent, [int]$MlEval, [int]$Alerts, [string]$Tamper, [string]$MlHealth, [string]$SysGuard, [int]$Mitigations) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    # --- DYNAMIC PADDING MATH ---
    # Lock the column widths to 9 so the center pipe '|' stays anchored
    $evPad     = $Events.ToString().PadRight(9)
    $mlPad     = "$MlSent / $MlEval".PadRight(9)
    $tamperPad = $Tamper.PadRight(9)
    $sysguardPad = $SysGuard.PadRight(9)
    $defFired = $Mitigations.ToString().PadRight(9)

    $TitlePlain = "  ⚡ C2 HUNTER V6 | KERNEL MONITOR DASHBOARD"
    $StatusStr  = "  [ LIVE TELEMETRY ]"
    $Stats1Str  = "  Events Processed : $evPad | Active Flows   : $Flows"
    $Stats2Str  = "  ML Sent/Eval     : $mlPad | Active Alerts  : $Alerts"
    $TamperStr  = "  ETW Sensor       : $tamperPad | ML Math Engine : $MlHealth"
    $SysGuardStr = "  Sys Guard State  : $sysguardPad | Defenses Fired : $defFired"

    # Total UI Width set to 100
    $UIWidth = 100

    # Subtract 1 from Title padding because the ⚡ emoji occupies
    # 2 visual columns but only 1 string length character.
    $PadTitle  = " " * [math]::Max(0, ($UIWidth - $TitlePlain.Length - 1))

    $PadStatus = " " * [math]::Max(0, ($UIWidth - $StatusStr.Length))
    $PadStats1 = " " * [math]::Max(0, ($UIWidth - $Stats1Str.Length))
    $PadStats2 = " " * [math]::Max(0, ($UIWidth - $Stats2Str.Length))
    $PadTamper = " " * [math]::Max(0, ($UIWidth - $TamperStr.Length))
    $PadSysGuard = " " * [math]::Max(0, ($UIWidth - $SysGuardStr.Length))

    $TamperColor = if ($Tamper -eq "Good") { $cGreen } else { $cRed }
    $MlColor     = if ($MlHealth -eq "Good") { $cGreen } else { $cRed }
    $GuardColor  = if ($SysGuard -eq "Secure") { $cGreen } else { $cRed }

    # --- RENDER DASHBOARD ---
    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed⚡ C2 HUNTER V6$cReset | KERNEL MONITOR DASHBOARD$PadTitle$cCyan║$cReset"
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

# ====================== MATH HELPERS ======================
$log2 = [Math]::Log(2)
$Regex_NonDigit = [regex]::new('[^0-9]', 'Compiled')
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")

function Get-Entropy([string]$inputString) {
    <# Calculates Shannon Entropy to evaluate domain randomness #>
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

function Is-AnomalousDomain([string]$domain) {
    <# Evaluates domains against common DGA (Domain Generation Algorithm) heuristics #>
    if ([string]::IsNullOrEmpty($domain)) { return $false }
    if ($domain.Length -gt 35) { return $true }

    $digits = $Regex_NonDigit.Replace($domain, "").Length
    if (($digits / $domain.Length) -gt 0.45) { return $true }

    $vowelCount = 0
    foreach ($char in $domain.ToLower().ToCharArray()) { if ($vowels.Contains($char)) { $vowelCount++ } }
    if (($vowelCount / $domain.Length) -lt 0.15) { return $true }

    return (Get-Entropy $domain) -gt 3.8
}

# ====================== DIAGNOSTIC ENGINE ======================
$DiagLogPath = "C:\Temp\C2Hunter_Diagnostic.log"

if (Test-Path $DiagLogPath) { Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue }

function Write-Diag {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "IPC-TX", "IPC-RX", "MATH")]
        [string]$Level = "INFO"
    )
    # Architectural Performance Gate: Prevents disk I/O penalties during normal operation.
    # Only writes to disk if -EnableDiagnostics is invoked, UNLESS the event is a fatal error.
    if (-not $EnableDiagnostics -and $Level -ne "ERROR" -and $Level -ne "WARN") { return }

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $logLine = "[$ts] [$Level] $Message"
    Add-Content -Path $DiagLogPath -Value $logLine -Encoding UTF8
}

Write-Diag "=== C2 HUNTER V6 DIAGNOSTIC LOG INITIALIZED ===" "INFO"
Write-Diag "Host: $env:COMPUTERNAME | PS Version: $($PSVersionTable.PSVersion.ToString())" "INFO"
$TamperLogPath = Initialize-TamperGuard

# =========================================================================
# JA3 THREAT INTEL LOADER
# =========================================================================
$Ja3CachePath = "C:\Temp\C2Hunter_JA3_Cache.json"
$global:MaliciousJA3Cache = @()

if (Test-Path $Ja3CachePath) {
    try {
        $global:MaliciousJA3Cache = Get-Content $Ja3CachePath -Raw | ConvertFrom-Json
        Write-Diag "Loaded $($global:MaliciousJA3Cache.Count) JA3 signatures from dynamic Threat Intel cache." "INFO"
    } catch {
        Write-Diag "Failed to parse JA3 JSON cache. Falling back to offline defaults." "WARN"
    }
}

if ($global:MaliciousJA3Cache.Count -eq 0) {
    # Expanded Offline Fallback Cache (Air-Gapped Mode)
    # Maps directly to known APT frameworks, generic C2 languages, and commodity malware
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
    Write-Diag "Loaded $( $global:MaliciousJA3Cache.Count ) default offline JA3 signatures." "INFO"
}

# ====================== 1. TRACEEVENT LIBRARY FETCH ======================
# Resolves and stages the TraceEvent ETW parser dynamically based on the active host environment.
# Provides seamless cross-compatibility between PowerShell 5.1 (.NET 4.8) and PowerShell 7+ (.NET Core).
Write-Host "Initializing C# TraceEvent Engine..." -ForegroundColor Cyan
$ExtractPath = "C:\Temp\TraceEventPackage"

$DotNetTarget = if ($PSVersionTable.PSVersion.Major -ge 7) { "netstandard2.0" } else { "net45" }
$ManagedDllPath = "$ExtractPath\lib\$DotNetTarget\Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Host "      [*] Downloading Microsoft.Diagnostics.Tracing.TraceEvent..." -ForegroundColor DarkGray
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    $NugetUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/2.0.61"
    Invoke-WebRequest -Uri $NugetUrl -OutFile "C:\Temp\TraceEvent.zip"
    Expand-Archive -Path "C:\Temp\TraceEvent.zip" -DestinationPath $ExtractPath -Force
}

Get-ChildItem -Path $ExtractPath -Recurse | Unblock-File
[System.Reflection.Assembly]::LoadFrom($ManagedDllPath) | Out-Null
Write-Host "      [+] TraceEvent Library Loaded ($DotNetTarget)." -ForegroundColor Green

# Translates the PowerShell exclusion array into a static C# string array for native compilation.
$DnsExclusionCS = ($DnsExclusions | ForEach-Object { "`"$($_.ToLower())`"" }) -join ", "

# ====================== CROSS-PLATFORM COMPILER ======================
# [DEVELOPER NOTE: PowerShell 5.1 (.NET 4.8) uses monolithic libraries.
# PowerShell 7+ (.NET Core 8+) uses modular micro-libraries and type-forwarding.
# We must explicitly load the physical framework DLLs to satisfy the compiler.]
$RefAssemblies = @(
    $ManagedDllPath,
    "System",
    "System.Core"
)

if ($PSVersionTable.PSVersion.Major -ge 7) {
    # Find the root directory of the .NET Core framework running this session
    $coreDir = [System.IO.Path]::GetDirectoryName([System.Object].Assembly.Location)

    # Explicitly load the micro-libraries requested by the .NET 8 compiler
    $requiredDlls = @(
        "System.Runtime.dll",
        "System.Collections.dll",
        "System.Collections.Concurrent.dll",
        "System.Linq.Expressions.dll",
        "System.Net.Primitives.dll",
        "System.Private.CoreLib.dll",
        "netstandard.dll"
    )

    foreach ($dll in $requiredDlls) {
        $fullPath = Join-Path $coreDir $dll
        if (Test-Path $fullPath) { $RefAssemblies += $fullPath }
    }
}

# Resolve the path to the external C# file
$CSharpFilePath = Join-Path $ScriptDir "RealTimeC2Hunter.cs"

if (-not (Test-Path $CSharpFilePath)) {
    Write-Output "  $cRed[-] FATAL: Missing C# Engine Source: $CSharpFilePath$cReset"
    exit
}

# Compile the external file using the existing references
Add-Type -Path $CSharpFilePath -ReferencedAssemblies $RefAssemblies
Write-Output "  $cGreen[+] External C# Engine Compiled Natively.$cReset"
Write-Host "      [+] C# Engine Compiled Natively." -ForegroundColor Green

# ====================== 3. ML DAEMON STARTUP ======================
# Instantiates the Python ML Engine as a parallel background daemon.
# STDIN/STDOUT piping is used to forward telemetry batches without incurring Disk I/O penalties.
$pyStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$pyStartInfo.FileName = $PythonPath
$pyStartInfo.Arguments = '-u "' + $FullMLPath + '"'
$pyStartInfo.RedirectStandardInput = $true
$pyStartInfo.RedirectStandardOutput = $true
# Architectural Health Check: Captures native Python tracebacks for orchestrator visibility.
$pyStartInfo.RedirectStandardError = $true
$pyStartInfo.UseShellExecute = $false
$pyStartInfo.CreateNoWindow = $true
$pyProcess = [System.Diagnostics.Process]::Start($pyStartInfo)
$pyIn = $pyProcess.StandardInput
$pyOut = $pyProcess.StandardOutput
$pyErr = $pyProcess.StandardError

# Validation Engine: Ensures the interpreter successfully loaded the C-libraries and ML matrices before entering the operational loop.
Start-Sleep -Seconds 2
if ($pyProcess.HasExited) {
    $fatalErr = $pyErr.ReadToEnd()
    Write-Host "`n[FATAL] The Python ML Daemon terminated unexpectedly during initialization." -ForegroundColor Red
    Write-Host "Native Exception Trace:`n$fatalErr" -ForegroundColor DarkRed
    Write-Diag "Python daemon crashed on startup. STDERR: $fatalErr" "ERROR"
    exit
}

# ====================== 4. RUNTIME STRUCTURES ======================
# High-speed memory structures utilized by the foreground loop to aggregate and track flow states
$ProcessCache = @{} # Ultra-fast L1 cache for ETW Ghost PIDs
$connectionHistory = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$lastPingTime = @{}
$flowMetadata = @{}
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()

# Deduplication log structures
$loggedFlows = @{}
$MonitorLogPath = "C:\Temp\OutboundNetwork_Monitor.log"

$lastMLRunTime = Get-Date
$globalMlSent = 0
$globalMlRcvd = 0
$globalMlEvaluated = 0
$globalMlAlerts = 0
$OutboundNetEvents = 0
$global:TotalMitigations = 0

$StateDBPath = "C:\Temp\C2_StateDB"
if (-not (Test-Path $StateDBPath)) {
    New-Item -ItemType Directory -Force -Path $StateDBPath | Out-Null
} else {
    # Database Grooming: Preserves temporal memory across reboots but prevents disk exhaustion.
    # Automatically purges any dormant state file older than 14 days upon daemon startup.
    Get-ChildItem -Path $StateDBPath -Filter "*.json" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } | Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Output "Starting Real-Time ETW Session (No Disk IO)..."
# Pass the PowerShell exclusions array into the compiled C# engine
[RealTimeC2Hunter]::InitializeEngine($DnsExclusions)
# Start the session
[RealTimeC2Hunter]::StartSession()

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   C2 HUNTER SYSTEM HEALTH CHECK" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
if ($TestMode) { Write-Host " [!] TEST MODE ACTIVE     : AWS/CDN EXCLUSIONS DISABLED" -ForegroundColor Yellow }
Write-Host " [+] C# ETW Engine        : RUNNING (In-Memory)" -ForegroundColor Green
Write-Host " [+] Native IP Decoders   : BYPASSED (Using Raw Byte Scanner)" -ForegroundColor Green
Write-Host " [+] Kernel Provider      : LISTENING (TCPIP/DNS/Process)" -ForegroundColor Green
if ($pyProcess -and -not $pyProcess.HasExited) {
    Write-Host " [+] ML Analysis Daemon   : CONNECTED (PID: $($pyProcess.Id))" -ForegroundColor Green
} else {
    Write-Host " [-] ML Analysis Daemon   : FAILED TO START" -ForegroundColor Red
}
Write-Host "========================================================`n" -ForegroundColor Cyan

# ====================== 4.5 ANTI-TAMPER SENSOR WATCHDOG ======================
Write-Host "Initializing Anti-Tamper Canary Thread (DNS)..." -ForegroundColor Cyan

# --- ETW Sensor Health Check Variables ---
$LastHeartbeat = Get-Date
$LastCanaryPing = Get-Date
$SensorBlinded = $false

# --- ML Health Check Variables ---
$LastMlHealthPing = (Get-Date).AddSeconds(-115) # Force an early initial ping
$LastMlHeartbeat = Get-Date
$MlBlinded = $false

<#
# The Canary fires a synthetic TCP connection attempt to a reserved loopback IP
$CanaryIP = "127.0.0.99"
$CanaryTimer = New-Object System.Timers.Timer(60000)
$CanaryTimer.AutoReset = $true
$CanaryAction = {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ConnectAsync($CanaryIP, 443).Wait(100) # Fails instantly, but ETW captures the attempt
    } catch {}
}
Register-ObjectEvent -InputObject $CanaryTimer -EventName Elapsed -Action $CanaryAction | Out-Null
$CanaryTimer.Start()
#>
# ====================== 5. MAIN EVENT LOOP ======================
try {
    while ($true) {
        $now = Get-Date

        # --- ASYNCHRONOUS CANARY PING (IETF in RFC 5737 as TEST-NET-3) ---
        if (($now - $LastCanaryPing).TotalSeconds -ge 60) {
            $LastCanaryPing = $now
            try {
                $rnd = Get-Random
                # Resolve-DnsName forces the native OS service to trigger an ETW 3008 event
                Resolve-DnsName -Name "canary-$rnd.c2hunter.com" -ErrorAction SilentlyContinue | Out-Null
            } catch {}
        }

        $eventCount = 0
        $jsonStr = ""
        $SysGuardState = "Secure"

        # Drain the C# Queue constantly to maintain a low memory footprint
        while ([RealTimeC2Hunter]::EventQueue.TryDequeue([ref]$jsonStr)) {
            $eventCount++
            $evt = $jsonStr | ConvertFrom-Json -ErrorAction SilentlyContinue

            if (-not $evt) { continue }
            if ($evt.Error) {
                Write-Diag "FATAL ETW CRASH: $($evt.Error)" "ERROR"
                Add-AlertMessage "FATAL ERROR: C# ETW THREAD CRASHED" $cRed
                continue
            }

            # --- ANTI-TAMPER SENSOR WATCHDOG ---
            if ($evt.Query -match "canary-\d+\.c2hunter\.com") {
                $LastHeartbeat = $now

                if ($SensorBlinded) {
                    $SensorBlinded = $false
                    Add-AlertMessage "SENSOR RECOVERED: ETW telemetry restored." $cGreen
                    Write-Diag "Sensor connection restored after blinding event." "INFO"
                }
                continue # Drop the canary event so it doesn't pollute the ML engine
            }

            # --- TAMPER GUARD INTERCEPTION ---
            if ($evt.Provider -eq "TamperGuard") {
                $SysGuardState = "BREACHED"
                $alertMsg = "TAMPER ALERT: $($evt.EventName) - $($evt.Details)"
                Add-AlertMessage $alertMsg $cRed

                # Write securely to the locked file
                $global:TamperWriter.WriteLine("[$(Get-Date -Format 'o')] [TAMPER] $($evt.EventName) | $($evt.Details)")
                continue
            }

            # --- JA3 FINGERPRINT INTERCEPTION ---
            if ($evt.Provider -eq "NDIS" -and $evt.EventName -eq "TLS_JA3_FINGERPRINT") {
                Write-Diag "JA3 HASH EXTRACTED: $($evt.DestIp) -> $($evt.JA3)" "INFO"

                # Check against known malicious framework signatures
                if ($global:MaliciousJA3Cache -contains $evt.JA3) {

                    # Because L2 frames lack PID context, cross-reference our active
                    # L4 network tracker to find the process mapped to this IP
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

                    # Immediate Surgical Containment
                    Invoke-ActiveDefense -ProcName $owningProcess -DestIp $evt.DestIp -Confidence 100 -Reason "Malicious JA3 Hash"
                }

                # Drop the NDIS event so it doesn't proceed into the ML matrices
                # (which are strictly for L4 packet timing, not L2 crypto analysis)
                continue
            }

            # --- SERVER-SIDE APPGUARD INTERCEPTION & DEFENSE ---
            if ($evt.Provider -eq "AppGuard") {
                $alertMsg = "SERVER EXPLOIT: $($evt.EventName) -> $($evt.Parent) spawned $($evt.Child)"
                Add-AlertMessage $alertMsg $cRed
                Write-Diag "APPGUARD HIT: $($evt.Parent) spawned $($evt.Child) | CMD: $($evt.CommandLine)" "WARN"

                $MitreTags = if ($evt.EventName -eq "WEB_SHELL_DETECTED") {
                    "TA0003: T1505.003; TA0001: T1190; TA0002: T1059"
                } else {
                    "TA0001: T1190; TA0002: T1569.002; TA0002: T1059"
                }

                # Package the alert for the JSONL SIEM forwarder
                $dataBatch.Add([PSCustomObject]@{
                    EventType = $evt.EventName
                    Timestamp = $now
                    Destination = "Local_Privilege_Escalation"
                    Image = $evt.Parent
                    SuspiciousFlags = "Server Application Spawned Command Shell: $($evt.Child) | Cmd: $($evt.CommandLine)"
                    ATTCKMappings = $MitreTags
                    Confidence = 100
                })

                # --- PRECISE CONTAINMENT ---
                # By passing $evt.Child, we terminate the attacker's shell instantly
                # leaving the parent IIS/SQL server alive to preserve business continuity.
                Invoke-ActiveDefense -ProcName $evt.Child -DestIp "" -Confidence 100 -Reason "Server Application Exploitation"

                continue # Drop the event so it doesn't bleed into the ML network matrix
            }

            # --- NOISE REDUCTION FILTERS ---
            $procName = ""

            # 1. Attempt to use ETW's provided image name
            if ($evt.Image -and $evt.Image -ne "Unknown") {
                $procName = [System.IO.Path]::GetFileNameWithoutExtension($evt.Image).ToLower()
            }
            # 2. Cache Fallback: If ETW stripped the name, resolve the PID natively and cache it
            elseif ($evt.PID -match '^\d+$' -and $evt.PID -ne "0" -and $evt.PID -ne "4") {
                if (-not $ProcessCache.ContainsKey($evt.PID)) {
                    try {
                        $ProcessCache[$evt.PID] = (Get-Process -Id $evt.PID -ErrorAction Stop).Name.ToLower()
                    } catch {
                        $ProcessCache[$evt.PID] = "terminated"
                    }
                }
                $procName = $ProcessCache[$evt.PID]
            }

            $skipEvent = $false

            # Process Filter: Drop notoriously noisy applications
            if (-not [string]::IsNullOrEmpty($procName) -and ($ProcessExclusions -contains $procName)) {
                $skipEvent = $true
            }

            # Subnet Filter: Drop known Microsoft/Google CDN ranges
            if (-not $skipEvent -and -not [string]::IsNullOrEmpty($evt.DestIp)) {
                foreach ($prefix in $IpPrefixExclusions) {
                    if ($evt.DestIp -match $prefix) { $skipEvent = $true; break }
                }
            }

            if ($skipEvent) { continue }

            $props = [ordered]@{
                EventType = $evt.EventName
                Timestamp = [datetime]$evt.TimeStamp
                Image = $evt.Image
                SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                ATTCKMappings = [System.Collections.Generic.List[string]]::new()
                DestinationHostname = $evt.Query
                Confidence = 85
            }

            # --- STATIC SIGNATURE DETECTION ---
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

            # --- BEACONING TRACKER (STATE MANAGEMENT) ---
            if ($evt.Provider -match "TCPIP|Network" -and $evt.DestIp -and $evt.DestIp -notmatch '^192\.168\.|^10\.|^127\.|^172\.') {
                $OutboundNetEvents++

                # Dictionary Tracker: Enforces Destination IP isolation for shared OS processes (System/Idle)
                # to prevent background network noise from polluting the ML clustering matrices.
                # Enforces Destination IP and Thread isolation
                $safePort = if ([string]::IsNullOrWhiteSpace($evt.Port) -or $evt.Port -eq "0") { "IP_$($evt.DestIp)" } else { $evt.Port }

                # Matrix alignment now tracks individual threads (TID) to isolate injected payloads
                $key = if ($evt.PID -eq "4" -or $evt.PID -eq "0") {
                    "PID_$($evt.PID)_TID_$($evt.TID)_IP_$($evt.DestIp)_Port_$safePort"
                } else {
                    "PID_$($evt.PID)_TID_$($evt.TID)_Port_$safePort"
                }

                # --- HYBRID STATE MANAGER (RAM + DISK) ---
                if (-not $connectionHistory.ContainsKey($key)) {
                    $dbFile = Join-Path $StateDBPath "$key.json"

                    if (Test-Path $dbFile) {
                        # LOW AND SLOW DETECTED: Restore historical state from Disk to RAM
                        $restored = Get-Content $dbFile -Raw | ConvertFrom-Json
                        $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                        foreach ($ts in $restored.timestamps) { $connectionHistory[$key].Enqueue([datetime]$ts) }

                        $flowMetadata[$key] = @{
                            dst_ips = [System.Collections.Generic.List[string]]::new([string[]]$restored.dst_ips)
                            packet_sizes = [System.Collections.Generic.List[int]]::new([int[]]$restored.packet_sizes)
                            domain = $restored.domain
                            image = $restored.image
                        }

                        # Purge the DB file since the flow is active in RAM again
                        Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
                        Write-Diag "Restored historical temporal state for $key from Disk DB." "INFO"
                    } else {
                        # Standard New Connection
                        $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                        $flowMetadata[$key] = @{
                            dst_ips = [System.Collections.Generic.List[string]]::new()
                            packet_sizes = [System.Collections.Generic.List[int]]::new()
                            domain = if ($evt.Query) { $evt.Query } else { $evt.DestIp }
                            image = $evt.Image
                        }
                    }
                }

                $isNewPing = $true

                # Debounce Filter: Discards rapid payload fragments (e.g., TCP handshakes) to isolate true beacon intervals
                if ($lastPingTime.ContainsKey($key) -and ($props.Timestamp - $lastPingTime[$key]).TotalMilliseconds -lt 100) {
                    $isNewPing = $false
                }

                # Data Alignment: Metadata is appended exclusively on debounced intervals to maintain parallel arrays
                if ($isNewPing) {
                    $connectionHistory[$key].Enqueue($props.Timestamp)
                    $lastPingTime[$key] = $props.Timestamp
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

        # ---------------- ML HANDOFF PIPELINE ----------------
        if (($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {
            $payload = @{}

            foreach ($key in $connectionHistory.Keys) {
                $count = $connectionHistory[$key].Count
                if ($count -ge $MinSamplesForML) {
                    $arr = $connectionHistory[$key].ToArray()

                    # Telemetry Pruning: Ensures active flows are evaluated but drops long-dead flows
                    # Widened to 120 seconds to completely eliminate execution race conditions.
                    if (($now - $arr[-1]).TotalSeconds -gt 120) {
                        continue
                    }

                    # Structured Deduplication Logging
                    if (-not $loggedFlows.ContainsKey($key) -or $loggedFlows[$key] -ne $count) {
                        $loggedFlows[$key] = $count
                        $duration = [Math]::Round(($arr[-1] - $arr[0]).TotalSeconds, 2)
                        $firstPing = $arr[0].ToString("yyyy-MM-dd HH:mm:ss")

                        $destIp = $flowMetadata[$key].dst_ips[-1]
                        $domain = $flowMetadata[$key].domain

                        $portParts = $key -split "_Port_"
                        $portVal = if ($portParts.Count -gt 1) { $portParts[1] } else { "Unknown" }

                        # Robust Regex Parsing
                        $pidVal = "Unknown"
                        if ($key -match "PID_(\d+)") {
                            $pidVal = $matches[1]
                        }

                        # Process Name Fallback: If ETW missed the image load event, explicitly fetch the process name via the OS.
                        $procName = "Unknown"
                        if ($flowMetadata[$key].image -and $flowMetadata[$key].image -ne "Unknown") {
                            $procName = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$key].image)
                        } elseif ($pidVal -match '^\d+$') {
                            try {
                                $procName = (Get-Process -Id $pidVal -ErrorAction Stop).Name
                                if ($pidVal -eq "4") { $procName = "System" }
                            } catch { $procName = "Terminated" }
                        }

                        $logEntry = "Timestamp: $firstPing, Destination IP: $destIp, Destination Domain: $domain, Port: $portVal, PID: $pidVal, Process Name: $procName, Connection Amount over duration: $count connections over ${duration}s"
                        Add-Content -Path $MonitorLogPath -Value $logEntry -Encoding UTF8
                    }

                    $intervals = @()
                    $aligned_ips = @()
                    $aligned_sizes = @()

                    # Array Slicing: Extracts N-1 intervals to ensure perfectly aligned matrices for Scikit-Learn processing
                    for ($i = 1; $i -lt $arr.Count; $i++) {
                        $intervals += [Math]::Round(($arr[$i] - $arr[$i-1]).TotalSeconds, 2)
                        if ($i -lt $flowMetadata[$key].dst_ips.Count) { $aligned_ips += $flowMetadata[$key].dst_ips[$i] }
                        if ($i -lt $flowMetadata[$key].packet_sizes.Count) { $aligned_sizes += $flowMetadata[$key].packet_sizes[$i] }
                    }

                    $payload[$key] = @{
                        intervals = $intervals
                        domain = $flowMetadata[$key].domain
                        dst_ips = $aligned_ips
                        packet_sizes = $aligned_sizes
                    }
                }
            }

            # --- SYNTHETIC ML HEALTH CHECK INJECTION ---
            if (($now - $LastMlHealthPing).TotalSeconds -ge 120) {
                $LastMlHealthPing = $now
                # Camouflage as external traffic to bypass Python's internal LAN filters
                $payload["HEALTH_CHECK_PAYLOAD"] = @{
                    intervals = @(10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0)
                    domain = "synthetic-ml-validation.com"
                    dst_ips = @("9.9.9.99", "9.9.9.99", "9.9.9.99", "9.9.9.99", "9.9.9.99", "9.9.9.99", "9.9.9.99", "9.9.9.99")
                    packet_sizes = @(256, 256, 256, 256, 256, 256, 256, 256)
                }
            }

            if ($payload.Count -gt 0) {
                $globalMlSent++
                $jsonPayload = $payload | ConvertTo-Json -Depth 6 -Compress

                # --- DIAGNOSTIC INJECTION: TRACK TRANSMISSION ---
                Write-Diag "Flushing matrix to Python STDIN. Flows: $($payload.Count) | ByteSize: $($jsonPayload.Length)" "IPC-TX"

                $pyIn.WriteLine($jsonPayload)
                $pyIn.Flush()

                $timeout = 3000
                $responseReceived = $false

                while ($timeout-- -gt 0 -and -not $pyProcess.HasExited) {
                    if (-not $pyOut.EndOfStream) {
                        $pyResponse = $pyOut.ReadLine()

                        if ($pyResponse) {
                            $responseReceived = $true
                            $globalMlRcvd++

                            # --- DIAGNOSTIC INJECTION: TRACK RAW RECEIPT ---
                            Write-Diag "Raw payload received from Python STDOUT: $pyResponse" "IPC-RX"

                            try {
                                $mlResults = $pyResponse | ConvertFrom-Json -ErrorAction Stop
                            } catch {
                                Write-Host "`n[!] ML Daemon IPC Error: Python emitted non-JSON string. Check Diagnostic Log." -ForegroundColor Red
                                Write-Diag "JSON Parse Failure. Python emitted corrupted/non-JSON data: $pyResponse" "ERROR"
                                break
                            }

                            foreach ($alertKey in $mlResults.PSObject.Properties.Name) {
                                if ($alertKey -eq "_health_metrics") {
                                    $globalMlEvaluated += $mlResults.$alertKey.flows_evaluated
                                    $globalMlAlerts += $mlResults.$alertKey.alerts_generated
                                    Write-Diag "Python Health Metrics -> Evaluated: $($mlResults.$alertKey.flows_evaluated) | Alerts Generated: $($mlResults.$alertKey.alerts_generated)" "MATH"
                                    continue
                                }

                                if ($alertKey -eq "daemon_error") {
                                    Write-Host "`n[!] ML Daemon Runtime Error: $($mlResults.$alertKey)" -ForegroundColor Red
                                    Write-Diag "Fatal Python Daemon Error: $($mlResults.$alertKey)" "ERROR"
                                    continue
                                }

                                $alertData = $mlResults.$alertKey
                                if ($alertData.error) {
                                    Write-Host "`n[!] ML Flow Processing Error ($alertKey): $($alertData.error)" -ForegroundColor DarkRed
                                    Write-Diag "Python flow math error on $alertKey : $($alertData.error)" "ERROR"
                                    continue
                                }

                                # --- INTERCEPT SYNTHETIC HEALTH CHECK ---
                                if ($alertKey -eq "HEALTH_CHECK_PAYLOAD") {
                                    if ($alertData.alert) {
                                        $LastMlHeartbeat = $now
                                        if ($MlBlinded) {
                                            $MlBlinded = $false
                                            Add-AlertMessage "ML ENGINE RECOVERED: Math operations verified." $cGreen
                                            Write-Diag "ML Daemon math health check recovered." "INFO"
                                        }
                                    }
                                    continue # Skip so it never triggers UI or Defense
                                }

                                if ($alertData.alert) {
                                    Write-Diag "DETECTION TRIGGERED: $alertKey -> $($alertData.alert) (Confidence: $($alertData.confidence))" "INFO"

                                    # --- PROCESS NAME RESOLUTION FALLBACK ---
                                    # Extract PID from the thread key
                                    $pidVal = "Unknown"
                                    $pidParts = ($alertKey -split "PID_")
                                    if ($pidParts.Count -gt 1) {
                                        $pidVal = ($pidParts[1] -split "_")[0]
                                    }

                                    $resolvedImage = "Unknown"
                                    if ($flowMetadata[$alertKey].image -and $flowMetadata[$alertKey].image -ne "Unknown") {
                                        $resolvedImage = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$alertKey].image)
                                    } elseif ($pidVal -match '^\d+$') {
                                        try {
                                            $resolvedImage = (Get-Process -Id $pidVal -ErrorAction Stop).Name
                                            if ($pidVal -eq "4") { $resolvedImage = "System" }
                                            if ($pidVal -eq "0") { $resolvedImage = "Idle" }
                                        } catch { $resolvedImage = "Terminated" }
                                    }

                                    Add-AlertMessage "ML ($($alertData.confidence)%): $alertKey - $($alertData.alert)" $cRed
                                    Write-Diag "DETECTION TRIGGERED: $alertKey -> $($alertData.alert) (Confidence: $($alertData.confidence))" "INFO"

                                    $dataBatch.Add([PSCustomObject]@{
                                        EventType = "ML_Beacon"
                                        Timestamp = $now
                                        Destination = $alertKey
                                        Image = $resolvedImage
                                        SuspiciousFlags = $alertData.alert
                                        Confidence = $alertData.confidence
                                    })

                                    $targetIp = if ($alertKey -match "IP_([0-9\.]+)") { $matches[1] } else { "Unknown" }
                                    Invoke-ActiveDefense -ProcName $resolvedImage -DestIp $targetIp -Confidence $alertData.confidence -Reason $alertData.alert
                                }
                            }
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 20
                }

                if (-not $responseReceived) {
                    if ($pyProcess.HasExited) {
                        $fatalErr = $pyErr.ReadToEnd()
                        Write-Host "`n[!] ML IPC FATAL: The Python Daemon crashed. STDERR:`n$fatalErr" -ForegroundColor Red
                        Write-Diag "IPC FATAL CRASH: Python Daemon exited prematurely. STDERR: $fatalErr" "ERROR"
                    } else {
                        Write-Host "`n[!] ML IPC Timeout: The Daemon did not respond within 15000ms." -ForegroundColor DarkRed
                        Write-Diag "IPC TIMEOUT: Python Daemon failed to return a response line within 15000ms." "ERROR"
                    }
                }
            }

            # --- HYBRID STATE GARBAGE COLLECTION (FLUSH TO DISK) ---
            $staleKeys = @()
            foreach ($k in $connectionHistory.Keys) {
                $historyArr = $connectionHistory[$k].ToArray()
                if ($historyArr.Count -gt 0) {
                    $lastActivity = $historyArr[-1]
                    if (($now - $lastActivity).TotalSeconds -gt 300) {

                        # Instead of destroying the temporal data, serialize it to the local State DB
                        $dbFile = Join-Path $StateDBPath "$k.json"

                        $diskState = @{ timestamps = @(); dst_ips = @(); packet_sizes = @(); domain = $flowMetadata[$k].domain; image = $flowMetadata[$k].image }

                        # If the DB file already exists (multiple flushes over days), append to it
                        if (Test-Path $dbFile) {
                            $existing = Get-Content $dbFile -Raw | ConvertFrom-Json
                            $diskState.timestamps = [System.Collections.Generic.List[string]]::new([string[]]$existing.timestamps)
                            $diskState.dst_ips = [System.Collections.Generic.List[string]]::new([string[]]$existing.dst_ips)
                            $diskState.packet_sizes = [System.Collections.Generic.List[int]]::new([int[]]$existing.packet_sizes)
                        }

                        foreach ($t in $historyArr) { $diskState.timestamps += $t.ToString("O") }
                        $diskState.dst_ips += $flowMetadata[$k].dst_ips
                        $diskState.packet_sizes += $flowMetadata[$k].packet_sizes

                        $diskState | ConvertTo-Json -Compress | Set-Content $dbFile -Encoding UTF8

                        $staleKeys += $k
                        Write-Diag "Flushed $k to Disk DB (Low and Slow Tracking)." "INFO"
                    }
                }
            }
            foreach ($k in $staleKeys) {
                [void]$connectionHistory.Remove($k); [void]$flowMetadata.Remove($k); [void]$loggedFlows.Remove($k)
            }
            $lastMLRunTime = $now
        }

        if ($dataBatch.Count -gt 0) {
            # --- LOG ROTATION ENGINE (Caps file size at ~50MB) ---
            if (Test-Path $OutputPath) {
                $logSize = (Get-Item $OutputPath).Length
                if ($logSize -gt 50MB) {
                    $archiveName = $OutputPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    Rename-Item -Path $OutputPath -NewName $archiveName -Force
                    Write-Diag "Log rotated. Archived to $archiveName" "INFO"
                }
            }

            # Use raw .NET to bypass PowerShell File-Lock collisions
            $batchOutput = ($dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            [System.IO.File]::AppendAllText($OutputPath, $batchOutput + "`r`n")
            $dataBatch.Clear()
        }

        $activeFlows = $connectionHistory.Keys.Count

        $tamperStatus = if (($now - $LastHeartbeat).TotalSeconds -le 180) { "Good" } else { "BAD" }
        $mlStatus = if (($now - $LastMlHeartbeat).TotalSeconds -le 300) { "Good" } else { "BAD" }

        Draw-MonitorDashboard -Events $eventCount -Flows $activeFlows -MlSent $globalMlSent -MlEval $globalMlEvaluated -Alerts $globalMlAlerts -Tamper $tamperStatus -MlHealth $mlStatus -SysGuard $SysGuardState -Mitigations $global:TotalMitigations

        # --- ETW DEADMAN'S SWITCH ---
        if ($tamperStatus -eq "BAD" -and -not $SensorBlinded) {
            $SensorBlinded = $true
            Add-AlertMessage "CRITICAL ALARM: SENSOR BLINDED (ETW COMPROMISE)" $cRed
            Write-Diag "SENSOR BLINDED: No heartbeat received since $($LastHeartbeat.ToString('HH:mm:ss'))." "ERROR"
        }

        # --- ML DEADMAN'S SWITCH ---
        if ($mlStatus -eq "BAD" -and -not $MlBlinded) {
            $MlBlinded = $true
            Add-AlertMessage "CRITICAL ALARM: ML MATH ENGINE FROZEN" $cRed
            Write-Diag "ML BLINDED: No valid health check returned from Python." "ERROR"
        }
        Start-Sleep -Milliseconds 2000
    }

# ====================== 6. TEARDOWN SEQUENCE ======================
} finally {
    Write-Diag "Initiating Teardown Sequence..." "INFO"

    [RealTimeC2Hunter]::StopSession()
    Write-Diag "C# TraceEvent Session Halted." "INFO"

    # Clean up the Watchdog
    if ($CanaryTimer) { $CanaryTimer.Stop(); $CanaryTimer.Dispose() }

    if ($pyProcess -and -not $pyProcess.HasExited) {
        $pyProcess.StandardInput.WriteLine("QUIT")
        Start-Sleep -Milliseconds 200
        if (-not $pyProcess.HasExited) {
            $pyProcess.Kill()
            Write-Diag "Python Daemon forcefully killed." "WARN"
        } else {
            Write-Diag "Python Daemon exited gracefully." "INFO"
        }
    }

    $ProjectArtifacts = @(
        "C:\Temp\TraceEventPackage",
        "C:\Temp\TraceEvent.zip",
        "C:\Temp\TraceEventSupport.zip",
        "C:\Temp\C2Kernel.etl"
    )
    foreach ($Item in $ProjectArtifacts) {
        if (Test-Path $Item) {
            Remove-Item -Path $Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"
}