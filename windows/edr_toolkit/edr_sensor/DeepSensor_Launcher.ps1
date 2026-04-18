<#
.SYNOPSIS
    Deep Visibility Sensor v2.1 - OS Behavioral Orchestrator & Active Defense HUD

.DESCRIPTION
    The central nervous system of the Deep Visibility EDR toolkit. This script is
    responsible for bootstrapping the environment, bridging the unmanaged C# ETW
    engine natively with the Rust ML DLL, and rendering the mathematically pinned
    diagnostic HUD.

    It operates completely independently of network-based C2 tracking, focusing
    strictly on deep operating system hooks and persistence mechanisms.
    Additionally, it acts as a dynamic Threat Intelligence compiler, natively parsing
    and executing Sigma rules and BYOVD driver lists directly within the kernel event loop.

.ARCHITECTURE_FLOW
    1. Environment Pre-Flight: Validates the presence of the compiled Rust ML DLL.
    2. Threat Intel Compiler: Recursively parses the local 'sigma/' directory, auto-corrects
       YAML syntax, and fetches live BYOVD (LOLDrivers) intelligence to build O(1) arrays.
    3. Dynamic Compilation: Embeds the OsSensor.cs payload directly
       into the PowerShell RAM space, linking the TraceEvent libraries on the fly.
    4. Matrix Initialization: Maps critical PIDs (Sensor) and injects the compiled
       Sigma and Threat Intel arrays directly into the unmanaged C# memory space.
    5. Native FFI Pipeline: C# natively invokes the Rust ML engine (DeepSensor_ML_v2.1.dll)
       directly within its own memory space, bypassing all IPC pipe latency.
    6. Security Lockdown: Utilizes icacls and sdset to restrict file and service access.
    7. Telemetry Triage: Continuously drains the C# ConcurrentQueue. Static, high-
       fidelity alerts and native ML anomalies are actioned instantly.
    8. Active Defense: If ArmedMode is enabled, native SuspendThread / Quarantine (Surgical) and memory
       neutralization (PAGE_NOACCESS) are issued the millisecond an exploit chain is verified.

.PARAMETERS
    ArmedMode           - Enables autonomous surgical thread suspension (Quarantine),
                          memory permission stripping, and forensic payload extraction
                          for critical alerts.
    PolicyUpdateUrl     - URL to fetch centralized Sigma rules during policy sync.
    SiemEndpoint        - REST API endpoint for Splunk HEC or Azure Log Analytics.
    SiemToken           - Authorization token for the SIEM endpoint.
    MlBinaryName        - The filename of the compiled Rust ML engine.
    MlRepoUrl           - URL to fetch the compiled Rust binary if missing.
    LogPath             - Destination for the rolling JSONL SIEM forwarder cache.
    TraceEventDllPath   - Path to the Microsoft.Diagnostics.Tracing.TraceEvent.dll.
#>
#Requires -RunAsAdministrator

# ======================================================================
# 1. PARAMETERS
# ======================================================================

param (
    [switch]$ArmedMode,
    [switch]$EnableDiagnostics,
    [string]$PolicyUpdateUrl = "",
    [string]$SiemEndpoint = "",
    [string]$SiemToken = "",
    [string]$OfflineRepoPath = "",
    [string]$MlBinaryName = "DeepSensor_ML_v2.1.dll",
    [string]$LogPath = "C:\ProgramData\DeepSensor\Data\DeepSensor_Events.jsonl",
    [string]$TraceEventDllPath = "C:\ProgramData\DeepSensor\Dependencies\TE\lib\net45\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
)

# --- Clear Trace ---
logman stop "NT Kernel Logger" -ets >$null 2>&1

# ======================================================================
# 2. GLOBAL CONSTANTS & PATHS
# ======================================================================

$Global:ProgData = if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }
$global:EnrichmentPrefix = "`"ComputerName`":`"$env:COMPUTERNAME`", `"IP`":`"$IpAddress`", `"OS`":`"$OsContext`", `"SensorUser`":`"$userStr`", "
$global:ComputerName = $env:COMPUTERNAME
$global:HostIP = $IpAddress
$global:SensorUser = $userStr
$global:cycleAlerts = [System.Collections.Generic.Dictionary[string, object]]::new()
$global:dataBatch = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:IsArmed = $ArmedMode
if ($ArmedMode) {
    Write-Host "`n[!] SENSOR BOOTING IN ARMED MODE: ACTIVE DEFENSE ENABLED" -ForegroundColor Red
} else {
    Write-Host "`n[*] SENSOR BOOTING IN AUDIT MODE: OBSERVATION ONLY" -ForegroundColor Yellow
}
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:StartupLogs = [System.Collections.Generic.List[string]]::new()
$global:TotalMitigations = 0

$script:logBatch = [System.Collections.Generic.List[string]]::new()
# Dedicated UEBA JSONL pipeline
$script:uebaBatch = [System.Collections.Generic.List[string]]::new()
$UebaLogPath = $LogPath -replace "DeepSensor_Events.jsonl", "DeepSensor_UEBA_Events.jsonl"

$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptDir)) {
    if ($PSCommandPath) { $ScriptDir = Split-Path $PSCommandPath -Parent }
    else { $ScriptDir = $PWD.Path }
}

$LogDir = Join-Path $env:ProgramData "DeepSensor\Logs"
$DiagLogPath = Join-Path $LogDir "DeepSensor_Diagnostic.log"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if (Test-Path $DiagLogPath) {
    Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue
}

# ======================================================================
# 3. HELPER FUNCTIONS
# ======================================================================

function Write-Diag([string]$Message, [string]$Level = "INFO") {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try {
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        Add-Content -Path $DiagLogPath -Value "[$ts] [$Level] $Message" -Encoding UTF8
    } catch {}

    if ($Level -eq "STARTUP") {
        $global:StartupLogs.Add($Message)
        Draw-StartupWindow
    }
}

# ====================== SIEM ENRICHMENT METADATA ======================
$activeRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($activeRoute) {
    $IpAddress = (Get-NetIPAddress -InterfaceIndex $activeRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}
if (-not $IpAddress) { $IpAddress = "Unknown" }
$OsContext = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption -replace 'Microsoft ', ''
$userStr = "$env:USERDOMAIN\$env:USERNAME".Replace("\", "\\")

# ======================================================================
# 4. HUD / UI RENDERING
# ======================================================================

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

# ====================== HUD DASHBOARD RENDERING ======================
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

$ESC      = [char]27
# 24-bit TrueColor Neon Palette (R;G;B)
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
    $buffer = $ui.BufferSize
    $buffer.Width = 160
    $buffer.Height = 3000
    $ui.BufferSize = $buffer
    $size = $ui.WindowSize
    $size.Width = 160

    $size.Height = 55
    $ui.WindowSize = $size
} catch {}

[Console]::SetCursorPosition(0, 9)

function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $ts = (Get-Date).ToString("HH:mm:ss"); $prefix = "[$ts] "
    $maxLen = 98 - $prefix.Length
    if ($Message.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }
    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })

    # Expanded to keep the last 20 events in the queue
    if ($global:RecentAlerts.Count -gt 20) { $global:RecentAlerts.RemoveAt(0) }
    Draw-AlertWindow
}

function Draw-Dashboard([long]$Events, [long]$MlEvals, [int]$Alerts, [string]$EtwHealth, [string]$MlHealth) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $mitreTags = @()
    foreach ($alert in $global:RecentAlerts) {
        if ($alert.Text -match "\[(T\d{4}(?:\.\d{3})?)\]") { $mitreTags += $matches[1] }
    }
    $uniqueMitre = if ($mitreTags.Count -gt 0) { ($mitreTags | Select-Object -Unique) -join ", " } else { "None" }
    if ($uniqueMitre.Length -gt 25) { $uniqueMitre = $uniqueMitre.Substring(0, 22) + "..." }

    $lastAction = "None"
    for ($i = $script:logBatch.Count - 1; $i -ge 0; $i--) {
        if ($script:logBatch[$i] -match "`"Action`":`"(.*?Quarantined.*?)`"") {
            $lastAction = $matches[1]; break
        }
    }
    if ($lastAction.Length -gt 25) { $lastAction = $lastAction.Substring(0, 22) + "..." }

    $evPad       = $Events.ToString().PadRight(15)
    $mlPad       = $MlEvals.ToString().PadRight(15)
    $alertPad    = $Alerts.ToString().PadRight(15)
    $defFiredPad = $global:TotalMitigations.ToString().PadRight(15)

    $EtwState    = if ($EtwHealth -eq "Good") { "ONLINE" } else { "DEGRADED" }
    $tamperPad   = $EtwState.PadRight(15)
    $mlHealthPad = $MlHealth.PadRight(15)

    $lastActionPad = $lastAction.PadRight(25)
    $vectorsPad = $uniqueMitre.PadRight(25)

    $TitlePlain = "  ██ Deep Sensor v2.1 | OS Behavioral Dashboard"
    $StatusStr  = "  [ ENGINE STATUS ]               [ ACTIVE DEFENSE ]"
    $Stats1Str  = "  Sensor Status : $tamperPad | Defenses Engaged : $defFiredPad"
    $Stats2Str  = "  ML/UEBA       : $mlHealthPad | Total Alerts     : $alertPad"
    $Stats3Str  = "  Total Events  : $evPad | Last Action      : $lastActionPad"
    $Stats4Str  = "  ML/UEBA Evals : $mlPad | Vectors          : $vectorsPad"

    $UIWidth = 100
    $PadTitle  = " " * [math]::Max(0, ($UIWidth - $TitlePlain.Length))
    $PadStatus = " " * [math]::Max(0, ($UIWidth - $StatusStr.Length))
    $PadStats1 = " " * [math]::Max(0, ($UIWidth - $Stats1Str.Length))
    $PadStats2 = " " * [math]::Max(0, ($UIWidth - $Stats2Str.Length))
    $PadStats3 = " " * [math]::Max(0, ($UIWidth - $Stats3Str.Length))
    $PadStats4 = " " * [math]::Max(0, ($UIWidth - $Stats4Str.Length))

    $cGold  = "$([char]27)[38;2;255;215;0m"
    $cOrange = "$([char]27)[38;2;255;103;0m"
    $EColor = if ($EtwHealth -eq "Good") { $cGreen } else { $cGold }
    $MColor = if ($MlHealth -match "Native DLL|Good") { $cGreen } else { $cGold }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGold██ Deep Sensor v2.1$cReset | OS Behavioral Dashboard$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cOrange[ ENGINE STATUS ]$cReset               $cOrange[ ACTIVE DEFENSE ]$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Sensor Status : $EColor$tamperPad$cReset | Defenses Engaged : $cYellow$defFiredPad$cReset$PadStats1$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ML/UEBA       : $MColor$mlHealthPad$cReset | Total Alerts     : $cGold$alertPad$cReset$PadStats2$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Total Events  : $cWhite$evPad$cReset | Last Action      : $cWhite$lastActionPad$cReset$PadStats3$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ML/UEBA Evals : $cYellow$mlPad$cReset | Vectors          : $cWhite$vectorsPad$cReset$PadStats4$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    if ($curTop -lt 10) { $curTop = 10 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100

    # Moved up to slot perfectly under the Dashboard
    [Console]::SetCursorPosition(0, 10)

    $cGreen = "$([char]27)[38;2;57;255;20m"
    $headerPlain = "  [ LIVE THREAT TELEMETRY ]"
    $padHeader = " " * [math]::Max(0, ($UIWidth - $headerPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGreen[ LIVE THREAT TELEMETRY ]$cReset$padHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 20; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            # Strip ANSI codes from length calculation to preserve original right-side padding math
            $cleanText = $item.Text -replace "`e\[[0-9;]*m",""
            $pad = " " * [math]::Max(0, (98 - $cleanText.Length))
            Write-Host "$cCyan║$cReset  $($item.Color)$($item.Text)$cReset$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset                                                                                                    $cCyan║$cReset"
        }
    }

    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    $ControlsPlain = "  [ I ] UPDATE SIGMA  |  [ R ] ROLLBACK DEFENSE  |  [ CTRL + C ] TEARDOWN SEQUENCE"
    $PadControls   = " " * [math]::Max(0, ($UIWidth - $ControlsPlain.Length))
    Write-Host "$cCyan║$cReset$cWhite$ControlsPlain$cReset$PadControls$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    [Console]::SetCursorPosition(0, 36)
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Draw-StartupWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100

    # Shifted entirely down below the Telemetry Pane and Controls
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

# ======================================================================
# 5. ACTIVE DEFENSE & RESPONSE FUNCTIONS
# ======================================================================
function Invoke-ActiveDefense([string]$ProcName, [int]$PID_Id, [int]$TID_Id, [string]$TargetType, [string]$Reason) {
    if (-not $global:IsArmed -or $ProcName -match "Unknown|System|Idle") { return }

    # 1. THE ANTI-BSOD & BUSINESS CONTINUITY GATEKEEPER
    $BSOD_Risks = @("csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe")
    if ($BSOD_Risks -contains $ProcName.ToLower()) {
        Write-Diag "[ACTIVE DEFENSE] Skipped termination of $ProcName to prevent OS BSOD." "WARNING"
        Add-AlertMessage "DEFENSE ABORTED: OS Critical Process ($ProcName)" "$([char]27)[95;40m"
        return
    }

    $containmentStatus = "Failed"
    $forensicArtifact = "None"

    # 2. FORENSIC PRESERVATION
    $dumpPath = [DeepVisibilitySensor]::PreserveForensics($PID_Id, $ProcName)
    if ($dumpPath -ne "Failed" -and $dumpPath -ne "AccessDenied" -and $dumpPath -ne "Bypassed") {
        $forensicArtifact = $dumpPath
    }

    # 3. CONTAINMENT EXECUTION (Prefer Thread Quarantine for safe rollback)
    if ($TargetType -eq "Thread" -and $TID_Id -gt 0) {
        $res = [DeepVisibilitySensor]::QuarantineNativeThread($TID_Id, $PID_Id)
        if ($res) {
            $containmentStatus = "Thread ($TID_Id) Quarantined"
            $global:TotalMitigations++
        }
    }
    else {
        Stop-Process -Id $PID_Id -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Id $PID_Id -ErrorAction SilentlyContinue)) {
            $containmentStatus = "Process ($PID_Id) Terminated"
            $global:TotalMitigations++
        }
    }

    # 4. INCIDENT REPORTING
    $ReportDir = "C:\ProgramData\DeepSensor\Data\Reports"
    if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
    $ReportId = [guid]::NewGuid().ToString().Substring(0,8)

    $IncidentReport = @{
        IncidentID = $ReportId
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Process = $ProcName
        PID = $PID_Id
        TID = $TID_Id
        TriggerReason = $Reason
        ActionTaken = $containmentStatus
        ForensicsSavedAt = $forensicArtifact
    }
    $IncidentReport | ConvertTo-Json -Depth 4 | Out-File "$ReportDir\Incident_${ReportId}.json"

    $audit = "{$global:EnrichmentPrefix`"Category`":`"AuditTrail`", `"Action`":`"$containmentStatus`", `"TargetProcess`":`"$ProcName`", `"PID`":$PID_Id, `"TID`":$TID_Id, `"Reason`":`"$Reason`", `"ReportID`":`"$ReportId`"}"
    $script:logBatch.Add($audit)

    Add-AlertMessage "DEFENSE: $containmentStatus ($ProcName)" "$([char]27)[93;40m"
}

function Invoke-DefenseRollback {
    Write-Host "`n[!] INITIATING ACTIVE DEFENSE ROLLBACK..." -ForegroundColor Cyan

    # 1. Lift Host Isolation (Firewall)
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured -ErrorAction Stop
        Remove-NetFirewallRule -DisplayName "DeepSensor_Safe_Uplink" -ErrorAction SilentlyContinue
        Write-Diag "[ROLLBACK] Network Host Isolation lifted." "INFO"
        Add-AlertMessage "ROLLBACK: Network Isolation Lifted" "$([char]27)[96;40m"
    } catch { Write-Diag "[ROLLBACK] Network restore failed: $($_.Exception.Message)" "ERROR" }

    # 2. Look for recently suspended threads in our audit log and resume them
    # Note: In a full enterprise UI, you would select the specific TID. Here we use a safe heuristic for the last action.
    $LastSuspendedTid = 0
    # Search backwards through the log batch for the last quarantined thread
    for ($i = $script:logBatch.Count - 1; $i -ge 0; $i--) {
        if ($script:logBatch[$i] -match "`"Action`":`"Thread \((\d+)\) Quarantined`"") {
            $LastSuspendedTid = [int]$matches[1]
            break
        }
    }

    if ($LastSuspendedTid -gt 0) {
        $res = [DeepVisibilitySensor]::ResumeNativeThread($LastSuspendedTid)
        if ($res) {
            Write-Diag "[ROLLBACK] Successfully resumed Native Thread $LastSuspendedTid." "INFO"
            Add-AlertMessage "ROLLBACK: Thread $LastSuspendedTid Resumed" "$([char]27)[96;40m"
        }
    } else {
        Add-AlertMessage "ROLLBACK: No suspended threads found in active queue." "$([char]27)[90;40m"
    }
    Start-Sleep -Seconds 2
}

function Invoke-HostIsolation {
    param([string]$Reason, [string]$TriggeringProcess)

    if (-not $ArmedMode) {
        Write-Diag "[AUDIT MODE] Host Isolation bypassed for: $Reason ($TriggeringProcess)" "CRITICAL"
        return
    }

    Write-Host "`n[!] CRITICAL THREAT DETECTED: INITIATING HOST ISOLATION" -ForegroundColor Red
    Write-Host "    Reason: $Reason ($TriggeringProcess)" -ForegroundColor Yellow

    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
        New-NetFirewallRule -DisplayName "DeepSensor_Safe_Uplink" -Direction Outbound -Action Allow -RemoteAddress "10.0.0.50" -ErrorAction SilentlyContinue | Out-Null
        Write-Diag "[ACTIVE DEFENSE] Host isolated from network via Firewall. Safe Uplink preserved." "CRITICAL"
    } catch {
        Write-Diag "[ACTIVE DEFENSE ERROR] Failed to enforce firewall quarantine: $($_.Exception.Message)" "CRITICAL"
    }
}

function Submit-SensorAlert {
    param(
        [string]$Type, [string]$TargetObject, [string]$Image, [string]$Flags,
        [int]$Confidence, [int]$PID_Id = 0, [int]$TID_Id = 0, [string]$AttckMapping = "N/A",
        [string]$EventId = ([guid]::NewGuid().ToString()), [string]$RawJson = $null,
        [int]$LearningHit = 0, [string]$CommandLine = "Unknown", [switch]$IsSuppressed
    )

    # 1. Deduplication Logic
    $dedupKey = "$($Type)_$($TargetObject)_$($Flags)_$($Image)"
    $isNewAlert = -not $global:cycleAlerts.ContainsKey($dedupKey)

    if (-not $isNewAlert) {
        $global:cycleAlerts[$dedupKey].Count++
        return
    }

    # 2. Targeted UEBA Telemetry
    if ($RawJson -and ($Type -eq "ML_Anomaly" -or $Type -eq "Static_Detection")) {
        try {
            $injectStr = "`"EventID`":`"$EventId`", `"ComputerName`":`"$global:ComputerName`", `"HostIP`":`"$global:HostIP`", `"SensorUser`":`"$global:SensorUser`", `"LearningHit`":$LearningHit, "
            $enrichedJson = $RawJson.Insert(1, $injectStr)

            # Safely route the enriched telemetry directly into the Rust ML engine memory space
            [DeepVisibilitySensor]::InjectUebaTelemetry($enrichedJson)

            # Persist to local batch for SIEM forwarding
            $script:uebaBatch.Add($enrichedJson)
        } catch {}
    }

    # 3. Standardized PSCustomObject
    $alertObj = [PSCustomObject][ordered]@{
        EventID = $EventId; Count = 1
        Timestamp_Local = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        Timestamp_UTC   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        ComputerName = $global:ComputerName; HostIP = $global:HostIP; SensorUser = $global:SensorUser
        EventType = $Type; Destination = $TargetObject; Image = $Image; CommandLine = $CommandLine
        SuspiciousFlags = $Flags; ATTCKMappings = $AttckMapping; Confidence = $Confidence
        Action = if ($IsSuppressed) { "Suppressed" } elseif ($global:IsArmed -and $Confidence -ge 95) { "Mitigated" } else { "Logged" }
    }

    $global:cycleAlerts[$dedupKey] = $alertObj

    # 4. Instant HUD Rendering & Defense Routing
    if ($IsSuppressed) { return }

    $cRed = "$([char]27)[38;2;255;49;49m"; $cOrange = "$([char]27)[38;2;255;103;0m"
    $cGold = "$([char]27)[38;2;255;215;0m"; $cWhite = "$([char]27)[38;2;255;255;255m"

    if ($alertObj.Action -eq "Mitigated" -or $Confidence -ge 100) {
        Add-AlertMessage "CRITICAL BEHAVIOR: $Flags ($Image)" $cRed
    } elseif ($Confidence -ge 90) {
        Add-AlertMessage "ANOMALY: $Flags ($Image) [Conf:$Confidence]" $cOrange
    } elseif ($LearningHit -gt 0) {
        Add-AlertMessage "LEARNING: $Flags ($Image) [Hit:$LearningHit]" $cGold
    } else {
        Add-AlertMessage "STATIC: $Flags ($Image)" $cWhite
    }

    if ($alertObj.Action -eq "Mitigated") {
        Invoke-ActiveDefense -ProcName $Image -PID_Id $PID_Id -TID_Id $TID_Id -TargetType "Process" -Reason $Flags
        Invoke-HostIsolation -Reason $Flags -TriggeringProcess $Image
    }
}

# ======================================================================
# 6. ENVIRONMENT & BOOTSTRAP FUNCTIONS
# ======================================================================

function Protect-SensorEnvironment {
    Write-Diag "[*] Hardening Sensor Ecosystem (DACLs & Registry)..." "STARTUP"

    $DataDir = "C:\ProgramData\DeepSensor\Data"
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }

    $PathsToLock = @($ScriptDir, (Join-Path $ScriptDir "sigma"))
    foreach ($p in $PathsToLock) {
        if (Test-Path $p) {
            $null = icacls $p /inheritance:r /q
                $null = icacls $p /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q
                $null = icacls $p /grant "BUILTIN\Administrators:(OI)(CI)F" /q
                $null = icacls $p /deny "BUILTIN\Users:(OI)(CI)W" /q
        }
    }

    if (Test-Path $DataDir) {
        $currentUser = "$env:USERDOMAIN\$env:USERNAME"

        icacls $DataDir /inheritance:d /q *>$null
        icacls $DataDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q *>$null
        icacls $DataDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q *>$null
        icacls $DataDir /grant "${currentUser}:(OI)(CI)M" /q *>$null

        if ($null -ne $ReadAccessAccounts) {
            foreach ($account in $ReadAccessAccounts) {
                if (-not [string]::IsNullOrWhiteSpace($account)) {
                    icacls $DataDir /grant "${account}:(OI)(CI)RX" /q *>$null
                }
            }
        }
        icacls $DataDir /remove "BUILTIN\Users" /q 2>$null *>$null
    }

    Write-Diag "    [+] Discretionary Access Control Lists (DACLs) locked down." "STARTUP"

    $ServiceName = "DeepSensorService"
    $serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($serviceExists) {
        $secureSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        $null = & sc.exe sdset $ServiceName $secureSddl
        Write-Diag "    [+] Windows Service configuration secured." "STARTUP"
    }
}

function Initialize-Environment {
    Write-Diag "[*] Hardening Binary Environment & Cryptographic Validation..." "STARTUP"

    $BaseDataDir = "C:\ProgramData\DeepSensor"
    $BinDir = Join-Path $BaseDataDir "bin"
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    $MlBinaryPath = Join-Path $BinDir $MlBinaryName
    $HashPath     = $MlBinaryPath -replace "\.dll$", ".sha256"
    $binaryReady  = $false

    $ProjectDll  = Join-Path $ScriptDir $MlBinaryName
    $ProjectHash = Join-Path $ScriptDir ($MlBinaryName -replace "\.dll$", ".sha256")

    if ((Test-Path $ProjectDll) -and (Test-Path $ProjectHash)) {
        Write-Diag "    [*] New build artifacts detected in project directory. Preparing secure update..." "STARTUP"

        Write-Diag "    [*] Temporarily unlocking bin directory for update..." "STARTUP"
        $null = icacls $BinDir /inheritance:e /q
        $null = icacls $BinDir /remove "BUILTIN\Users" /q 2>$null

        if (Test-Path $MlBinaryPath) { Remove-Item $MlBinaryPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $HashPath)     { Remove-Item $HashPath     -Force -ErrorAction SilentlyContinue }

        $ExpectedHash = (Get-Content $ProjectHash -Raw).Trim()
        $ActualHash   = (Get-FileHash $ProjectDll -Algorithm SHA256).Hash

        if ($ExpectedHash -eq $ActualHash) {
            Move-Item -Path $ProjectDll  -Destination $MlBinaryPath -Force
            Move-Item -Path $ProjectHash -Destination $HashPath     -Force
            $binaryReady = $true
            Write-Diag "    [+] Hash verified → New DLL and hash successfully moved to secure bin" "STARTUP"
        }
        else {
            Write-Diag "    [!] Hash mismatch on build artifacts in project directory!" "ERROR"
        }

        Write-Diag "    [*] Re-locking bin directory..." "STARTUP"
        $null = icacls $BinDir /inheritance:d /q
        $null = icacls $BinDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q
        $null = icacls $BinDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q
        $null = icacls $BinDir /deny "BUILTIN\Users:(W)" /q
    }

    if (-not $binaryReady -and (Test-Path $MlBinaryPath) -and (Test-Path $HashPath)) {
        $ExpectedHash = (Get-Content $HashPath -Raw).Trim()
        $ActualHash   = (Get-FileHash $MlBinaryPath -Algorithm SHA256).Hash

        if ($ExpectedHash -eq $ActualHash) {
            $binaryReady = $true
            Write-Diag "    [+] Cryptographic Integrity Verified: $MlBinaryName" "STARTUP"
        } else {
            Write-Diag "    [!] CRITICAL: Hash Mismatch. Possible DLL Hijacking detected." "ERROR"
        }
    }

    if (-not $binaryReady) {
        Write-Diag "    [-] Provisioning verified binary from repository..." "STARTUP"
        try {
            if ($OfflineRepoPath) {
                Copy-Item (Join-Path $OfflineRepoPath $MlBinaryName) -Destination $MlBinaryPath -Force
                Copy-Item (Join-Path $OfflineRepoPath ($MlBinaryName -replace "\.dll$", ".sha256")) -Destination $HashPath -Force
            }

            if ((Test-Path $MlBinaryPath) -and (Test-Path $HashPath)) {
                $ExpectedHash = (Get-Content $HashPath -Raw).Trim()
                $ActualHash   = (Get-FileHash $MlBinaryPath -Algorithm SHA256).Hash
                if ($ExpectedHash -eq $ActualHash) {
                    $binaryReady = $true
                    Write-Diag "    [+] Binary successfully provisioned and verified." "STARTUP"
                }
            }
        } catch {
            Write-Diag "    [!] Acquisition failed: $($_.Exception.Message)" "ERROR"
        }
    }

    if (-not $binaryReady) {
        throw "CRITICAL: Engine initialization aborted due to missing verified artifacts."
    }

    $null = icacls $BinDir /inheritance:d /q
    $null = icacls $BinDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q
    $null = icacls $BinDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q
    $null = icacls $BinDir /deny "BUILTIN\Users:(W)" /q

    return $MlBinaryPath
}

function Initialize-TraceEventDependency {
    param([string]$ExtractBase = "C:\ProgramData\DeepSensor\Dependencies")

    Write-Diag "Validating C# ETW Dependencies..." "STARTUP"
    $ExpectedDllName = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

    $ExistingDll = Get-ChildItem -Path $ExtractBase -Filter $ExpectedDllName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ExistingDll) {
        $DllDir = Split-Path $ExistingDll.FullName -Parent
        $FastSerPath = Join-Path $DllDir "Microsoft.Diagnostics.FastSerialization.dll"
        $YaraPath = Join-Path $DllDir "libyara.NET.dll"

        # Flatten unmanaged DLLs on fast-restart
        $Amd64Dir = Join-Path $DllDir "amd64"
        if (Test-Path $Amd64Dir) {
            $UnmanagedToFlatten = @("KernelTraceControl.dll", "msdia140.dll", "yara.dll")
            foreach ($lib in $UnmanagedToFlatten) {
                $src = Join-Path $Amd64Dir $lib
                $dst = Join-Path $DllDir $lib
                if ((Test-Path $src) -and -not (Test-Path $dst)) {
                    Copy-Item -Path $src -Destination $dst -Force
                }
            }
        }

        if ((Test-Path $FastSerPath) -and (Test-Path $YaraPath)) {
            Write-Diag "[+] TraceEvent and Context-Aware YARA libraries validated." "STARTUP"
            return $ExistingDll.FullName
        }
    }

    Write-Diag "[-] TraceEvent library absent. Initiating silent deployment..." "STARTUP"
    try {
        if (Test-Path $ExtractBase) { Remove-Item $ExtractBase -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $ExtractBase -Force | Out-Null

        $SecureStaging = "C:\ProgramData\DeepSensor\Staging"
        if (-not (Test-Path $SecureStaging)) { New-Item -ItemType Directory -Path $SecureStaging -Force | Out-Null }

        $TE_Zip = "$SecureStaging\TE.zip"
        $UN_Zip = "$SecureStaging\UN.zip"

        if ($OfflineRepoPath) {
            Copy-Item (Join-Path $OfflineRepoPath "traceevent.nupkg") -Destination $TE_Zip -Force
            Copy-Item (Join-Path $OfflineRepoPath "unsafe.nupkg") -Destination $UN_Zip -Force
        } else {
            $TE_Url = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.2"
            $UN_Url = "https://www.nuget.org/api/v2/package/System.Runtime.CompilerServices.Unsafe/5.0.0"
            Invoke-WebRequest -Uri $TE_Url -OutFile $TE_Zip -UseBasicParsing
            Invoke-WebRequest -Uri $UN_Url -OutFile $UN_Zip -UseBasicParsing
        }

        Expand-Archive -Path $TE_Zip -DestinationPath "$ExtractBase\TE" -Force
        Expand-Archive -Path $UN_Zip -DestinationPath "$ExtractBase\UN" -Force
        Remove-Item $TE_Zip, $UN_Zip -Force -ErrorAction SilentlyContinue

        $YARA_Zip = "$SecureStaging\YARA.zip"
        if ($OfflineRepoPath) {
            Copy-Item (Join-Path $OfflineRepoPath "libyaranet.nupkg") -Destination $YARA_Zip -Force
        } else {
            Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/libyara.NET/3.5.2" -OutFile $YARA_Zip -UseBasicParsing
        }
        Expand-Archive -Path $YARA_Zip -DestinationPath "$ExtractBase\YARA" -Force
        Remove-Item $YARA_Zip -Force -ErrorAction SilentlyContinue

        $FoundDll = Get-ChildItem -Path "$ExtractBase\TE" -Filter $ExpectedDllName -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -match "net462|netstandard|net45" } | Select-Object -First 1

        if ($FoundDll) {
            $DllDir = Split-Path $FoundDll.FullName -Parent
            $UnsafeDll = Get-ChildItem -Path "$ExtractBase\UN" -Filter "System.Runtime.CompilerServices.Unsafe.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "net45|netstandard|net46" } | Select-Object -First 1
            if ($UnsafeDll) { Copy-Item -Path $UnsafeDll.FullName -Destination $DllDir -Force }

            $Amd64Dir = Join-Path $DllDir "amd64"
            if (-not (Test-Path $Amd64Dir)) { New-Item -ItemType Directory -Path $Amd64Dir -Force | Out-Null }

            $NativeHelpers = @(
                (Get-ChildItem -Path "$ExtractBase\TE" -Filter "KernelTraceControl.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1),
                (Get-ChildItem -Path "$ExtractBase\TE" -Filter "msdia140.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1)
            )

            foreach ($h in $NativeHelpers) {
                if ($h) {
                    Copy-Item -Path $h.FullName -Destination $Amd64Dir -Force
                    Copy-Item -Path $h.FullName -Destination $DllDir -Force
                }
            }

            $ManagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "libyara.NET.dll" -Recurse | Select-Object -First 1
            $UnmanagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "yara.dll" -Recurse | Where-Object { $_.FullName -match "win-x64" } | Select-Object -First 1

            if ($ManagedYara) { Copy-Item -Path $ManagedYara.FullName -Destination $DllDir -Force }
            if ($UnmanagedYara) {
                Copy-Item -Path $UnmanagedYara.FullName -Destination $Amd64Dir -Force
                Copy-Item -Path $UnmanagedYara.FullName -Destination $DllDir -Force
            }

            Write-Diag "[+] TraceEvent library deployed successfully." "STARTUP"
            return $FoundDll.FullName
        } else {
            throw "DLL not found within extracted package structure."
        }
    } catch {
        Write-Diag "[!] TraceEvent deployment failed: $($_.Exception.Message)" "STARTUP"
        return $null
    }
}

function Invoke-EnvironmentalAudit {
    Write-Diag "    [*] Initializing Environmental Audit..." "STARTUP"
    Write-Diag "        [*] Executing Proactive Posture & WMI Sweep..." "STARTUP"

    $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if (-not $lsa -or $lsa.RunAsPPL -ne 1) {
        Write-Diag "[POSTURE] Vulnerability: LSASS is not running as a Protected Process Light (PPL)." "AUDIT"
    }

    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
        Write-Diag "[POSTURE] Vulnerability: RDP is currently enabled and exposed." "AUDIT"
    }

    try {
        $consumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction Stop
        foreach ($c in $consumers) {
            if ($c.CommandLineTemplate -match "powershell|cmd|wscript|cscript") {
                Write-Diag "[THREAT HUNT] Suspicious WMI Event Consumer Found: $($c.Name) -> $($c.CommandLineTemplate)" "CRITICAL"
            }
        }
    } catch { }
}

# ======================================================================
# 7. THREAT INTELLIGENCE & COMPILER FUNCTIONS
# ======================================================================

function Sync-YaraIntelligence {
    Write-Diag "Syncing YARA Intelligence (Elastic & ReversingLabs)..." "STARTUP"

    $YaraBaseDir = Join-Path $ScriptDir "yara"
    $VectorDir = if ($OfflineRepoPath) { Join-Path $OfflineRepoPath "yara_rules" } else { Join-Path $ScriptDir "yara_rules" }

    $CacheMarker = Join-Path $ScriptDir "yara.cache"
    $needsDownload = $true

    if (Test-Path $CacheMarker) {
        if (((Get-Date) - (Get-Item $CacheMarker).LastWriteTime).TotalHours -lt 24) {
            $needsDownload = $false
            Write-Diag "    [*] Using cached YARA Intelligence (< 24h old). Skipping download." "STARTUP"
        }
    }

    if (-not (Test-Path $YaraBaseDir)) { New-Item -ItemType Directory -Path $YaraBaseDir -Force | Out-Null }

    if ($needsDownload) {
        $Sources = @(
            @{ Name = "ElasticLabs"; Url = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"; SubPath = "protections-artifacts-main/yara" },
            @{ Name = "ReversingLabs"; Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip"; SubPath = "reversinglabs-yara-rules-develop/yara" },
            @{ Name = "SignatureBase_Neo23x0"; Url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"; SubPath = "signature-base-master/yara" }
        )

        $SecureStaging = "C:\ProgramData\DeepSensor\Staging"
        if (-not (Test-Path $SecureStaging)) { New-Item -ItemType Directory -Path $SecureStaging -Force | Out-Null }

        foreach ($src in $Sources) {
            $TempZip = "$SecureStaging\$($src.Name).zip"
            $TempExt = "$SecureStaging\$($src.Name)_extract"

            try {
                if ($OfflineRepoPath) {
                    $OfflineZip = Join-Path $OfflineRepoPath "$($src.Name).zip"
                    if (Test-Path $OfflineZip) { Copy-Item $OfflineZip -Destination $TempZip -Force }
                } else {
                    Write-Diag "    [*] Downloading $($src.Name) ruleset..." "STARTUP"
                    Invoke-WebRequest -Uri $src.Url -OutFile $TempZip -UseBasicParsing -ErrorAction Stop
                }

                if (Test-Path $TempZip) {
                    Expand-Archive -Path $TempZip -DestinationPath $TempExt -Force
                    $SourceRules = Join-Path $TempExt $src.SubPath
                    Copy-Item -Path "$SourceRules\*" -Destination $YaraBaseDir -Recurse -Force
                    Write-Diag "    [+] $($src.Name) staged to local yara/ directory." "STARTUP"
                }
            } catch {
                Write-Diag "    [-] Failed to sync $($src.Name): $($_.Exception.Message)" "STARTUP"
            } finally {
                if (Test-Path $TempZip) { Remove-Item $TempZip -Force }
                if (Test-Path $TempExt) { Remove-Item $TempExt -Recurse -Force }
            }
        }
        New-Item -Path $CacheMarker -ItemType File -Force | Out-Null
    }

    $LocalRules = Get-ChildItem -Path $YaraBaseDir -Filter "*.yar" -Recurse
    Write-Diag "    [*] Sorting $($LocalRules.Count) rules into context-aware vectors..." "STARTUP"

    $Vectors = @("WebInfrastructure", "SystemExploits", "LotL", "MacroPayloads", "BinaryProxy", "SystemPersistence", "InfostealerTargets", "RemoteAdmin", "DevOpsSupplyChain", "Core_C2")
    foreach ($v in $Vectors) {
        $vPath = Join-Path $VectorDir $v
        if (-not (Test-Path $vPath)) { New-Item -ItemType Directory -Path $vPath -Force | Out-Null }
    }

    foreach ($rule in $LocalRules) {
        try {
            # GATEKEEPER: Test-compile the rule in memory before committing to a vector
            if (-not [DeepVisibilitySensor]::IsYaraRuleValid($rule.FullName)) {
                continue # Skip this file and move to the next
            }

            $content = [System.IO.File]::ReadAllText($rule.FullName)
            $target = "Core_C2"

            if ($content -match "webshell|aspx?|php|iis|nginx|tomcat") { $target = "WebInfrastructure" }
            elseif ($content -match "exploit|cve|lsass|spoolsv|privesc") { $target = "SystemExploits" }
            elseif ($content -match "powershell|cmd|wscript|cscript|encoded") { $target = "LotL" }
            elseif ($content -match "vba|macro|office|doc|xls") { $target = "MacroPayloads" }
            elseif ($content -match "rundll32|regsvr32|mshta|dll_loading|sideload") { $target = "BinaryProxy" }
            elseif ($content -match "com_hijack|persistence|registry_run|startup") { $target = "SystemPersistence" }
            elseif ($content -match "cookie|infostealer|stealer|credential|browser") { $target = "InfostealerTargets" }
            elseif ($content -match "remotemanagement|rmm|vnc|rdp|tunnel") { $target = "RemoteAdmin" }
            elseif ($content -match "reverse_shell|supply_chain|container|escape") { $target = "DevOpsSupplyChain" }

            [System.IO.File]::Copy($rule.FullName, (Join-Path $VectorDir "$target\$($rule.Name)"), $true)
        }
        catch { continue }
    }
    Write-Diag "    [+] YARA Intelligence sorted and ready for compilation." "STARTUP"
}

function Get-CompiledSigmaBase64 {
    $LocalSigmaDir = Join-Path $ScriptDir "sigma"
    if (-not (Test-Path $LocalSigmaDir)) { return "" }

    $SigmaFiles = Get-ChildItem -Path $LocalSigmaDir -Include "*.yml", "*.yaml" -Recurse
    $RuleList = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($file in $SigmaFiles) {
        $lines = Get-Content $file.FullName
        $content = $lines -join "`n"

        # Noise reduction and scope filters
        if ($content -notmatch "product:\s*windows") { continue }
        if ($content -match "XBAP Execution From Uncommon Locations" -or
            $content -match "Suspicious Double Extension File Execution" -or
            $content -match "PresentationHost\.EXE") { continue }
        if ($content -match "sha256:" -or $content -match "md5:") { continue }

        $title = "Unknown Sigma Rule"
        $category = "process_creation" # Default fallback
        $ruleTags = @()
        $inAnchorBlock = $false
        $inTagsBlock = $false

        foreach ($line in $lines) {
            if ($line -match "(?i)^title:\s*(.+)") { $title = $matches[1].Trim(" '`""); continue }

            # Extract Category to route to the correct C# 0-Alloc Search Tree
            if ($line -match "(?i)category:\s*(.+)") {
                $rawCat = $matches[1].Trim(" '`"").ToLower()
                if ($rawCat -match "registry") { $category = "registry_event" }
                elseif ($rawCat -match "file") { $category = "file_event" }
                elseif ($rawCat -match "image") { $category = "image_load" }
                elseif ($rawCat -match "network|connection") { $category = "network_connection" }
                elseif ($rawCat -match "pipe") { $category = "pipe_created" }
                else { $category = "process_creation" }
                continue
            }

            if ($line -match "(?i)^tags:") { $inTagsBlock = $true; $inAnchorBlock = $false; continue }
            if ($line -match "(?i)(CommandLine|Query|PipeName|TargetObject|TargetFilename|Details|ScriptBlockText|ImageLoaded|Signature|Image|ParentImage|CommandLine|Image)\|.*?(contains|endswith|startswith|equals|match|regex).*?:(.+)") {
                $inAnchorBlock = $true; $inTagsBlock = $false; continue
            }

            if ($inTagsBlock) {
                if ($line -match "^\s*-\s*(.+)") {
                    $val = $matches[1].Trim(" '`"")
                    if (-not [string]::IsNullOrWhiteSpace($val)) { $ruleTags += $val }
                } elseif ($line -match "^[a-zA-Z]") { $inTagsBlock = $false }
            }

            if (-not $inTagsBlock -and $line -match "^[a-zA-Z]") { $inAnchorBlock = $false }

            if ($inAnchorBlock -and $line -match "^\s*-\s*(.+)") {
                $val = $matches[1].Trim(" '`"")
                if (-not [string]::IsNullOrWhiteSpace($val) -and $val.Length -gt 3 -and $val -notmatch "(?i)^\.exe$" -and $val -notmatch "(?i)^[a-z]:\\\\?$") {
                    $formattedTitle = if ($ruleTags.Count -gt 0) { "$title [$($ruleTags -join ', ')]" } else { $title }
                    [void]$RuleList.Add(@{ id = $formattedTitle; category = $category; anchor_string = $val })
                }
            }
        }
    }

    if ($RuleList.Count -eq 0) { return "" }
    $ruleStrings = [System.Collections.Generic.List[string]]::new()
    foreach ($rule in $RuleList) {
        $b64Anchor = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rule.anchor_string))
        $ruleStrings.Add("$($rule.category)|$($rule.id)|$b64Anchor")
    }

    $Payload = $ruleStrings -join "[NEXT]"
    $Base64Sigma = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Payload))
    return $Base64Sigma
}

function Invoke-StagingInjection {
    $StagingDir = "$ScriptDir\sigma_staging"
    $SigmaDir = "$ScriptDir\sigma"

    if (-not (Test-Path $StagingDir)) {
        Write-Diag "`n[*] Staging directory '\sigma_staging' has no rules. Skipping." "STARTUP"
        Start-Sleep -Seconds 1
        return
    }

    try {
        $StagedFiles = Get-ChildItem -Path $StagingDir -Filter "*.yaml" -ErrorAction Stop
        if ($StagedFiles.Count -gt 0) {
            Write-Diag "`n[!] HOT RELOAD INITIATED: Injecting $($StagedFiles.Count) rules from staging..." "STARTUP"

            if (-not (Test-Path $SigmaDir)) { New-Item -ItemType Directory -Path $SigmaDir | Out-Null }
            Move-Item -Path "$StagingDir\*.yaml" -Destination $SigmaDir -Force -ErrorAction Stop

            $NewBase64Rules = Get-CompiledSigmaBase64
            if (-not [string]::IsNullOrEmpty($NewBase64Rules)) {
                [DeepVisibilitySensor]::UpdateSigmaRules($NewBase64Rules)
            }
            Add-AlertMessage "HOT RELOAD SUCCESSFUL" "$([char]27)[92;40m"
            Start-Sleep -Seconds 2
        } else {
            Write-Diag "`n[*] Staging directory is empty. No rules to inject." "STARTUP"
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Diag "`n[-] HOT RELOAD FAILED: $($_.Exception.Message)" "STARTUP"
        Start-Sleep -Seconds 2
    }
}

function Initialize-SigmaEngine {
    Write-Diag "Initializing Sigma Compiler & Threat Intelligence Matrices..." "STARTUP"

    $LocalSigmaDir = Join-Path $ScriptDir "sigma"
    if (-not (Test-Path $LocalSigmaDir)) { New-Item -ItemType Directory -Path $LocalSigmaDir -Force | Out-Null }

    $SigmaCacheMarker = Join-Path $ScriptDir "sigma.cache"
    $needsSigmaDownload = $true

    if (Test-Path $SigmaCacheMarker) {
        if (((Get-Date) - (Get-Item $SigmaCacheMarker).LastWriteTime).TotalHours -lt 24) {
            $needsSigmaDownload = $false
            Write-Diag "    [*] Using cached Sigma HQ Rules (< 24h old). Skipping download." "STARTUP"
        }
    }

    if ($needsSigmaDownload) {
        $SecureStaging = "C:\ProgramData\DeepSensor\Staging"
        if (-not (Test-Path $SecureStaging)) { New-Item -ItemType Directory -Path $SecureStaging -Force | Out-Null }

        $TempZipPath = "$SecureStaging\sigma_master.zip"
        $ExtractPath = "$SecureStaging\sigma_extract"

        try {
            if ($OfflineRepoPath) {
                Write-Diag "    [*] Fetching Sigma rules from offline repository..." "STARTUP"
                Copy-Item (Join-Path $OfflineRepoPath "sigma_master.zip") -Destination $TempZipPath -Force -ErrorAction Stop
            } else {
                Write-Diag "    [*] Fetching latest Sigma rules from SigmaHQ GitHub..." "STARTUP"
                $SigmaZipUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
                Invoke-WebRequest -Uri $SigmaZipUrl -OutFile $TempZipPath -UseBasicParsing -ErrorAction Stop
            }
            Expand-Archive -Path $TempZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop

            $RuleCategories = @(
                "process_creation", "file_event", "registry_event", "wmi_event", "pipe_created",
                "ps_module", "ps_script", "ps_classic_start", "ps_classic_provider",
                "driver_load", "image_load", "network_connection", "dns", "firewall",
                "webserver", "sysmon", "powershell", "security", "application",
                "threat_hunting", "emerging_threats"
            )

            foreach ($cat in $RuleCategories) {
                $RulesPath = Join-Path $ExtractPath "sigma-master\rules\windows\$cat\*"
                if (Test-Path (Split-Path $RulesPath)) {
                    Copy-Item -Path $RulesPath -Destination $LocalSigmaDir -Recurse -Force
                }
            }
            New-Item -Path $SigmaCacheMarker -ItemType File -Force | Out-Null
            Write-Diag "    [+] Successfully updated local Sigma repository with Advanced Detection vectors." "STARTUP"
        } catch {
            Write-Diag "    [-] GitHub pull failed (Network/Firewall). Proceeding with local cache." "STARTUP"
        } finally {
            if (Test-Path $TempZipPath) { Remove-Item $TempZipPath -Force -ErrorAction SilentlyContinue }
            if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    $SigmaFiles = Get-ChildItem -Path $LocalSigmaDir -Include "*.yml", "*.yaml" -Recurse
    $RuleList = [System.Collections.Generic.List[hashtable]]::new()

    $ParsedCount = 0
    $SkippedCount = 0

    Write-Diag "    [*] Compiling local Sigma rules into Zero-Allocation Flat Arrays..." "STARTUP"

    foreach ($file in $SigmaFiles) {
        $lines = Get-Content $file.FullName
        $content = $lines -join "`n"

        if ($content -notmatch "product:\s*windows") { $SkippedCount++; continue }
        if ($content -match "XBAP Execution From Uncommon Locations" -or
            $content -match "Suspicious Double Extension File Execution" -or
            $content -match "PresentationHost\.EXE") {
            $SkippedCount++; continue
        }
        if ($content -match "sha256:" -or $content -match "md5:") { $SkippedCount++; continue }

        $title = "Unknown Sigma Rule"
        $category = "process_creation" # Default fallback
        $ruleTags = @()
        $inAnchorBlock = $false
        $inTagsBlock = $false

        foreach ($line in $lines) {
            # Extract Title
            if ($line -match "(?i)^title:\s*(.+)") { $title = $matches[1].Trim(" '`""); continue }

            # Extract Category to route to the correct C# 0-Alloc Search Tree
            if ($line -match "(?i)category:\s*(.+)") {
                $rawCat = $matches[1].Trim(" '`"").ToLower()
                if ($rawCat -match "registry") { $category = "registry_event" }
                elseif ($rawCat -match "file") { $category = "file_event" }
                elseif ($rawCat -match "image") { $category = "image_load" }
                elseif ($rawCat -match "network|connection") { $category = "network_connection" }
                elseif ($rawCat -match "pipe") { $category = "pipe_created" }
                else { $category = "process_creation" }
                continue
            }

            if ($line -match "(?i)^tags:") { $inTagsBlock = $true; $inAnchorBlock = $false; continue }

            # Unified regex to catch anchor strings across all categories
            if ($line -match "(?i)(CommandLine|Query|PipeName|TargetObject|TargetFilename|Details|ScriptBlockText|ImageLoaded|Signature|Image|ParentImage)\|.*?(contains|endswith|startswith).*?:") {
                $inAnchorBlock = $true; $inTagsBlock = $false; continue
            }

            if ($inTagsBlock) {
                if ($line -match "^\s*-\s*(.+)") {
                    $val = $matches[1].Trim(" '`"")
                    if (-not [string]::IsNullOrWhiteSpace($val)) { $ruleTags += $val }
                } elseif ($line -match "^[a-zA-Z]") {
                    $inTagsBlock = $false
                }
            }

            if (-not $inTagsBlock -and $line -match "^[a-zA-Z]") { $inAnchorBlock = $false }

            if ($inAnchorBlock -and $line -match "^\s*-\s*(.+)") {
                $val = $matches[1].Trim(" '`"")
                if (-not [string]::IsNullOrWhiteSpace($val) -and $val.Length -gt 3 -and $val -notmatch "(?i)^\.exe$" -and $val -notmatch "(?i)^[a-z]:\\\\?$") {

                    $formattedTitle = if ($ruleTags.Count -gt 0) { "$title [$($ruleTags -join ', ')]" } else { $title }

                    [void]$RuleList.Add(@{ id = $formattedTitle; category = $category; anchor_string = $val })
                }
            }
        }
        $ParsedCount++
    }

    # Re-inject the core built-in commands
    $BuiltInCmds = @("sekurlsa::logonpasswords", "lsadump::", "privilege::debug", "Invoke-BloodHound", "procdump -ma lsass", "vssadmin delete shadows")
    foreach ($c in $BuiltInCmds) {
        [void]$RuleList.Add(@{ id = "Built-in Core TI Signature"; category = "process_creation"; anchor_string = $c })
    }

    Write-Diag "    [+] Gatekeeper Compilation Complete: $ParsedCount rules armed ($SkippedCount incompatible rules safely bypassed)." "STARTUP"

    $TiDriverSignatures = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $OfflineDrivers = @("capcom.sys", "iqvw64.sys", "RTCore64.sys", "gdrv.sys", "AsrDrv.sys", "procexp.sys")
    foreach ($d in $OfflineDrivers) { [void]$TiDriverSignatures.Add($d) }

    $LolDriversCache = Join-Path $ScriptDir "loldrivers.json"
    $needsDriverDownload = $true
    if (Test-Path $LolDriversCache) {
        if (((Get-Date) - (Get-Item $LolDriversCache).LastWriteTime).TotalHours -lt 24) { $needsDriverDownload = $false }
    }

    try {
        $jsonString = ""
        if ($OfflineRepoPath) {
            Write-Diag "[*] Loading LOLDrivers Threat Intel from offline repository..." "STARTUP"
            $jsonString = Get-Content (Join-Path $OfflineRepoPath "drivers.json") -Raw
        } elseif ($needsDriverDownload) {
            Write-Diag "[*] Fetching live LOLDrivers.io Threat Intel..." "STARTUP"
            $response = Invoke-WebRequest -Uri "https://www.loldrivers.io/api/drivers.json" -UseBasicParsing -ErrorAction Stop
            $jsonString = $response.Content
            $jsonString | Out-File -FilePath $LolDriversCache -Encoding UTF8 -Force
        } else {
            Write-Diag "[*] Loading cached LOLDrivers.io Threat Intel (< 24h old)..." "STARTUP"
            $jsonString = Get-Content $LolDriversCache -Raw
        }

        $jsonString = $jsonString -replace '"INIT"', '"init"'
        $apiDrivers = $jsonString | ConvertFrom-Json

        $liveCount = 0
        foreach ($entry in $apiDrivers) {
            if ($entry.KnownVulnerableSamples) {
                foreach ($sample in $entry.KnownVulnerableSamples) {
                    if (-not [string]::IsNullOrWhiteSpace($sample.Filename)) {
                        if ($TiDriverSignatures.Add($sample.Filename)) {
                            $liveCount++
                        }
                    }
                }
            }
        }
        Write-Diag "[+] Integrated $liveCount live BYOVD signatures." "STARTUP"
    } catch {
        Write-Diag "[-] LOLDrivers API parsing failed: $($_.Exception.Message)" "STARTUP"
    }

    $ruleStrings = [System.Collections.Generic.List[string]]::new()
    foreach ($rule in $RuleList) {
        $b64Anchor = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rule.anchor_string))
        $ruleStrings.Add("$($rule.category)|$($rule.id)|$b64Anchor")
    }

    $Payload = $ruleStrings -join "[NEXT]"
    $Base64Sigma = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Payload))

    return @{
        Base64Sigma = $Base64Sigma
        Drivers = [string[]]($TiDriverSignatures | Select-Object)
    }
}

function Get-IniContent([string]$filePath) {
    $ini = @{}
    $currentSection = "Default"
    $ini[$currentSection] = @{}

    $lines = Get-Content $filePath -ErrorAction Stop
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { continue }

        if ($line -match "^\[(.*)\]$") {
            $currentSection = $matches[1].Trim()
            if (-not $ini.ContainsKey($currentSection)) { $ini[$currentSection] = @{} }
        } elseif ($line -match "^([^=]+)=(.*)$") {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            $ini[$currentSection][$key] = $val
        }
    }
    return $ini
}

# ======================================================================
# 8. MAIN EXECUTION FLOW (the only top-level code)
# ======================================================================

$ConfigPath = Join-Path $ScriptDir "DeepSensor_Config.ini"
if (-not (Test-Path $ConfigPath)) { throw "CRITICAL: Missing DeepSensor_Config.ini." }

Write-Diag "[*] Loading external process and registry exclusions..." "STARTUP"
$IniConfig = Get-IniContent $ConfigPath

if (-not $IniConfig.ContainsKey("ProcessExclusions")) { $IniConfig["ProcessExclusions"] = @{} }
if (-not $IniConfig.ContainsKey("RegistryExclusions")) { $IniConfig["RegistryExclusions"] = @{} }

$BenignADSProcs = ($IniConfig["ProcessExclusions"]["BenignADSProcs"]) -split ",\s*"
$TrustedNoise   = ($IniConfig["ProcessExclusions"]["TrustedNoise"]) -split ",\s*"
$BenignExplorerValues = ($IniConfig["RegistryExclusions"]["BenignExplorerValues"]) -split ",\s*"

# Merge ADS and Trusted Noise for the OS Sensor exclusion pipeline
$CombinedProcessExclusions = $BenignADSProcs + $TrustedNoise

$ValidMlBinaryPath = Initialize-Environment

$ActualDllPath = Initialize-TraceEventDependency -ExtractBase "C:\ProgramData\DeepSensor\Dependencies"
if (-not $ActualDllPath) {
    Write-Host "`n[!] CRITICAL: TraceEvent dependency missing. Cannot start ETW sensor. Exiting." -ForegroundColor Red
    Exit
}
$TraceEventDllPath = $ActualDllPath
Write-Diag "    [+] Environment Bootstrap Complete." "STARTUP"

Invoke-EnvironmentalAudit

$CompiledTI = Initialize-SigmaEngine

Write-Diag "Initializing Core Engine..." "STARTUP"

# 1. Compile C# Sensor into RAM
try {
    $DllDir = Split-Path $ActualDllPath -Parent
    $SiblingDlls = Get-ChildItem -Path $DllDir -Filter "*.dll" | Where-Object { $_.Name -notmatch "KernelTraceControl|msdia140|yara(?!\.NET)" }

    foreach ($dll in $SiblingDlls) {
        try { [System.Reflection.Assembly]::LoadFrom($dll.FullName) | Out-Null } catch {}
    }

    $RefAssemblies = @(
        "mscorlib",
        "System", "System.Core", "System.Collections",
        "System.Collections.Concurrent", "System.Runtime", "System.Diagnostics.Process",
        "System.Linq.Expressions", "System.ComponentModel", "System.ComponentModel.Primitives", "netstandard",
        "System.Threading", "System.Threading.Thread"
    )

    if ($SiblingDlls) {
        foreach ($dll in $SiblingDlls) { $RefAssemblies += $dll.FullName }
    }

    if (-not ("DeepVisibilitySensor" -as [type])) {
        Add-Type -TypeDefinition (Get-Content (Join-Path $ScriptDir "OsSensor.cs") -Raw) `
                 -ReferencedAssemblies $RefAssemblies `
                 -ErrorAction Stop
    }

    Write-Diag "    [*] Bootstrapping unmanaged memory structures..." "STARTUP"

    # Map the DLL path for the C# DllImport dynamically
    $SecureBinDir = Split-Path $ValidMlBinaryPath -Parent
    [DeepVisibilitySensor]::SetLibraryPath($SecureBinDir)

    # Initialize the C# Engine with the 5 required core parameters
    [DeepVisibilitySensor]::Initialize(
        $ActualDllPath,
        $PID,
        $CompiledTI.Drivers,
        $BenignExplorerValues,
        $CombinedProcessExclusions
    )

    # Inject the startup Sigma JSON Matrix
    if (-not [string]::IsNullOrEmpty($CompiledTI.Base64Sigma)) {
        [DeepVisibilitySensor]::UpdateSigmaRules($CompiledTI.Base64Sigma)
    } else {
        Write-Diag "    [!] Warning: No valid Sigma rules parsed on startup." "STARTUP"
        $EmptyJson = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("[]"))
        [DeepVisibilitySensor]::UpdateSigmaRules($EmptyJson)
    }

    Sync-YaraIntelligence
    $YaraRulesPath = if ($OfflineRepoPath) { Join-Path $OfflineRepoPath "yara_rules" } else { Join-Path $ScriptDir "yara_rules" }
    [DeepVisibilitySensor]::InitializeYaraMatrices($YaraRulesPath)
    [DeepVisibilitySensor]::StartSession()
    [DeepVisibilitySensor]::IsArmed = $ArmedMode.IsPresent

} catch {
    Write-Diag "CRITICAL: Engine Compilation Failed. Check OsSensor.cs syntax." "ERROR"
    Write-Diag "Error Detail: $($_.Exception.Message)" "ERROR"
    throw $_
}

Protect-SensorEnvironment

# ==============================================================================
Write-Diag "Initiating 20-second JIT compilation and RAM stabilization phase..." "STARTUP"
Write-Diag "    [*] Initializing Math Engine and pre-compiling native FFI pointers..." "STARTUP"
Write-Host "[*] Stabilizing memory footprint (20-second cooldown)..." -ForegroundColor Cyan

$ESC = [char]27
$cGrid      = "$ESC[38;2;0;100;200m"
$cLand      = "$ESC[38;2;20;220;80m"
$cTrail     = "$ESC[38;2;0;255;255m"
$cMapText   = "$ESC[38;2;0;255;255m"
$cWhite     = "$ESC[38;2;255;255;255m"
$cRed       = "$ESC[38;2;255;50;50m"
$cYellow    = "$ESC[38;2;255;215;0m"
$cReset     = "$ESC[0m"

$cursor = "█"

function Invoke-WoprTyping {
    param([string]$text, [int]$baseDelay = 40, [int]$pause = 800)
    foreach ($char in $text.ToCharArray()) {
        Write-Host "$cMapText$char" -NoNewline
        Write-Host "$cMapText$cursor" -NoNewline
        Start-Sleep -Milliseconds ($baseDelay + (Get-Random -Min -10 -Max 30))
        Write-Host "`b `b" -NoNewline
    }
    Write-Host ""
    Start-Sleep -Milliseconds $pause
}

[Console]::Clear()
Write-Host "`n`n"

Invoke-WoprTyping -text "LOGON: Joshua" -pause 600
Invoke-WoprTyping -text "GREETINGS PROFESSOR FALKEN." -pause 800
Invoke-WoprTyping -text "SHALL WE PLAY A GAME?" -pause 1000

$games = @(
    "CHECKERS", "CHESS", "POKER", "FIGHTER COMBAT",
    "GUERRILLA ENGAGEMENT", "DESERT WARFARE", "AIR-TO-GROUND ACTIONS",
    "THEATERWIDE TACTICAL WARFARE", "THEATERWIDE BIOTOXIC AND CHEMICAL WARFARE",
    "", "GLOBAL THERMONUCLEAR WAR"
)

foreach ($g in $games) {
    if ($g -eq "") { Start-Sleep -Milliseconds 500; continue }
    Write-Host "  $cMapText$g"
    Start-Sleep -Milliseconds 120
}

Start-Sleep -Milliseconds 1500
[Console]::Clear()
Write-Host "`n"

[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

$simStart = Get-Date
$width = [Console]::WindowWidth - 2
$startY = [Console]::CursorTop + 1

if ($startY -ge 20) { $startY = 2 }

$worldMap = @(
'   180   150W  120W  90W   60W   30W   000   30E   60E   90E   120E  150E  180',
'    |     |     |     |     |     |     |     |     |     |     |     |     |',
'90N-+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-90N',
'    |           . _..::__:  ,-"-"._        |7       ,     _,.__             |',
'    |   _.___ _ _<_>`!(._`.`-.    /         _._     `_ ,_/  ''  ''-._.---.-.__|',
'    |>.{     " " `-==,'',._\{  \  / {)      / _ ">_,-'' `                mt-2_|',
'60N-+  \_.:--.       `._ )`^-. "''       , [_/(                       __,/-'' +-60N',
'    | ''"''     \         "    _L        oD_,--''                )     /. (|   |',
'    |          |           ,''          _)_.\\._<> 6              _,'' /  ''   |',
'    |          `.         /           [_/_''` `"(                <''}  )      |',
'30N-+           \\    .-. )           /   `-''".." `:._          _)  ''       +-30N',
'    |    `        \  (  `(           /         `:\  > \  ,-^.  /'' ''         |',
'    |              `._,   ""         |           \`''   \|   ?_)  {\         |',
'    |                 `=.---.        `._._       ,''     "`  |'' ,- ''.        |',
'000-+                   |    `-._         |     /          `:`<_|h--._      +-000',
'    |                   (        >        .     | ,          `=.__.`-''\     |',
'    |                    `.     /         |     |{|              ,-.,\     .|',
'    |                     |   ,''           \   / `''            ,"     \     |',
'30S-+                     |  /              |_''                |  __  /     +-30S',
'    |                     | |                                  ''-''  `-''   \.|',
'    |                     |/                                         "    / |',
'    |                     \.                                             ''  |',
'60S-+                                                                       +-60S',
'    |                      ,/            ______._.--._ _..---.---------._   |',
'    |     ,-----"-..?----_/ )      __,-''"             "                  (  |',
'    |-.._(                  `-----''                                       `-|',
'90S-+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-90S',
'    Map 1998 Matthew Thomas.|Freely usable as long as this|line is included.|',
'    |     |     |     |     |     |     |     |     |     |     |     |     |',
'   180   150W  120W  90W   60W   30W   000   30E   60E   90E   120E  150E  180',
'-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----'
)

Write-Host "$ESC[?25l" -NoNewline
$mapOffsetX = 5
$mapWidth = 83

for ($i = 0; $i -lt $worldMap.Count; $i++) {
    try {
        [Console]::SetCursorPosition($mapOffsetX, $startY + $i)
        if ($i -le 2 -or $i -ge 26) {
            Write-Host "$cGrid$($worldMap[$i])" -NoNewline
        } else {
            $line = $worldMap[$i] -replace "^(\d+[NS]-?\+?\s*\|\s*)", "$cGrid`$1$cLand"
            $line = $line -replace "(\s*\|\s*\+?-?\d*[NS]?)$", "$cGrid`$1"
            Write-Host "$cLand$line" -NoNewline
        }
    } catch {}
}

$icbms = [System.Collections.Generic.List[PSCustomObject]]::new()
$explosions = [System.Collections.Generic.List[PSCustomObject]]::new()
$activeSubs = [System.Collections.Generic.List[PSCustomObject]]::new()
$frames = 0
$impacts = 0

while (((Get-Date) - $simStart).TotalSeconds -lt 20) {
    $frames++

    $timeSecs = [math]::Round(((Get-Date) - $simStart).TotalSeconds)
    try {
        [Console]::SetCursorPosition(2, $startY - 2)
        if ($timeSecs % 2 -eq 0) { Write-Host "$cRed[ DEFCON 1 ]" -NoNewline }
        else { Write-Host "$cWhite[ DEFCON 1 ]" -NoNewline }
        [Console]::SetCursorPosition(17, $startY - 2)
        Write-Host "$cYellow CASUALTIES: $(($impacts * 5.2).ToString('N1')) M " -NoNewline
    } catch {}

    if ((Get-Random -Max 100) -gt 85 -and $activeSubs.Count -lt 15) {
        $subX = Get-Random -Min 6 -Max ($mapWidth - 6)
        $subY = Get-Random -Min 4 -Max 24

        if ($worldMap[$subY][$subX] -eq ' ') {
            $activeSubs.Add([PSCustomObject]@{ X = $mapOffsetX + $subX; Y = $startY + $subY; Char = "▲" })
            try {
                [Console]::SetCursorPosition($mapOffsetX + $subX, $startY + $subY)
                Write-Host "$cRed▲" -NoNewline
            } catch {}
        }
    }

    if ((Get-Random -Max 100) -gt 45) {
        $origin = Get-Random -Max 5
        $startX = 0; $startYc = 0

        switch ($origin) {
            0 { $startX = (Get-Random -Min 15 -Max 30); $startYc = $startY + (Get-Random -Min 5 -Max 13) }
            1 { $startX = (Get-Random -Min 55 -Max 75); $startYc = $startY + (Get-Random -Min 4 -Max 8) }
            2 { $startX = (Get-Random -Min 45 -Max 55); $startYc = $startY + (Get-Random -Min 5 -Max 10) }
            3 { $startX = (Get-Random -Min 65 -Max 80); $startYc = $startY + (Get-Random -Min 10 -Max 17) }
            4 {
                if ($activeSubs.Count -gt 0) {
                    $rndSub = $activeSubs[(Get-Random -Max $activeSubs.Count)]
                    $startX = $rndSub.X - $mapOffsetX; $startYc = $rndSub.Y
                } else {
                    $startX = 20; $startYc = $startY + 6
                }
            }
        }

        $icbms.Add([PSCustomObject]@{
            X = [double]($mapOffsetX + $startX);
            Y = [double]$startYc;
            TX = $mapOffsetX + (Get-Random -Minimum 5 -Maximum 78);
            TY = $startY + (Get-Random -Minimum 4 -Maximum 24);
            Step = 0.0;
            MaxSteps = (Get-Random -Min 15 -Max 35);
            Trail = [System.Collections.Generic.List[int[]]]::new()
        })
    }

    for ($i = $icbms.Count - 1; $i -ge 0; $i--) {
        $m = $icbms[$i]
        $m.Step++

        $t = $m.Step / $m.MaxSteps
        if ($t -ge 1.0) {
            $explosions.Add([PSCustomObject]@{ X = $m.TX; Y = $m.TY; Life = 6 })
            $impacts++

            foreach ($pos in $m.Trail) {
                $tx = $pos[0]; $ty = $pos[1]
                $mapRow = $ty - $startY
                $mapCol = $tx - $mapOffsetX
                $restoreChar = " "
                $restoreColor = $cLand

                $isSub = $false
                foreach ($sub in $activeSubs) {
                    if ($sub.X -eq $tx -and $sub.Y -eq $ty) { $restoreChar = "▲"; $restoreColor = $cRed; $isSub = $true; break }
                }

                if (-not $isSub -and $mapRow -ge 0 -and $mapRow -lt $worldMap.Count -and $mapCol -ge 0 -and $mapCol -lt $worldMap[$mapRow].Length) {
                    $restoreChar = $worldMap[$mapRow][$mapCol]
                    if ($mapRow -le 2 -or $mapRow -ge 26 -or $mapCol -le 4 -or $mapCol -ge 78) { $restoreColor = $cGrid }
                }
                try { [Console]::SetCursorPosition($tx, $ty); Write-Host "$restoreColor$restoreChar" -NoNewline } catch {}
            }
            $icbms.RemoveAt($i)
            continue
        }

        $curX = $m.X + ($m.TX - $m.X) * $t
        $arcHeight = 8.0
        $curY = $m.Y + ($m.TY - $m.Y) * $t - ($arcHeight * [math]::Sin($t * [math]::PI))

        $iX = [int][math]::Round($curX)
        $iY = [int][math]::Round($curY)

        if ($iY -ge $startY -and $iY -lt ($startY + $worldMap.Count)) {
            try {
                [Console]::SetCursorPosition($iX, $iY)
                Write-Host "$cTrail*" -NoNewline
                $m.Trail.Add([int[]]($iX, $iY))

                if ($m.Trail.Count -gt 1) {
                    $prev = $m.Trail[$m.Trail.Count - 2]
                    [Console]::SetCursorPosition($prev[0], $prev[1])
                    Write-Host "$cGrid." -NoNewline
                }
            } catch {}
        }
    }

    for ($i = $explosions.Count - 1; $i -ge 0; $i--) {
        $exp = $explosions[$i]
        $exp.Life--

        try {
            [Console]::SetCursorPosition([int]$exp.X, [int]$exp.Y)
            if ($exp.Life % 2 -eq 0) { Write-Host "$cWhite*" -NoNewline }
            else { Write-Host "$cYellow*" -NoNewline }
        } catch {}

        if ($exp.Life -le 0) {
            $mapRow = [int]$exp.Y - $startY
            $mapCol = [int]$exp.X - $mapOffsetX
            $restoreChar = " "
            $restoreColor = $cLand

            $isSub = $false
            foreach ($sub in $activeSubs) {
                if ($sub.X -eq [int]$exp.X -and $sub.Y -eq [int]$exp.Y) { $restoreChar = "▲"; $restoreColor = $cRed; $isSub = $true; break }
            }

            if (-not $isSub -and $mapRow -ge 0 -and $mapRow -lt $worldMap.Count -and $mapCol -ge 0 -and $mapCol -lt $worldMap[$mapRow].Length) {
                $restoreChar = $worldMap[$mapRow][$mapCol]
                if ($mapRow -le 2 -or $mapRow -ge 26 -or $mapCol -le 4 -or $mapCol -ge 78) { $restoreColor = $cGrid }
            }
            try { [Console]::SetCursorPosition([int]$exp.X, [int]$exp.Y); Write-Host "$restoreColor$restoreChar" -NoNewline } catch {}
            $explosions.RemoveAt($i)
        }
    }

    Start-Sleep -Milliseconds 40
}

for ($y = 0; $y -lt 35; $y++) {
    try {
        [Console]::SetCursorPosition(0, $startY + $y - 3)
        Write-Host (" " * $width) -NoNewline
    } catch {}
}

[Console]::SetCursorPosition(0, $startY)

Invoke-WoprTyping -text "A STRANGE GAME. THE ONLY WINNING MOVE IS NOT TO PLAY." -baseDelay 110 -pause 1500
Invoke-WoprTyping -text "HOW ABOUT A NICE GAME OF CHESS?" -baseDelay 110 -pause 2500

Write-Host "$ESC[?25h$cReset" -NoNewline
[Console]::SetCursorPosition(0, [Console]::CursorTop + 2)
Write-Diag "Stabilization complete. Memory optimized. Transitioning to HUD..." "STARTUP"
# ==============================================================================

Start-Sleep -Seconds 3

Clear-Host

$dumpRef = $null
while ([DeepVisibilitySensor]::EventQueue.TryDequeue([ref]$dumpRef)) {
}

Write-Diag "Binding Kernel ETW Trace Session..." "INFO"
[DeepVisibilitySensor]::StartSession()
Start-Sleep -Seconds 1

$totalEvents = 0
$totalAlerts = 0
$LastHeartbeat = Get-Date
$eventCount = 0
$SensorBlinded = $false
$LastPolicySync = Get-Date
$LastHeartbeatWrite = Get-Date
$lastLightGC = Get-Date
$lastUebaCleanup = Get-Date
$LastEventReceived = Get-Date

$dashboardDirty = $true
Draw-Dashboard -Events 0 -MlEvals 0 -Alerts 0 -EtwHealth "ONLINE" -MlHealth "Native DLL"
Draw-AlertWindow
Draw-StartupWindow

# ====================== MAIN ORCHESTRATOR LOOP ======================
try {
    try { [console]::TreatControlCAsInput = $true } catch {}
    Write-Diag "    [*] Press 'Ctrl+C' or 'Q' to gracefully terminate the sensor." "STARTUP"

    while ($true) {
        $now = Get-Date
        if ([console]::KeyAvailable) {
            $keyInput = [console]::ReadKey($true)
            if ($keyInput.Key -eq 'Q' -or ($keyInput.Key -eq 'C' -and $keyInput.Modifiers -match 'Control')) {
                Write-Host "`n[!] Graceful shutdown initiated by user..." -ForegroundColor Yellow
                break
            }
            # 'I' for Staging Injection (Hot Reload)
            if ($keyInput.KeyChar -eq 'i' -or $keyInput.KeyChar -eq 'I') {
                Invoke-StagingInjection
            }
            # 'R' for Active Defense Rollback
            if ($keyInput.KeyChar -eq 'r' -or $keyInput.KeyChar -eq 'R') {
                Invoke-DefenseRollback
            }
        }

        if (($now - $LastPolicySync).TotalMinutes -ge 60) {
            $LastPolicySync = $now
            icacls $ScriptDir /reset /T /C /Q *>$null
            # 1. Fetch, Extract, and Compile the heavy startup matrices
            $EngineData = Initialize-SigmaEngine
            # 2. Pass the compiled arrays natively to the C# Engine
            if (-not [string]::IsNullOrEmpty($EngineData.Base64Sigma)) {
                [DeepVisibilitySensor]::UpdateSigmaRules($EngineData.Base64Sigma)
            } else {
                Write-Diag "    [!] Warning: No valid Sigma rules parsed on startup." "STARTUP"
                $EmptyJson = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("[]"))
                [DeepVisibilitySensor]::Initialize($EmptyJson)
            }

            [DeepVisibilitySensor]::UpdateThreatIntel($EngineData.Drivers)
            Protect-SensorEnvironment
            Add-AlertMessage "POLICY SYNC COMPLETE" $cGreen
        }

        $maxDequeue = 500
        $jsonStr = ""

        while (($maxDequeue-- -gt 0) -and [DeepVisibilitySensor]::EventQueue.TryDequeue([ref]$jsonStr)) {
            $LastEventReceived = $now
            $eventCount++
            try {
                if ([string]::IsNullOrWhiteSpace($jsonStr)) { continue }

                # INTERCEPT NATIVE RUST ML ALERTS FROM C# FFI
                if ($jsonStr.StartsWith("[ML_ALERTS]")) {
                    $mlPayload = $jsonStr.Substring(11)
                    $mlResponse = try { $mlPayload | ConvertFrom-Json } catch { $null }

                    if ($mlResponse -and $mlResponse.alerts) {
                        foreach ($alert in $mlResponse.alerts) {
                            if ($alert.reason -eq "HEALTH_OK") { continue }

                            if ($alert.score -eq -2.0) {
                                $ruleName = $alert.reason
                                Add-AlertMessage "GLOBAL SUPPRESSION: '$ruleName' pruned from Kernel." $cDark
                                [DeepVisibilitySensor]::SuppressSigmaRule($ruleName)
                                $logObj = "{$global:EnrichmentPrefix`"Category`":`"UEBA_Audit`", `"Type`":`"RuleDegraded`", `"Details`":`"Rule '$ruleName' triggered across 5+ unique processes.`"}"
                                $script:uebaBatch.Add($logObj)
                                continue
                            }

                            # TEMPORAL UEBA FEEDBACK LOOP
                            if ($alert.score -eq -1.0) {
                                Add-AlertMessage $alert.reason $cDark
                                $logObj = "{$global:EnrichmentPrefix`"Category`":`"UEBA_Audit`", `"Type`":`"SuppressionLearned`", `"Process`":`"$($alert.process)`", `"Details`":`"$($alert.reason)`"}"
                                $script:uebaBatch.Add($logObj)

                                # Extract the pure rule name from the Rust reason
                                # Format: "UEBA SECURED: [T1547.001] RegPersistence | Mode: Automated Baseline."
                                $ruleName = $alert.reason -replace "^UEBA SECURED: ", "" -replace " \| Mode:.*", ""

                                # INJECT INTO C# UNMANAGED MEMORY DICTIONARY
                                try { [DeepVisibilitySensor]::SuppressProcessRule($alert.process, $ruleName) } catch {}
                                continue
                            }

                            if ($alert.score -eq 0.0) {
                                Add-AlertMessage "LEARNING: $($alert.reason)" $cDark
                                $logObj = "{$global:EnrichmentPrefix`"Category`":`"UEBA_Audit`", `"Type`":`"Learning`", `"Process`":`"$($alert.process)`", `"Details`":`"$($alert.reason)`"}"
                                $script:uebaBatch.Add($logObj)
                                continue
                            }

                            if ($alert.severity -match "CRITICAL|HIGH|WARNING") {
                                [DeepVisibilitySensor]::TotalAlertsGenerated++

                                $MitreTag = "Unknown"
                                if ($alert.reason -match "\[(.*?)\]") { $MitreTag = $matches[1] }
                                elseif ($alert.reason -match "^(T\d{4}(?:\.\d{3})?)") { $MitreTag = $matches[1] }

                                $confMap = @{ "CRITICAL" = 100; "HIGH" = 90; "WARNING" = 75 }
                                $conf = if ($confMap.ContainsKey($alert.severity)) { $confMap[$alert.severity] } else { 50 }

                                $targetObj = if (-not [string]::IsNullOrEmpty($alert.destination)) { "$($alert.destination):$($alert.port)" } else { $alert.parent }

                                # Add to Unified Pipeline (handles UI, Defense, and JSON generation automatically)
                                Submit-SensorAlert -Type "ML_Anomaly" `
                                    -TargetObject $targetObj `
                                    -Image $alert.process `
                                    -Flags $alert.reason `
                                    -Confidence $conf `
                                    -PID_Id $alert.pid `
                                    -TID_Id $alert.tid `
                                    -AttckMapping $MitreTag `
                                    -CommandLine $alert.cmd `
                                    -RawJson $jsonStr
                            }
                        }
                    }
                    continue
                }

                # STANDARD C# ETW ALERTS
                $evt = try { $jsonStr | ConvertFrom-Json } catch { $null }
                if ($null -eq $evt) { continue }

                if ($evt.Provider -eq "DiagLog") {
                    # Route engine diagnostics directly to the log file and HUD initialization window
                    Write-Diag $evt.Message "ENGINE"
                    continue
                }
                if ($evt.Provider -eq "HealthCheck") { $LastHeartbeat = $now; continue }
                if ($evt.Provider -eq "Error") { Add-AlertMessage "CORE ENGINE CRASH: $($evt.Message)" $cRed; continue }

                # Catch ALL native C# alerts (Sigma_Match, T1055, StaticAlert)
                if ($evt.Category -and $evt.Category -notmatch "RawEvent|UEBA") {
                    [DeepVisibilitySensor]::TotalAlertsGenerated++

                    $conf = if ($evt.Type -match "SensorTampering|ProcessHollowing|PendingRename|UnbackedModule|EncodedCommand|ThreatIntel_Driver") { 100 } else { 85 }
                    $pidExtract = 0; if ($evt.Process -match "PID:(\d+)") { $pidExtract = [int]$matches[1] } else { $pidExtract = $evt.PID }

                    # Map the Mitre tag if the C# engine provided one in the Category
                    $mitre = if ($evt.Category -match "^T\d{4}") { $evt.Category } else { "N/A" }

                    # Extract the alert text depending on which C# constructor sent it
                    $alertText = if ($evt.Details) { $evt.Details } elseif ($evt.Reason) { $evt.Reason } else { "Suspicious Activity" }

                    Submit-SensorAlert -Type "Static_Detection" `
                        -TargetObject $evt.Type `
                        -Image $evt.Process `
                        -Flags $alertText `
                        -Confidence $conf `
                        -PID_Id $pidExtract `
                        -TID_Id $evt.TID `
                        -AttckMapping $mitre `
                        -RawJson $jsonStr
                }
            } catch {
                Write-Diag "DEQUEUE ERROR: $($_.Exception.Message)" "ERROR"
            }
        }

        # Transfer Deduplicated Alerts into the SIEM Batch Array
        foreach ($alert in $global:cycleAlerts.Values) {
            $global:dataBatch.Add($alert)
        }
        $global:cycleAlerts.Clear()

        # BATCH SIEM FORWARDING (Actionable Alerts & Active Defense)
        if ($global:dataBatch.Count -gt 0) {
            $batchOutput = ($global:dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            [System.IO.File]::AppendAllText($LogPath, $batchOutput + "`r`n")
            $global:dataBatch.Clear()
        }

        # Preserve legacy action logging
        if ($script:logBatch.Count -gt 0) {
            [System.IO.File]::AppendAllText($LogPath, ($script:logBatch -join "`r`n") + "`r`n")
            $script:logBatch.Clear()
        }

        # BATCH UEBA FORWARDING (Learning & Suppressions)
        if ($script:uebaBatch.Count -gt 0) {
            [System.IO.File]::AppendAllText($UebaLogPath, ($script:uebaBatch -join "`r`n") + "`r`n")
            $script:uebaBatch.Clear()
        }

        # === LIGHT MEMORY PROTECTION: GARBAGE COLLECTION (every 60 seconds) ===
        if (($now - $lastLightGC).TotalSeconds -ge 60) {
            [System.GC]::Collect(1, [System.GCCollectionMode]::Optimized)
            $lastLightGC = $now
        }

        # === DEEP MEMORY PROTECTION: GARBAGE COLLECTION (every 30 minutes) ===
        if (($now - $lastUebaCleanup).TotalMinutes -ge 30) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $lastUebaCleanup = $now
            Write-Diag "Deep Memory protection executed. Caches flushed and GC forced." "INFO"
        }

        # ETW HEALTH CANARY & WATCHDOG EVALUATION
        if (($now - $LastHeartbeatWrite).TotalSeconds -ge 60) {
            $LastHeartbeatWrite = $now
            $CanaryPath = Join-Path "C:\ProgramData\DeepSensor\Data" "deepsensor_canary.tmp"
            $null = New-Item -ItemType File -Path $CanaryPath -Force
            Remove-Item -Path $CanaryPath -Force -ErrorAction SilentlyContinue
        }

        $tamperStatus = "Good"

        # 1. Did the background Watchdog flag a buffer exhaustion?
        if ($jsonStr -match "SENSOR_BLINDING_DETECTED") { $tamperStatus = "BAD" }

        # 2. Is the C# session still alive and responding to canaries?
        if (-not [DeepVisibilitySensor]::IsSessionHealthy() -or (($now - $LastHeartbeat).TotalSeconds -gt 120)) { $tamperStatus = "BAD" }

        # 3. Have we been starved of events?
        if (($now - $LastEventReceived).TotalMinutes -gt 3) { $tamperStatus = "BAD" }

        $currentTotalEvents = [DeepVisibilitySensor]::TotalEventsParsed
        $currentTotalAlerts = [DeepVisibilitySensor]::TotalAlertsGenerated

        # Only burn CPU to redraw the HUD if telemetry counts actually incremented or health changed
        if ($dashboardDirty -or $currentTotalEvents -ne $totalEvents -or $currentTotalAlerts -ne $totalAlerts -or $tamperStatus -eq "BAD") {
            $totalEvents = $currentTotalEvents
            $totalAlerts = $currentTotalAlerts

            Draw-Dashboard -Events $totalEvents -MlEvals ([DeepVisibilitySensor]::TotalMlEvals) -Alerts $totalAlerts -EtwHealth $tamperStatus -MlHealth "Native DLL"
            $dashboardDirty = $false
            $eventCount = 0
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
                [DeepVisibilitySensor]::StopSession()

                # OS-LEVEL FAILSAFE: Force terminate the trace via logman to prevent Zombie lockups
                logman stop "NT Kernel Logger" -ets -ErrorAction SilentlyContinue
                logman stop "DeepSensor_UserMode" -ets -ErrorAction SilentlyContinue

                Start-Sleep -Seconds 2

                Write-Diag "Auto-Recovery: Re-initializing native ETW session..." "INFO"
                [DeepVisibilitySensor]::StartSession()

                $LastEventReceived = $now # Reset the starvation timer
                $SensorBlinded = $false
                Add-AlertMessage "SENSOR RECOVERED: ETW SESSION RESTORED" $cGreen
            } catch {
                Write-Diag "Auto-Recovery failed: $($_.Exception.Message). Retrying next cycle." "ERROR"
            }
        }

        Start-Sleep -Milliseconds 250
    }
} catch {
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" -ForegroundColor Red
    "[$((Get-Date).ToString('HH:mm:ss'))] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" | Out-File -FilePath "$env:ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log" -Append
} finally {
    Clear-Host
    Write-Host "`n[*] Initiating Graceful Shutdown..." -ForegroundColor Cyan
    try { [console]::TreatControlCAsInput = $false } catch {}

    # C# now handles the entire synchronized teardown of the DLL and ETW
    Write-Host "    [*] Finalizing Kernel Telemetry & ML Database..." -ForegroundColor Gray
    try {
        [DeepVisibilitySensor]::StopSession()
        [DeepVisibilitySensor]::TeardownEngine()
    } catch {}

    Write-Host "    [*] Unlocking project directory permissions..." -ForegroundColor Gray
    if ($null -ne $ScriptDir) {
        $null = icacls $ScriptDir /reset /T /C /Q
    }

    Write-Host "    [*] Cleaning up centralized library dependencies..." -ForegroundColor Gray

    # Strictly define and guard the Dependencies path
    $DependenciesPath = "C:\ProgramData\DeepSensor\Dependencies"
    if ($null -ne $DependenciesPath -and (Test-Path $DependenciesPath)) {
        Remove-Item -Path $DependenciesPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Strictly define and guard the Staging path
    $StagingPath = "C:\ProgramData\DeepSensor\Staging"
    if ($null -ne $StagingPath -and (Test-Path $StagingPath)) {
        Remove-Item -Path "$StagingPath\*.zip" -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`n[+] Sensor Teardown Complete. Log artifacts preserved in C:\ProgramData\DeepSensor\Logs & \Data." -ForegroundColor Green
}