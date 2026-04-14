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

param (
    [switch]$ArmedMode,
    [switch]$EnableDiagnostics,
    [string]$PolicyUpdateUrl = "",
    [string]$SiemEndpoint = "",
    [string]$SiemToken = "",
    [string]$OfflineRepoPath = "",
    [string]$MlBinaryName = "DeepSensor_ML_v2.1.dll",
    [string]$LogPath = "C:\ProgramData\DeepSensor\Data\DeepSensor_Events.jsonl",
    [string]$TraceEventDllPath = "C:\Temp\TraceEventPackage\lib\net45\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
)

# DEVELOPER NOTE: O(1) Exclusions for Alternate Data Streams (ADS)
$BenignADSProcs = @(
    "coreserviceshell.exe",
    "explorer.exe",
    "msedge.exe",
    "chrome.exe",
    "onedrive.exe"
)

# DEVELOPER NOTE: O(1) Exclusions for Registry Noise
$BenignExplorerValues = @(
    "Zvpebfbsg.Jvaqbjf.Rkcybere",
    "HRZR_PGYFRFFVBA",
    "IdleInWorkingState",
    "WritePermissionsCheck",
    "GlobalUserStartTime"
)

# Environmental Noise Filter
$TrustedProcessExclusions = @(
    "svchost.exe", "wmiprvse.exe", "taskhostw.exe", "dllhost.exe",
    "backgroundtaskhost.exe", "coreserviceshell.exe", "asussystemanalysis.exe",
    "samsungmagician.exe", "msedge.exe", "chrome.exe"
)

logman stop "NT Kernel Logger" -ets >$null 2>&1

# ====================== SIEM ENRICHMENT METADATA ======================
$activeRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($activeRoute) {
    $IpAddress = (Get-NetIPAddress -InterfaceIndex $activeRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}
if (-not $IpAddress) { $IpAddress = "Unknown" }
$OsContext = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption -replace 'Microsoft ', ''
$userStr = "$env:USERDOMAIN\$env:USERNAME".Replace("\", "\\")

$global:EnrichmentPrefix = "`"ComputerName`":`"$env:COMPUTERNAME`", `"IP`":`"$IpAddress`", `"OS`":`"$OsContext`", `"SensorUser`":`"$userStr`", "
# ======================================================================

$global:IsArmed = $ArmedMode
if ($ArmedMode) {
    Write-Host "`n[!] SENSOR BOOTING IN ARMED MODE: ACTIVE DEFENSE ENABLED" -ForegroundColor Red
} else {
    Write-Host "`n[*] SENSOR BOOTING IN AUDIT MODE: OBSERVATION ONLY" -ForegroundColor Yellow
}
$ScriptDir = Split-Path $PSCommandPath -Parent

$script:logBatch = [System.Collections.Generic.List[string]]::new()

# ====================== CONSOLE UI & BUFFER SETUP ======================
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

$ESC = [char]27
$cRed = "$ESC[91;40m"; $cCyan = "$ESC[96;40m"; $cGreen = "$ESC[92;40m"; $cYellow = "$ESC[93;40m"; $cDark = "$ESC[90;40m"; $cReset = "$ESC[0m$ESC[40m"

try {
    $ui = $Host.UI.RawUI
    $buffer = $ui.BufferSize
    $buffer.Width = 160
    $buffer.Height = 3000
    $ui.BufferSize = $buffer
    $size = $ui.WindowSize
    $size.Width = 160
    $size.Height = 45
    $ui.WindowSize = $size
} catch {}

[Console]::SetCursorPosition(0, 9)

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

# ====================== DIAGNOSTICS & TAMPER GUARD ======================
$LogDir = Join-Path $env:ProgramData "DeepSensor\Logs"
$DiagLogPath = Join-Path $LogDir "DeepSensor_Diagnostic.log"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if (Test-Path $DiagLogPath) {
    Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue
}

$global:StartupLogs = [System.Collections.Generic.List[string]]::new()

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

function Protect-SensorEnvironment {
    Write-Diag "[*] Hardening Sensor Ecosystem (DACLs & Registry)..." "STARTUP"

    $DataDir = "C:\ProgramData\DeepSensor\Data"
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }

    $PathsToLock = @($ScriptDir, (Join-Path $ScriptDir $MlBinaryName), (Join-Path $ScriptDir "sigma"))
    foreach ($p in $PathsToLock) {
        if (Test-Path $p) {
            icacls $p /inheritance:d /q | Out-Null
            icacls $p /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q | Out-Null
            icacls $p /grant "BUILTIN\Administrators:(OI)(CI)RX" /q | Out-Null
            icacls $p /deny "BUILTIN\Administrators:(OI)(CI)W" /q | Out-Null
        }
    }

    if (Test-Path $DataDir) {
        $currentUser = "$env:USERDOMAIN\$env:USERNAME"

        icacls $DataDir /inheritance:d /q | Out-Null
        icacls $DataDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q | Out-Null
        icacls $DataDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q | Out-Null
        icacls $DataDir /grant "${currentUser}:(OI)(CI)M" /q

        if ($null -ne $ReadAccessAccounts) {
            foreach ($account in $ReadAccessAccounts) {
                if (-not [string]::IsNullOrWhiteSpace($account)) {
                    icacls $DataDir /grant "${account}:(OI)(CI)RX" /q | Out-Null
                }
            }
        }
        icacls $DataDir /remove "BUILTIN\Users" /q 2>$null
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

# ====================== ENVIRONMENT BOOTSTRAP (RUST NATIVE DLL) ======================
function Initialize-Environment {
    Write-Diag "[*] Executing Environment Pre-Flight Checks..." "STARTUP"
    $MlBinaryPath = Join-Path $ScriptDir $MlBinaryName
    $binaryReady = $false

    if (Test-Path $MlBinaryPath) {
        $binaryReady = $true
        Write-Diag "    [+] Deep Visibility Native Rust DLL validated." "STARTUP"
    } else {
        Write-Diag "    [-] ML DLL absent. Initiating offline deployment..." "STARTUP"
        try {
            if ($OfflineRepoPath) {
                Write-Diag "    [*] Fetching ML DLL from offline repository..." "STARTUP"
                Copy-Item (Join-Path $OfflineRepoPath $MlBinaryName) -Destination $MlBinaryPath -Force
            }
            if (Test-Path $MlBinaryPath) {
                Write-Diag "    [+] ML DLL deployed successfully." "STARTUP"
                $binaryReady = $true
            } else { Write-Diag "    [!] ML DLL deployment failed." "STARTUP" }
        } catch { Write-Diag "    [!] ML DLL acquisition failed: $($_.Exception.Message)" "STARTUP" }
    }

    if (-not $binaryReady) { throw "CRITICAL: Unable to provision the ML engine DLL." }
    return $MlBinaryPath
}

function Initialize-TraceEventDependency {
    param([string]$ExtractBase = "C:\Temp\TraceEventPackage")

    Write-Diag "Validating C# ETW Dependencies..." "STARTUP"
    $ExpectedDllName = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

    $ExistingDll = Get-ChildItem -Path $ExtractBase -Filter $ExpectedDllName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ExistingDll) {
        $DllDir = Split-Path $ExistingDll.FullName -Parent
        $FastSerPath = Join-Path $DllDir "Microsoft.Diagnostics.FastSerialization.dll"
        $YaraPath = Join-Path $DllDir "libyara.NET.dll"

        if ((Test-Path $FastSerPath) -and (Test-Path $YaraPath)) {
            Write-Diag "[+] TraceEvent and Context-Aware YARA libraries validated." "STARTUP"
            return $ExistingDll.FullName
        }
    }

    Write-Diag "[-] TraceEvent library absent. Initiating silent deployment..." "STARTUP"
    try {
        if (Test-Path $ExtractBase) { Remove-Item $ExtractBase -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $ExtractBase -Force | Out-Null

        $TE_Zip = "$env:TEMP\TE.zip"; $UN_Zip = "$env:TEMP\UN.zip"

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

        $YARA_Zip = "$env:TEMP\YARA.zip"
        if ($OfflineRepoPath) {
            Copy-Item (Join-Path $OfflineRepoPath "libyaranet.nupkg") -Destination $YARA_Zip -Force
        } else {
            Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/libyara.NET/3.5.2" -OutFile $YARA_Zip -UseBasicParsing
        }
        Expand-Archive -Path $YARA_Zip -DestinationPath "$ExtractBase\YARA" -Force

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
                if ($h) { Copy-Item -Path $h.FullName -Destination $Amd64Dir -Force }
            }

            $ManagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "libyara.NET.dll" -Recurse | Select-Object -First 1
            $UnmanagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "yara.dll" -Recurse | Where-Object { $_.FullName -match "win-x64" } | Select-Object -First 1

            if ($ManagedYara) { Copy-Item -Path $ManagedYara.FullName -Destination $DllDir -Force }
            if ($UnmanagedYara) { Copy-Item -Path $UnmanagedYara.FullName -Destination $Amd64Dir -Force }

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

# ====================== ACTIVE DEFENSE ENGINE ======================
$global:TotalMitigations = 0

function Invoke-ActiveDefense([string]$ProcName, [int]$PID_Id, [int]$TID_Id, [string]$TargetType, [string]$Reason) {
    if (-not $global:IsArmed -or $ProcName -match "Unknown|System|Idle") { return }

    $yaraMatch = [DeepVisibilitySensor]::NeuterAndDumpPayload($PID_Id, 0, 4096)
    $containmentStatus = "Failed"

    if ($TargetType -eq "Thread" -and $TID_Id -gt 0) {
        $res = [DeepVisibilitySensor]::QuarantineNativeThread($TID_Id, $PID_Id)
        if ($res) {
            $containmentStatus = "Thread ($TID_Id) Quarantined"
            $global:TotalMitigations++
            $audit = "{$global:EnrichmentPrefix`"Category`":`"AuditTrail`", `"Action`":`"QuarantineNativeThread`", `"TargetProcess`":`"$ProcName`", `"PID`":$PID_Id, `"TID`":$TID_Id, `"Reason`":`"$Reason`", `"YaraAttribution`":`"$yaraMatch`"}"
            $script:logBatch.Add($audit)
        }
    }
    else {
        Stop-Process -Id $PID_Id -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Id $PID_Id -ErrorAction SilentlyContinue)) {
            $containmentStatus = "Process ($PID_Id) Terminated"
            $global:TotalMitigations++
            $audit = "{$global:EnrichmentPrefix`"Category`":`"AuditTrail`", `"Action`":`"Stop-Process`", `"TargetProcess`":`"$ProcName`", `"PID`":$PID_Id, `"TID`":$TID_Id, `"Reason`":`"$Reason`", `"YaraAttribution`":`"$yaraMatch`"}"
            $script:logBatch.Add($audit)
        }
    }
    Add-AlertMessage "DEFENSE: $containmentStatus ($ProcName -> $Reason | YARA: $yaraMatch)" "$([char]27)[93;40m"
}

# ====================== HUD DASHBOARD RENDERING ======================
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $ts = (Get-Date).ToString("HH:mm:ss"); $prefix = "[$ts] "
    $maxLen = 98 - $prefix.Length
    if ($Message.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }
    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })
    if ($global:RecentAlerts.Count -gt 7) { $global:RecentAlerts.RemoveAt(0) }
    Draw-AlertWindow
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100
    [Console]::SetCursorPosition(0, 24)

    $logTrunc = if ($LogPath.Length -gt 60) { "..." + $LogPath.Substring($LogPath.Length - 57) } else { $LogPath }
    $headerPlain = "  [ RECENT DETECTIONS ] | Log: $logTrunc"
    $padHeader = " " * [math]::Max(0, ($UIWidth - $headerPlain.Length))

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

    [Console]::SetCursorPosition(0, 32)
    [Console]::SetCursorPosition($curLeft, $curTop)
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

function Draw-Dashboard([long]$Events, [long]$MlEvals, [int]$Alerts, [string]$EtwHealth, [string]$MlHealth) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $evPad       = $Events.ToString().PadRight(9)
    $mlPad       = $MlEvals.ToString().PadRight(9)
    $alertPad    = $Alerts.ToString().PadRight(9)
    $defFiredPad = $global:TotalMitigations.ToString().PadRight(9)
    $tamperPad   = $EtwHealth.PadRight(9)
    $mlHealthPad = $MlHealth.PadRight(9)

    $TitlePlain = "  ⚡ Deep Sensor v2.1 | OS BEHAVIORAL DASHBOARD"
    $StatusStr  = "  [ LIVE TELEMETRY ]"
    $Stats1Str  = "  OS Events Parsed : $evPad | Active Alerts    : $alertPad"
    $Stats2Str  = "  ML Batches Sent  : $mlPad | Defenses Fired   : $defFiredPad"
    $TamperStr  = "  ETW Sensor State : $tamperPad | ML Math Engine   : $mlHealthPad"

    $UIWidth = 100
    $PadTitle  = " " * [math]::Max(0, ($UIWidth - $TitlePlain.Length - 1))
    $PadStatus = " " * [math]::Max(0, ($UIWidth - $StatusStr.Length))
    $PadStats1 = " " * [math]::Max(0, ($UIWidth - $Stats1Str.Length))
    $PadStats2 = " " * [math]::Max(0, ($UIWidth - $Stats2Str.Length))
    $PadTamper = " " * [math]::Max(0, ($UIWidth - $TamperStr.Length))

    $EColor = if ($EtwHealth -eq "Good") { $cGreen } else { $cRed }
    $MColor = if ($MlHealth -match "Native DLL|Good") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed⚡ Deep Sensor v2.1$cReset | OS BEHAVIORAL DASHBOARD$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cDark[ LIVE TELEMETRY ]$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  OS Events Parsed : $cCyan$evPad$cReset | Active Alerts    : $cRed$alertPad$cReset$PadStats1$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Native ML Evals  : $cYellow$mlPad$cReset | Defenses Fired   : $cYellow$defFiredPad$cReset$PadStats2$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ETW Sensor State : $EColor$tamperPad$cReset | ML Math Engine   : $MColor$mlHealthPad$cReset$PadTamper$cCyan║$cReset"
    $ExitPlain = "  [ CTRL+C ] TO EXIT AND INITIATE TEARDOWN SEQUENCE"
    $PadExit   = " " * [math]::Max(0, ($UIWidth - $ExitPlain.Length))
    Write-Host "$cCyan║$cReset$cDark$ExitPlain$cReset$PadExit$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    if ($curTop -lt 9) { $curTop = 9 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

# ====================== YARA RULES ======================
function Sync-YaraIntelligence {
    Write-Diag "Syncing YARA Intelligence (Elastic & ReversingLabs)..." "STARTUP"

    $YaraBaseDir = Join-Path $ScriptDir "yara"
    $VectorDir = if ($OfflineRepoPath) { Join-Path $OfflineRepoPath "yara_rules" } else { Join-Path $ScriptDir "yara_rules" }
    if (-not (Test-Path $YaraBaseDir)) { New-Item -ItemType Directory -Path $YaraBaseDir -Force | Out-Null }

    $Sources = @(
        @{ Name = "ElasticLabs"; Url = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"; SubPath = "protections-artifacts-main/yara" },
        @{ Name = "ReversingLabs"; Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip"; SubPath = "reversinglabs-yara-rules-develop/yara" }
    )

    foreach ($src in $Sources) {
        $TempZip = "$env:TEMP\$($src.Name).zip"
        $TempExt = "$env:TEMP\$($src.Name)_extract"

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
                Write-Diag "    [!] Excluding incompatible/invalid YARA rule: $($rule.Name)" "WARNING"
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

            if ($line -match "(?i)category:\s*(.+)") {
                $rawCat = $matches[1].Trim(" '`"").ToLower()
                if ($rawCat -match "registry") { $category = "registry_event" }
                elseif ($rawCat -match "file") { $category = "file_event" }
                elseif ($rawCat -match "image") { $category = "image_load" }
                else { $category = "process_creation" }
                continue
            }

            if ($line -match "(?i)^tags:") { $inTagsBlock = $true; $inAnchorBlock = $false; continue }
            if ($line -match "(?i)(CommandLine|Query|PipeName|TargetObject|TargetFilename|Details|ScriptBlockText|ImageLoaded|Signature|Image|ParentImage)\|.*?(contains|endswith|startswith).*?:") {
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
        Write-Diag "`n[*] Staging directory ($StagingDir) does not exist. Skipping." "STARTUP"
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

# ====================== SIGMA COMPILER & THREAT INTEL ======================
function Initialize-SigmaEngine {
    Write-Diag "Initializing Sigma Compiler & Threat Intelligence Matrices..." "STARTUP"

    $LocalSigmaDir = Join-Path $ScriptDir "sigma"
    if (-not (Test-Path $LocalSigmaDir)) { New-Item -ItemType Directory -Path $LocalSigmaDir -Force | Out-Null }

    $TempZipPath = "$env:TEMP\sigma_master.zip"
    $ExtractPath = "$env:TEMP\sigma_extract"

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
            "process_creation", "file_event", "registry_event",
            "wmi_event", "pipe_created",
            "ps_module", "ps_script", "ps_classic_start",
            "driver_load", "image_load"
        )

        foreach ($cat in $RuleCategories) {
            $RulesPath = Join-Path $ExtractPath "sigma-master\rules\windows\$cat\*"
            if (Test-Path (Split-Path $RulesPath)) {
                Copy-Item -Path $RulesPath -Destination $LocalSigmaDir -Recurse -Force
            }
        }
        Write-Diag "    [+] Successfully updated local Sigma repository with Advanced Detection vectors." "STARTUP"
    } catch {
        Write-Diag "    [-] GitHub pull failed (Network/Firewall). Proceeding with local cache." "STARTUP"
    } finally {
        if (Test-Path $TempZipPath) { Remove-Item $TempZipPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $SigmaFiles = Get-ChildItem -Path $LocalSigmaDir -Include "*.yml", "*.yaml" -Recurse
    $RuleList = [System.Collections.Generic.List[hashtable]]::new()

    $ParsedCount = 0
    $SkippedCount = 0

    Write-Diag "    [*] Compiling local Sigma rules into JSON Aho-Corasick Matrix..." "STARTUP"

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

            # Extract Category to route to the correct C# Aho-Corasick Tree
            if ($line -match "(?i)category:\s*(.+)") {
                $rawCat = $matches[1].Trim(" '`"").ToLower()
                if ($rawCat -match "registry") { $category = "registry_event" }
                elseif ($rawCat -match "file") { $category = "file_event" }
                elseif ($rawCat -match "image") { $category = "image_load" }
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

    try {
        $jsonString = ""
        if ($OfflineRepoPath) {
            Write-Diag "[*] Loading LOLDrivers Threat Intel from offline repository..." "STARTUP"
            $jsonString = Get-Content (Join-Path $OfflineRepoPath "drivers.json") -Raw
        } else {
            Write-Diag "[*] Fetching live LOLDrivers.io Threat Intel..." "STARTUP"
            $response = Invoke-WebRequest -Uri "https://www.loldrivers.io/api/drivers.json" -UseBasicParsing -ErrorAction Stop
            $jsonString = $response.Content
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

# ====================== SENSOR INITIALIZATION ======================
$ValidMlBinaryPath = Initialize-Environment

$ActualDllPath = Initialize-TraceEventDependency -ExtractBase "C:\Temp\TraceEventPackage"
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
    [DeepVisibilitySensor]::SetLibraryPath($ScriptDir)

    # Initialize the C# Engine with the 5 required core parameters
    [DeepVisibilitySensor]::Initialize(
        $ActualDllPath,
        $PID,
        $CompiledTI.Drivers,
        $BenignExplorerValues,
        $BenignADSProcs
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

    [DeepVisibilitySensor]::IsArmed = $ArmedMode.IsPresent
    [DeepVisibilitySensor]::StartSession()

} catch {
    Write-Diag "CRITICAL: Engine Compilation Failed. Check OsSensor.cs syntax." "ERROR"
    Write-Diag "Error Detail: $($_.Exception.Message)" "ERROR"
    throw $_
}

Protect-SensorEnvironment

# ====================================================================
$totalEvents = 0; $totalAlerts = 0

$LastHeartbeat = Get-Date; $SensorBlinded = $false
$LastPolicySync = Get-Date
$LastHeartbeatWrite = Get-Date

[Console]::SetCursorPosition(0, 9)

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
            # Triggers dynamic reload from sigma_staging/
            if ($keyInput.KeyChar -eq 'i' -or $keyInput.KeyChar -eq 'I') {
                Invoke-StagingInjection
            }
        }

        if (($now - $LastPolicySync).TotalMinutes -ge 60) {
            $LastPolicySync = $now
            icacls $ScriptDir /reset /T /C /Q | Out-Null
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
                                $script:logBatch.Add($logObj)
                                continue
                            }

                            # TEMPORAL UEBA FEEDBACK LOOP
                            if ($alert.score -eq -1.0) {
                                Add-AlertMessage $alert.reason $cDark
                                $logObj = "{$global:EnrichmentPrefix`"Category`":`"UEBA_Audit`", `"Type`":`"SuppressionLearned`", `"Process`":`"$($alert.process)`", `"Details`":`"$($alert.reason)`"}"
                                $script:logBatch.Add($logObj)

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
                                $script:logBatch.Add($logObj)
                                continue
                            }

                            if ($alert.severity -eq "CRITICAL") {
                                [DeepVisibilitySensor]::TotalAlertsGenerated++
                                Add-AlertMessage "CRITICAL THREAT: $($alert.reason)" $cRed
                                Write-Diag "[!] [$($alert.confidence)%] CRITICAL DETECTION: $($alert.reason)" "CRITICAL"
                            } elseif ($alert.severity -eq "HIGH") {
                                [DeepVisibilitySensor]::TotalAlertsGenerated++
                                Add-AlertMessage "HIGH RISK: $($alert.reason)" $cYellow
                            } elseif ($alert.severity -eq "WARNING") {
                                Add-AlertMessage "WARNING: $($alert.reason)" $cDark
                            }

                            if ($alert.severity -match "CRITICAL|HIGH|WARNING") {
                                $MitreTag = "Unknown"
                                # 1. Look for bracketed Sigma/Rust tags (e.g., [T1003.001])
                                if ($alert.reason -match "\[(.*?)\]") {
                                    $MitreTag = $matches[1]
                                }
                                # 2. Fallback: Catch C#-injected categories (e.g., T1562.002: Attempted to...)
                                elseif ($alert.reason -match "^(T\d{4}(?:\.\d{3})?)") {
                                    $MitreTag = $matches[1]
                                }

                                # Generate SIEM-specific context
                                $EventGuid = [guid]::NewGuid().ToString()
                                $TimeLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                                $TimeUTC   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                                $Action    = if ($global:ArmedMode) { "Quarantined" } else { "Logged" }

                                $logObj = "{" +
                                    "`"EventID`":`"$EventGuid`", " +
                                    "`"Timestamp_Local`":`"$TimeLocal`", " +
                                    "`"Timestamp_UTC`":`"$TimeUTC`", " +
                                    "`"Action`":`"$Action`", " +
                                    $global:EnrichmentPrefix +
                                    "`"Category`":`"ValidatedAlert`", " +
                                    "`"Mitre`":`"$MitreTag`", " +
                                    "`"Type`":`"ThreatDetection`", " +
                                    "`"Process`":`"$($alert.process)`", " +
                                    "`"ParentProcess`":`"$($alert.parent)`", " +
                                    "`"CommandLine`":`"$($alert.cmd)`", " +
                                    "`"PID`":$($alert.pid), " +
                                    "`"TID`":$($alert.tid), " +
                                    "`"Score`":$([math]::Round($alert.score, 2)), " +
                                    "`"Severity`":`"$($alert.severity)`", " +
                                    "`"Details`":`"$($alert.reason)`"}"

                                $script:logBatch.Add($logObj)
                            }

                            if ($ArmedMode -and $alert.severity -eq "CRITICAL") {
                                Invoke-ActiveDefense -ProcName $alert.process -PID_Id $alert.pid -TID_Id $alert.tid -TargetType "Process" -Reason $alert.reason
                                Invoke-HostIsolation -Reason $alert.reason -TriggeringProcess $alert.process
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

                if ($evt.Category -eq "StaticAlert") {
                    [DeepVisibilitySensor]::TotalAlertsGenerated++
                    $enrichedJson = $jsonStr.Replace("{`"Category`"", "{$global:EnrichmentPrefix`"Category`"")
                    $script:logBatch.Add($enrichedJson)

                    if ($evt.Type -match "SensorTampering|ProcessHollowing|PendingRename|UnbackedModule|EncodedCommand|ThreatIntel_Driver") {
                        Add-AlertMessage "CRITICAL: $($evt.Type) ($($evt.Process))" $cRed
                        Invoke-ActiveDefense -ProcName $evt.Process -PID_Id $evt.PID -TID_Id $evt.TID -TargetType "Process" -Reason "Critical Execution/Injection/Persistence"
                    } else {
                        Add-AlertMessage "$($evt.Type): $($evt.Details)" $cYellow
                    }
                }
                } catch {
                Write-Diag "DEQUEUE ERROR: $($_.Exception.Message)" "ERROR"
            }
        }

        # BATCH SIEM FORWARDING
        if ($script:logBatch.Count -gt 0) {
            [System.IO.File]::AppendAllText($LogPath, ($script:logBatch -join "`r`n") + "`r`n")
            $script:logBatch.Clear()
        }

        # ETW HEALTH CANARY: Write a temp file every 60 seconds to prove the Kernel Listener is alive
        if (($now - $LastHeartbeatWrite).TotalSeconds -ge 60) {
            $LastHeartbeatWrite = $now
            $CanaryPath = Join-Path $env:TEMP "deepsensor_canary.tmp"
            $null = New-Item -ItemType File -Path $CanaryPath -Force
            Remove-Item -Path $CanaryPath -Force -ErrorAction SilentlyContinue
        }

        # DRAW HUD WITH C# STATIC COUNTERS
        $eState = if (($now - $LastHeartbeat).TotalSeconds -le 180) { "Good" } else { "BAD" }
        $totalParsed = [DeepVisibilitySensor]::TotalEventsParsed
        $totalAlerts = [DeepVisibilitySensor]::TotalAlertsGenerated
        $totalMlEvals = [DeepVisibilitySensor]::TotalMlEvals

        Draw-Dashboard -Events $totalParsed -MlEvals $totalMlEvals -Alerts $totalAlerts -EtwHealth $eState -MlHealth "Native DLL"

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
    try { [DeepVisibilitySensor]::StopSession() } catch {}

    Write-Host "    [*] Unlocking project directory permissions..." -ForegroundColor Gray
    $null = icacls $ScriptDir /reset /T /C /Q

    Write-Host "    [*] Cleaning up temporary library artifacts..." -ForegroundColor Gray
    $TempLibPath = "C:\Temp\TraceEventPackage"
    if (Test-Path $TempLibPath) {
        Remove-Item -Path $TempLibPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    $StrayNetStandard = "C:\Temp\netstandard.dll"
    if (Test-Path $StrayNetStandard) {
        Remove-Item -Path $StrayNetStandard -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`n[+] Sensor Teardown Complete. Log artifacts preserved in C:\ProgramData\DeepSensor\Logs & \Data." -ForegroundColor Green
}