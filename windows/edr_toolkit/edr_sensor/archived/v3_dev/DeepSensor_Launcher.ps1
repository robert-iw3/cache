<#
.SYNOPSIS
    Deep Sensor - OS Behavioral Orchestrator & Active Defense HUD

.DESCRIPTION
    The central nervous system of the Deep Visibility EDR toolkit. This script is
    responsible for bootstrapping the environment, bridging the unmanaged C# ETW
    engine with the Python ML daemon, and rendering the mathematically pinned
    diagnostic HUD.

    It operates completely independently of network-based C2 tracking, focusing
    strictly on deep operating system hooks and persistence mechanisms.
    Additionally, it acts as a dynamic Threat Intelligence compiler, natively parsing
    and executing Sigma rules and BYOVD driver lists directly within the kernel event loop.

.ARCHITECTURE_FLOW
    1. Environment Pre-Flight: Validates the local Python installation and ML dependencies,
       silently downloading and provisioning the environment if absent on the host.
    2. Threat Intel Compiler: Recursively parses the local 'sigma/' directory, auto-corrects
       YAML syntax, and fetches live BYOVD (LOLDrivers) intelligence to build O(1) arrays.
    3. Dynamic Compilation: Embeds the DeepVisibilitySensor.cs payload directly
       into the PowerShell RAM space, linking the TraceEvent libraries on the fly.
    4. Matrix Initialization: Maps critical PIDs (Sensor) and injects the compiled
       Sigma and Threat Intel arrays directly into the unmanaged C# memory space.
    5. IPC Pipeline: Spawns the OsAnomalyML.py daemon (Behavioral + UEBA engine). The Python
       daemon maintains a persistent SQLite database (DeepSensor_UEBA.db) in the Temp directory,
       utilizing WAL mode for lock-free baselining.
    6. Security Lockdown: Utilizes icacls and sdset to restrict file and service access,
       locking down the Sigma arrays, script paths, and service configurations from Admin tampering.
    7. Telemetry Triage: Continuously drains the C# ConcurrentQueue. Static, high-
       fidelity alerts (e.g., Sigma matches) are actioned instantly.
       Raw telemetry is batched and flushed to the Python engine.
    8. Active Defense: If ArmedMode is enabled, native SuspendThread / Quarantine (Surgical) and memory
       neutralization (PAGE_NOACCESS) are issued the millisecond an exploit chain is verified.
    9. Log Rotation & SIEM API: Routes JSONL telemetry locally or forwards directly
       to Azure/Splunk HEC endpoints via API.

.PARAMETERS
    ArmedMode           - Enables autonomous surgical thread suspension (Quarantine),
                          memory permission stripping, and forensic payload extraction
                          for critical alerts.
    PolicyUpdateUrl    - URL to fetch centralized Sigma rules during policy sync.
    SiemEndpoint       - REST API endpoint for Splunk HEC or Azure Log Analytics.
    SiemToken          - Authorization token for the SIEM endpoint.
    PythonPath         - Absolute or relative path to the Python 3.x interpreter.
    MLScriptPath       - Path to the OsAnomalyML.py behavioral engine.
    LogPath            - Destination for the rolling JSONL SIEM forwarder cache.
    TraceEventDllPath  - Path to the Microsoft.Diagnostics.Tracing.TraceEvent.dll.

.NOTES
    - Requires Administrator privileges to access kernel-level ETW providers.
    - Designed for maximum stealth and performance; runs entirely in-memory with no
      on-disk footprint beyond the optional log file and the UEBA SQLite database.
    - The UEBA database (DeepSensor_UEBA.db) is routed to the host Temp directory to
      intentionally bypass the strict 'Deny Write' DACLs applied to the sensor's
      core environment.
    - The HUD is rendered using ANSI escape codes for cross-platform compatibility
      and minimal resource usage.

    Author: Robert Weber

    Unlock project directory if cleanup was not initiated:

    icacls "Path:\To\Project\Files" /reset /T /C /Q
#>
#Requires -RunAsAdministrator

param (
    [switch]$ArmedMode,
    [switch]$EnableDiagnostics,
    [string]$PolicyUpdateUrl = "",
    [string]$SiemEndpoint = "",
    [string]$SiemToken = "",
    [string]$OfflineRepoPath = "", # Example: "\\SERVER\Share\DeepSensor_AirGap_Staging"
    [string]$PythonPath = "python",
    [string]$MLScriptPath = "OsAnomalyML.py",
    [string]$RequirementsPath = "requirements.txt",
    [string]$LogPath = "C:\ProgramData\DeepSensor\Data\DeepSensor_Events.jsonl",
    # Configurable array of accounts granted Read/Execute access to the data directory
    #[string[]]$ReadAccessAccounts = @("CORP\svc_splunk_fwd", "BUILTIN\EventLogReaders"),
    [string]$TraceEventDllPath = "C:\Temp\TraceEventPackage\lib\net45\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
)

# DEVELOPER NOTE: O(1) Exclusions for Alternate Data Streams (ADS)
    # These processes legitimately create hidden streams during normal operation.
    $BenignADSProcs = @(
        "coreserviceshell.exe", # Trend Micro AMSP Core Service
        "explorer.exe",         # Windows Explorer (File copies/downloads)
        "msedge.exe",           # Edge browser SmartScreen data
        "chrome.exe",           # Chrome browser downloads
        "onedrive.exe"          # OneDrive cloud sync streams
    )

    # DEVELOPER NOTE: O(1) Exclusions for Registry Noise
    # Filters out Microsoft's internal ROT13 telemetry and standard system state checks.
    $BenignExplorerValues = @(
        "Zvpebfbsg.Jvaqbjf.Rkcybere", # ROT13 for Microsoft.Windows.Explorer
        "HRZR_PGYFRFFVBA",            # ROT13 for USER_SESSION
        "IdleInWorkingState",         # Background system state
        "WritePermissionsCheck",      # Routine folder access checks
        "GlobalUserStartTime"         # Standard session initialization
    )

# Environmental Noise Filter
# Processes in this list will have their ML severity downgraded to prevent accidental isolation.
$TrustedProcessExclusions = @(
    "svchost.exe", "wmiprvse.exe", "taskhostw.exe", "dllhost.exe",
    "backgroundtaskhost.exe", "coreserviceshell.exe", "asussystemanalysis.exe",
    "samsungmagician.exe", "msedge.exe", "chrome.exe"
)

# DEVELOPER NOTE: Safeguard to prevent re-compilation errors in the same session.
if ($null -ne ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -match "DeepVisibilitySensor" })) {
    Write-Host "[!] CRITICAL: DeepVisibilitySensor type is already loaded in this session." -ForegroundColor Red
    Write-Host "[!] You MUST close and reopen PowerShell to apply code changes." -ForegroundColor Yellow
    Exit
}

# DEVELOPER NOTE: Force-clear the standard NT Kernel Logger (silent)
logman stop "NT Kernel Logger" -ets >$null 2>&1

# ====================== SIEM ENRICHMENT METADATA ======================
$IpAddress = (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 1).IPAddress
if (-not $IpAddress) { $IpAddress = "Unknown" }
$OsContext = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption -replace 'Microsoft ', ''
$userStr = "$env:USERDOMAIN\$env:USERNAME".Replace("\", "\\") # Escape backslash for JSON

$global:EnrichmentPrefix = "`"ComputerName`":`"$env:COMPUTERNAME`", `"IP`":`"$IpAddress`", `"OS`":`"$OsContext`", `"SensorUser`":`"$userStr`", "
# ======================================================================

$global:IsArmed = $ArmedMode
if ($ArmedMode) {
    Write-Host "`n[!] SENSOR BOOTING IN ARMED MODE: ACTIVE DEFENSE ENABLED" -ForegroundColor Red
} else {
    Write-Host "`n[*] SENSOR BOOTING IN AUDIT MODE: OBSERVATION ONLY" -ForegroundColor Yellow
}
$ScriptDir = Split-Path $PSCommandPath -Parent
$FullReqPath = Join-Path $ScriptDir $RequirementsPath
$FullMLPath = Join-Path $ScriptDir $MLScriptPath

# Declare LogBatch globally so ActiveDefense can append Audit Trails
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

# ====================== DIAGNOSTICS & TAMPER GUARD ======================
# DEVELOPER NOTE: All diagnostic/crash logging is now centralized under ProgramData
# for consistency with UEBA DB, quarantine folder, and security best practices.

$LogDir = Join-Path $env:ProgramData "DeepSensor\Logs"
$DiagLogPath = Join-Path $LogDir "DeepSensor_Diagnostic.log"

# Ensure the Logs directory exists (created early so Write-Diag works from the very first call)
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if (Test-Path $DiagLogPath) {
    Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue
}

$global:StartupLogs = [System.Collections.Generic.List[string]]::new()

function Write-Diag([string]$Message, [string]$Level = "INFO") {
    # DEVELOPER NOTE: Always log to file during startup phase to ensure troubleshooting is possible.
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try {
        # Defensive directory check (in case something deleted it mid-run)
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

# Posture & WMI Hijacking
function Invoke-EnvironmentalAudit {
    Write-Diag "    [*] Initializing Environmental Audit..." "STARTUP"
    Write-Diag "        [*] Executing Proactive Posture & WMI Sweep..." "STARTUP"

    # 1. LSASS PPL Protection Check
    $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if (-not $lsa -or $lsa.RunAsPPL -ne 1) {
        Write-Diag "[POSTURE] Vulnerability: LSASS is not running as a Protected Process Light (PPL)." "AUDIT"
    }

    # 2. Exposed RDP Check
    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
        Write-Diag "[POSTURE] Vulnerability: RDP is currently enabled and exposed." "AUDIT"
    }

    # 3. WMI Repository Auditing (Epic 9)
    # Attackers drop fileless payloads into CommandLineEventConsumers
    try {
        $consumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction Stop
        foreach ($c in $consumers) {
            if ($c.CommandLineTemplate -match "powershell|cmd|wscript|cscript") {
                Write-Diag "[THREAT HUNT] Suspicious WMI Event Consumer Found: $($c.Name) -> $($c.CommandLineTemplate)" "CRITICAL"
            }
        }
    } catch {
        # WMI namespace might be corrupted or inaccessible
    }
}

# Sever the host from the network when the ML daemon reports a critical threat
function Invoke-HostIsolation {
    param([string]$Reason, [string]$TriggeringProcess)

    if (-not $ArmedMode) {
        Write-Diag "[AUDIT MODE] Host Isolation bypassed for: $Reason ($TriggeringProcess)" "CRITICAL"
        return
    }

    Write-Host "`n[!] CRITICAL THREAT DETECTED: INITIATING HOST ISOLATION" -ForegroundColor Red
    Write-Host "    Reason: $Reason ($TriggeringProcess)" -ForegroundColor Yellow

    try {
        # Drop all inbound/outbound traffic across all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop

        # Poke a single hole for your SIEM / Orchestrator API (Change IP as needed)
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

    $PathsToLock = @($ScriptDir, $FullMLPath, (Join-Path $ScriptDir "sigma"))
    foreach ($p in $PathsToLock) {
        if (Test-Path $p) {
            icacls $p /inheritance:d /q | Out-Null
            icacls $p /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q | Out-Null
            icacls $p /grant "BUILTIN\Administrators:(OI)(CI)RX" /q | Out-Null
            icacls $p /deny "BUILTIN\Administrators:(OI)(CI)W" /q | Out-Null
        }
    }

    # SECURE DATA DIRECTORY (Grant Admin Full Control, Remove Standard Users)
    if (Test-Path $DataDir) {
        $currentUser = "$env:USERDOMAIN\$env:USERNAME"

        icacls $DataDir /inheritance:d /q | Out-Null
        icacls $DataDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q | Out-Null
        icacls $DataDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q | Out-Null

        # Grant the launching user Read & Execute access
        icacls $DataDir /grant "${currentUser}:(OI)(CI)M" /q

        # Apply Read & Execute access to the configured array of accounts
        foreach ($account in $ReadAccessAccounts) {
            if (-not [string]::IsNullOrWhiteSpace($account)) {
                icacls $DataDir /grant "${account}:(OI)(CI)RX" /q | Out-Null
            }
        }

        icacls $DataDir /remove "BUILTIN\Users" /q 2>$null
    }

    Write-Diag "    [+] Discretionary Access Control Lists (DACLs) locked down." "STARTUP"

    $ServiceName = "DeepSensor"
    $serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($serviceExists) {
        $secureSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        $null = & sc.exe sdset $ServiceName $secureSddl
        Write-Diag "    [+] Windows Service configuration secured." "STARTUP"
    }
}

# ====================== ENVIRONMENT BOOTSTRAP ======================
function Initialize-Environment {
    Write-Diag "[*]Executing Environment Pre-Flight Checks..." "STARTUP"
    $pythonCmd = $PythonPath
    $pythonInstalled = $false

    try {
        $null = & $pythonCmd --version 2>&1
        $pythonInstalled = $true
        Write-Diag "    [+] Python interpreter validated." "STARTUP"
    } catch {
        Write-Diag "    [-] Python absent. Initiating silent deployment..." "STARTUP"
        $InstallerPath = "$env:TEMP\python-installer.exe"

        if ($OfflineRepoPath) {
            Write-Diag "    [*] Fetching Python installer from offline repository..." "STARTUP"
            Copy-Item (Join-Path $OfflineRepoPath "python-3.11.8-amd64.exe") -Destination $InstallerPath -Force
        } else {
            $InstallerUrl = "https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe"
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
        }

        $InstallProcess = Start-Process -FilePath $InstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru

        if ($InstallProcess.ExitCode -eq 0) {
            Write-Diag "    [+] Python deployed successfully." "STARTUP"
            $pythonInstalled = $true
            $pythonCmd = "$env:ProgramFiles\Python311\python.exe"

            foreach ($level in "Machine", "User") {
                [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
                    Set-Item -Path "Env:\$($_.Name)" -Value $_.Value -ErrorAction SilentlyContinue
                }
            }
        } else {
            Write-Diag "    [!] Python deployment failed (Exit Code: $($InstallProcess.ExitCode))." "STARTUP"
        }
        if (Test-Path $InstallerPath) { Remove-Item $InstallerPath -Force }
    }

    if ($pythonInstalled) {
        Write-Diag "    [*] Validating ML dependencies..." "STARTUP"

        if ($OfflineRepoPath) {
            Write-Diag "    [*] Installing ML dependencies from offline wheels..." "STARTUP"
            $WheelDir = Join-Path $OfflineRepoPath "wheels"
            & $pythonCmd -m pip install --no-index --find-links="$WheelDir" scikit-learn numpy joblib scipy --quiet
        } else {
            & $pythonCmd -m pip install --upgrade pip --quiet
            if (Test-Path $FullReqPath) {
                & $pythonCmd -m pip install -r $FullReqPath --quiet
            } else {
                & $pythonCmd -m pip install scikit-learn numpy joblib scipy --quiet
            }
        }
        Write-Diag "    [+] ML dependencies verified." "STARTUP"
    }

    return $pythonCmd
}

function Initialize-TraceEventDependency {
    param([string]$ExtractBase = "C:\Temp\TraceEventPackage")

    Write-Diag "Validating C# ETW Dependencies..." "STARTUP"
    $ExpectedDllName = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

    $ExistingDll = Get-ChildItem -Path $ExtractBase -Filter $ExpectedDllName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ExistingDll) {
        # DEVELOPER NOTE: Ensure all helper dependencies (including YARA) exist alongside TraceEvent
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

        # DEVELOPER NOTE: FastSerialization is actually bundled INSIDE the TraceEvent
        # package. We only need to independently download the Unsafe dependency.
        $TE_Zip = "$env:TEMP\TE.zip"; $UN_Zip = "$env:TEMP\UN.zip"

        if ($OfflineRepoPath) {
            Write-Diag "    [*] Fetching TraceEvent libraries from offline repository..." "STARTUP"
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

        # DEVELOPER NOTE: Extract libyara.NET into the temp folder
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

            # 1. Move the managed .NET helper (Unsafe) directly next to TraceEvent
            $UnsafeDll = Get-ChildItem -Path "$ExtractBase\UN" -Filter "System.Runtime.CompilerServices.Unsafe.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "net45|netstandard|net46" } | Select-Object -First 1
            if ($UnsafeDll) { Copy-Item -Path $UnsafeDll.FullName -Destination $DllDir -Force }

            # 2. DEVELOPER NOTE: TraceEvent explicitly expects its native C++ dependencies
            # to be inside an architecture-specific subfolder ('amd64'). We must create
            # this folder and place the unmanaged binaries inside it.
            $Amd64Dir = Join-Path $DllDir "amd64"
            if (-not (Test-Path $Amd64Dir)) { New-Item -ItemType Directory -Path $Amd64Dir -Force | Out-Null }

            $NativeHelpers = @(
                (Get-ChildItem -Path "$ExtractBase\TE" -Filter "KernelTraceControl.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1),
                (Get-ChildItem -Path "$ExtractBase\TE" -Filter "msdia140.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1)
            )

            foreach ($h in $NativeHelpers) {
                if ($h) { Copy-Item -Path $h.FullName -Destination $Amd64Dir -Force }
            }

            # 3. YARA Dependencies (MOVED HERE AFTER $DllDir AND $Amd64Dir ARE DEFINED)
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

# ====================== Initialize RING-0 Driver ======================
function Initialize-JitDriverCompilation {
    $DriverName = "EndpointMonitor"
    $SysPath = Join-Path $ScriptDir "endpoint_monitor_driver.sys"
    $RustSrcDir = Join-Path $ScriptDir "DriverSrc"

    # =========================================================================
    # VBS / HVCI (MEMORY INTEGRITY) CHECK
    # =========================================================================
    $hvciReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue

    if ($hvciReg -and $hvciReg.Enabled -eq 1) {
        Write-Diag "[!] HVCI (Memory Integrity) is ENABLED on this endpoint." "STARTUP"
        Write-Diag "    [-] Cannot JIT-compile or load self-signed kernel drivers." "STARTUP"
        Write-Diag "    [-] ACTION: You must sign the driver with an EV cert and submit it to Microsoft WHCP." "STARTUP"
        Write-Diag "    [-] REFERENCE: Use the provided 'sign_kernel_driver.ps1' utility." "STARTUP"
        Write-Diag "    [*] Falling back to Ring-3 (User-Mode) monitoring only..." "STARTUP"
        return # Aborts JIT, allows C# Engine to boot
    }
    # =========================================================================

    # If the driver is already compiled, skip the heavy build process
    if (Test-Path $SysPath) {
        Write-Diag "[*] Compiled driver found. Skipping JIT compilation." "STARTUP"
        Boot-KernelDriver -SysPath $SysPath -DriverName $DriverName
        return
    }

    Write-Diag "[!] No compiled driver found. Initiating JIT Ring-0 Compilation..." "STARTUP"

    # 1. Download/Install Dependencies if not offline
    $RustInstaller = Join-Path $ScriptDir "rustup-init.exe"
    $VSBuildTools = Join-Path $ScriptDir "vs_buildtools.exe"
    $WDKSetup = Join-Path $ScriptDir "wdksetup.exe"

    if (-not (Test-Path $RustInstaller)) {
        Write-Diag "    [*] Downloading Toolchains via WAN..." "STARTUP"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $RustInstaller
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile $VSBuildTools
        Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2262365" -OutFile $WDKSetup
    }

    # 2. Install MSVC Build Tools & WDK (Silent)
    Write-Diag "    [*] Installing MSVC C++ Build Tools & WDK (This may take 15+ minutes)..." "STARTUP"
    Start-Process -FilePath $VSBuildTools -ArgumentList "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools" -Wait
    Start-Process -FilePath $WDKSetup -ArgumentList "/q /norestart" -Wait

    # 3. Install Rust
    Write-Diag "    [*] Installing Rust Toolchain..." "STARTUP"
    Start-Process -FilePath $RustInstaller -ArgumentList "-y --default-host x86_64-pc-windows-msvc --profile minimal" -Wait
    $env:Path += ";$env:USERPROFILE\.cargo\bin"

    # 4. Compile the Driver
    Write-Diag "    [*] Executing Cargo Build for Ring-0 Driver..." "STARTUP"
    Push-Location $RustSrcDir

    # We must run Cargo directly
    $CargoExe = "$env:USERPROFILE\.cargo\bin\cargo.exe"
    $BuildArgs = "build", "--release", "--features=registry,threads,objects,network"

    $BuildProc = Start-Process -FilePath $CargoExe -ArgumentList $BuildArgs -Wait -PassThru -NoNewWindow

    if ($BuildProc.ExitCode -eq 0) {
        Write-Diag "    [+] Rust compilation successful." "STARTUP"
        # Move the compiled driver out of the target folder
        $CompiledSys = Join-Path $RustSrcDir "target\release\endpoint_monitor_driver.sys"
        Copy-Item -Path $CompiledSys -Destination $SysPath -Force
    } else {
        Write-Diag "    [-] Rust compilation failed. Check toolchain dependencies." "STARTUP"
    }
    Pop-Location

    # 5. Rust Cleanup (Nuke it from orbit)
    Write-Diag "    [*] Wiping Rust compiler footprint from endpoint..." "STARTUP"
    Start-Process -FilePath "rustup" -ArgumentList "self uninstall -y" -Wait
    if (Test-Path $RustSrcDir) { Remove-Item -Path $RustSrcDir -Recurse -Force -ErrorAction SilentlyContinue }

    # 6. Boot the Driver
    if (Test-Path $SysPath) {
        Boot-KernelDriver -SysPath $SysPath -DriverName $DriverName
    }
}

function Boot-KernelDriver([string]$SysPath, [string]$DriverName) {
    Write-Diag "    [*] Registering and Booting Minifilter..." "STARTUP"

    # Stop existing
    if (Get-Service -Name $DriverName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $DriverName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $DriverName | Out-Null
        Start-Sleep -Seconds 1
    }

    # Register
    & sc.exe create $DriverName type= filesys binPath= "$SysPath" | Out-Null

    # Altitude Registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
    if (Test-Path $regPath) {
        New-Item -Path "$regPath\Instances" -Force | Out-Null
        New-ItemProperty -Path "$regPath\Instances" -Name "DefaultInstance" -Value "Endpoint Monitor Instance" -PropertyType String -Force | Out-Null

        $instPath = "$regPath\Instances\Endpoint Monitor Instance"
        New-Item -Path $instPath -Force | Out-Null
        New-ItemProperty -Path $instPath -Name "Altitude" -Value "320000" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $instPath -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null
    }

    # Boot & Connect IPC
    & sc.exe start $DriverName | Out-Null
    $running = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($running.Status -eq 'Running') {
        Write-Diag "    [+] Ring-0 Driver loaded successfully." "STARTUP"
        [DeepVisibilitySensor]::StartRustDriverIpc()
    } else {
        Write-Diag "    [!] Driver failed to start. (Is TestSigning ON?)" "STARTUP"
    }
}

# ====================== ACTIVE DEFENSE ENGINE ======================
$global:TotalMitigations = 0

function Invoke-ActiveDefense([string]$ProcName, [int]$PID_Id, [int]$TID_Id, [string]$TargetType, [string]$Reason, [double]$Score) {
    if (-not $global:IsArmed -or $ProcName -match "Unknown|System|Idle") { return }

    $mitigationStatus = "Failed"
    $yaraMatch = "None"

    # --- 1. Ring-0 Containment & Forensic Extraction (High-Confidence Threats) ---
    if ($Score -ge 8.5 -or $TargetType -eq "ZeroTolerance") {
        Write-Diag "[*] High-Confidence Threat Detected: $ProcName (PID: $PID_Id)" "TRIAGE"

        # Route the PID to the Rust Minifilter to immediately block all File I/O
        [DeepVisibilitySensor]::QuarantinePidInKernel($PID_Id)

        # Capture YARA attribution directly for the audit trail
        # Note: Address 0 is used for behavioral hits where specific allocation data is missing.
        $yaraMatch = [DeepVisibilitySensor]::NeuterAndDumpPayload($PID_Id, 0, 4096)

        Write-Diag "[+] Ring-0 Containment & Extraction complete. Attribution: $yaraMatch" "TRIAGE"
    }

    # --- 2. Ring-3 Execution Containment ---
    if ($TargetType -eq "Thread" -and $TID_Id -gt 0) {
        # Suspend the specific malicious native thread
        $res = [DeepVisibilitySensor]::QuarantineNativeThread($PID_Id, $TID_Id)

        if ($res) {
            $mitigationStatus = "Thread ($TID_Id) Quarantined"
            $global:TotalMitigations++

            # Surgical Containment Audit Trail
            $audit = "{$global:EnrichmentPrefix`"Category`":`"AuditTrail`", `"Action`":`"QuarantineNativeThread`", `"TargetProcess`":`"$ProcName`", `"PID`":$PID_Id, `"TID`":$TID_Id, `"Reason`":`"$Reason`", `"YaraAttribution`":`"$yaraMatch`"}"
            $script:logBatch.Add($audit)
        }
    }
    else {
        # Fallback: Process-level termination
        Stop-Process -Id $PID_Id -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Id $PID_Id -ErrorAction SilentlyContinue)) {
            $mitigationStatus = "Process ($PID_Id) Terminated"
            $global:TotalMitigations++

            # Process Containment Audit Trail
            $audit = "{$global:EnrichmentPrefix`"Category`":`"AuditTrail`", `"Action`":`"Stop-Process`", `"TargetProcess`":`"$ProcName`", `"PID`":$PID_Id, `"TID`":$TID_Id, `"Reason`":`"$Reason`", `"YaraAttribution`":`"$yaraMatch`"}"
            $script:logBatch.Add($audit)
        }
    }

    Add-AlertMessage "DEFENSE: $mitigationStatus ($ProcName -> $Reason | YARA: $yaraMatch)" "$([char]27)[93;40m"
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
    $UIWidth = 100 # Match Dashboard logic
    [Console]::SetCursorPosition(0, 24) # Shifted down to line 24

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
            # Truncate long lines to prevent wrapping
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

function Draw-Dashboard([int]$Events, [int]$MlSent, [int]$Alerts, [string]$EtwHealth, [string]$MlHealth) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $evPad       = $Events.ToString().PadRight(9)
    $mlPad       = $MlSent.ToString().PadRight(9)
    $alertPad    = $Alerts.ToString().PadRight(9)
    $defFiredPad = $global:TotalMitigations.ToString().PadRight(9)
    $tamperPad   = $EtwHealth.PadRight(9)
    $mlHealthPad = $MlHealth.PadRight(9)

    $TitlePlain = "  ⚡ DEEP SENSOR V2 | OS BEHAVIORAL DASHBOARD"
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
    $MColor = if ($MlHealth -eq "Good") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed⚡ DEEP SENSOR V2$cReset | OS BEHAVIORAL DASHBOARD$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cDark[ LIVE TELEMETRY ]$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  OS Events Parsed : $cCyan$evPad$cReset | Active Alerts    : $cRed$alertPad$cReset$PadStats1$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ML Batches Sent  : $cYellow$mlPad$cReset | Defenses Fired   : $cYellow$defFiredPad$cReset$PadStats2$cCyan║$cReset"
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
                # Attempt to pull from offline staging if available
                $OfflineZip = Join-Path $OfflineRepoPath "$($src.Name).zip"
                if (Test-Path $OfflineZip) { Copy-Item $OfflineZip -Destination $TempZip -Force }
            } else {
                Write-Diag "    [*] Downloading $($src.Name) ruleset..." "STARTUP"
                Invoke-WebRequest -Uri $src.Url -OutFile $TempZip -UseBasicParsing -ErrorAction Stop
            }

            if (Test-Path $TempZip) {
                Expand-Archive -Path $TempZip -DestinationPath $TempExt -Force
                $SourceRules = Join-Path $TempExt $src.SubPath

                # Mirror the rules into the local 'yara/' landing zone
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

    # CONTEXT-AWARE SORTING: Move rules from yara/ into the vector subfolders
    # DEVELOPER NOTE: Using [System.IO.File] instead of Get-Content for 10x speed
    # increase when processing thousands of rules.
    $LocalRules = Get-ChildItem -Path $YaraBaseDir -Filter "*.yar" -Recurse
    Write-Diag "    [*] Sorting $($LocalRules.Count) rules into context-aware vectors..." "STARTUP"

    # Pre-create all vector directories to avoid repeated I/O checks in the loop
    $Vectors = @("WebInfrastructure", "SystemExploits", "LotL", "MacroPayloads", "BinaryProxy", "SystemPersistence", "InfostealerTargets", "RemoteAdmin", "DevOpsSupplyChain", "Core_C2")
    foreach ($v in $Vectors) {
        $vPath = Join-Path $VectorDir $v
        if (-not (Test-Path $vPath)) { New-Item -ItemType Directory -Path $vPath -Force | Out-Null }
    }

    # Sorting Logic inside Sync-YaraIntelligence for Windows Artifacts
    foreach ($rule in $LocalRules) {
        try {
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
        catch {
            # Skip corrupted or locked files rather than halting the orchestrator
            continue
        }
    }
    Write-Diag "    [+] YARA Intelligence sorted and ready for compilation." "STARTUP"
}

# ====================== SIGMA COMPILER & THREAT INTEL ======================
function Initialize-SigmaEngine {
    Write-Diag "Initializing Sigma Compiler & Threat Intelligence Matrices..." "STARTUP"

    $LocalSigmaDir = Join-Path $ScriptDir "sigma"
    if (-not (Test-Path $LocalSigmaDir)) { New-Item -ItemType Directory -Path $LocalSigmaDir -Force | Out-Null }

    # --- NEW: LIVE SIGMAHQ REPOSITORY PULL ---
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

    # --- THE GATEKEEPER PARSER ---
    $SigmaFiles = Get-ChildItem -Path $LocalSigmaDir -Include "*.yml", "*.yaml" -Recurse

    $SigmaCmdKeys = [System.Collections.Generic.List[string]]::new()
    $SigmaCmdTitles = [System.Collections.Generic.List[string]]::new()
    $SigmaImgKeys = [System.Collections.Generic.List[string]]::new()
    $SigmaImgTitles = [System.Collections.Generic.List[string]]::new()

    $ParsedCount = 0
    $SkippedCount = 0

    Write-Diag "    [*] Compiling local Sigma rules into Aho-Corasick arrays..." "STARTUP"

    foreach ($file in $SigmaFiles) {
        $lines = Get-Content $file.FullName
        $content = $lines -join "`n"

        # GATEKEEPER 1: Platform Validation
        if ($content -notmatch "product:\s*windows") { $SkippedCount++; continue }

        # NOISE FILTER: Skip the two extremely noisy Sigma rules
        if ($content -match "XBAP Execution From Uncommon Locations" -or
            $content -match "Suspicious Double Extension File Execution" -or
            $content -match "PresentationHost\.EXE") {
            $SkippedCount++; continue
        }

        # GATEKEEPER 2: Modifier Sanitization (Allow |all modifiers, drop hashes)
        if ($content -match "sha256:" -or $content -match "md5:") { $SkippedCount++; continue }

        $title = "Unknown Sigma Rule"
        $ruleTags = @()
        $inCmdBlock = $false
        $inImgBlock = $false
        $inTagsBlock = $false

        # Fast Line-by-Line State Machine Parser
        foreach ($line in $lines) {
            # Extract Rule Title
            if ($line -match "(?i)^title:\s*(.+)") { $title = $matches[1].Trim(" '`""); continue }

            # Detect Array Starts
            if ($line -match "(?i)^tags:") { $inTagsBlock = $true; $inCmdBlock = $false; $inImgBlock = $false; continue }

            # Capture chained modifiers (like |contains|all:) and new telemetry fields
            if ($line -match "(?i)(CommandLine|Query|PipeName|TargetObject|Details|ScriptBlockText|ImageLoaded|Signature)\|.*?contains.*?:") {
                $inCmdBlock = $true; $inImgBlock = $false; $inTagsBlock = $false; continue
            }
            if ($line -match "(?i)(Image|ImageLoaded)\|.*?endswith.*?:") {
                $inImgBlock = $true; $inCmdBlock = $false; $inTagsBlock = $false; continue
            }

            # Extract Tags
            if ($inTagsBlock) {
                if ($line -match "^\s*-\s*(.+)") {
                    $val = $matches[1].Trim(" '`"")
                    if (-not [string]::IsNullOrWhiteSpace($val)) { $ruleTags += $val }
                } elseif ($line -match "^[a-zA-Z]") {
                    $inTagsBlock = $false
                }
            }

            # Reset state for Cmd/Img if a new root key begins
            if (-not $inTagsBlock -and $line -match "^[a-zA-Z]") { $inCmdBlock = $false; $inImgBlock = $false }

            # Extract Array Values & Append Tags to Title
            if ($inCmdBlock -and $line -match "^\s*-\s*(.+)") {
                $val = $matches[1].Trim(" '`"")

                if (-not [string]::IsNullOrWhiteSpace($val) -and
                    $val.Length -gt 3 -and
                    $val -notmatch "(?i)^\.exe$" -and
                    $val -notmatch "(?i)^[a-z]:\\\\?$") {

                    $SigmaCmdKeys.Add($val)
                    $formattedTitle = if ($ruleTags.Count -gt 0) { "$title [$($ruleTags -join ', ')]" } else { $title }
                    $SigmaCmdTitles.Add($formattedTitle)
                }
            }

            if ($inImgBlock -and $line -match "^\s*-\s*(.+)") {
                $val = $matches[1].Trim(" '`"")
                if (-not [string]::IsNullOrWhiteSpace($val)) {
                    $SigmaImgKeys.Add($val)
                    $formattedTitle = if ($ruleTags.Count -gt 0) { "$title [$($ruleTags -join ', ')]" } else { $title }
                    $SigmaImgTitles.Add($formattedTitle)
                }
            }
        }

        $ParsedCount++
    }

    # Inject Built-in core signatures
    $BuiltInCmds = @("sekurlsa::logonpasswords", "lsadump::", "privilege::debug", "Invoke-BloodHound", "procdump -ma lsass", "vssadmin delete shadows")
    foreach ($c in $BuiltInCmds) {
        $SigmaCmdKeys.Add($c); $SigmaCmdTitles.Add("Built-in Core TI Signature")
    }

    Write-Diag "    [+] Gatekeeper Compilation Complete: $ParsedCount rules armed ($SkippedCount incompatible rules safely bypassed)." "STARTUP"

    # Inject Built-in core signatures
    $BuiltInCmds = @("sekurlsa::logonpasswords", "lsadump::", "privilege::debug", "Invoke-BloodHound", "procdump -ma lsass", "vssadmin delete shadows")
    foreach ($c in $BuiltInCmds) {
        $SigmaCmdKeys.Add($c); $SigmaCmdTitles.Add("Built-in Core TI Signature")
    }

    # --- LOLDRIVERS THREAT INTEL ---
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

    return @{
        CmdKeys = $SigmaCmdKeys.ToArray(); CmdTitles = $SigmaCmdTitles.ToArray()
        ImgKeys = $SigmaImgKeys.ToArray(); ImgTitles = $SigmaImgTitles.ToArray()
        Drivers = [string[]]($TiDriverSignatures | Select-Object)
    }
}

# ====================== SENSOR INITIALIZATION ======================
$ValidPythonPath = Initialize-Environment

# Dynamically fetch and locate the DLL, updating the path for Add-Type
$ActualDllPath = Initialize-TraceEventDependency -ExtractBase "C:\Temp\TraceEventPackage"
if (-not $ActualDllPath) {
    Write-Host "`n[!] CRITICAL: TraceEvent dependency missing. Cannot start ETW sensor. Exiting." -ForegroundColor Red
    Exit
}
$TraceEventDllPath = $ActualDllPath # Overwrite the hardcoded parameter with the actual dynamic path
Write-Diag "    [+] Environment Bootstrap Complete." "STARTUP"

Invoke-EnvironmentalAudit

$CompiledTI = Initialize-SigmaEngine

Write-Diag "Initializing Core Engine..." "STARTUP"


# 1. Instantiate Python ML Daemon via IPC Pipes
$pyInfo = New-Object System.Diagnostics.ProcessStartInfo
$pyInfo.FileName = $ValidPythonPath
$pyInfo.Arguments = "-u `"$FullMLPath`""
$pyInfo.RedirectStandardInput = $true
$pyInfo.RedirectStandardOutput = $true
$pyInfo.RedirectStandardError = $true
$pyInfo.UseShellExecute = $false
$pyInfo.CreateNoWindow = $true

$pyProcess = [System.Diagnostics.Process]::Start($pyInfo)
$pyIn = $pyProcess.StandardInput
$pyOut = $pyProcess.StandardOutput
$pyErr = $pyProcess.StandardError

# === IPC AUTHENTICATION BEACON ===
$pyIn.WriteLine("AUTH:" + $pyProcess.Id)
Write-Diag "    [+] Sent IPC authentication beacon to Python" "STARTUP"

# === IPC CONFIGURATION BEACON ===
$configPayload = @{ trusted_binaries = $TrustedProcessExclusions } | ConvertTo-Json -Compress
$pyIn.WriteLine("CONFIG:$configPayload")
Write-Diag "    [+] Sent dynamic noise filter configuration to Python" "STARTUP"

$pyIn.Flush()

# 2. Wait for the Python PID with a strict 5-second timeout (Prevents infinite lockup)
$pyPid = $null
$handshakeTimeout = 50
while ($null -eq $pyPid -and $handshakeTimeout-- -gt 0) {
    if (-not $pyErr.EndOfStream) {
        $errLine = $pyErr.ReadLine()
        if ($errLine -match "\[PYTHON_PID\] (\d+)") {
            $pyPid = $matches[1]
            Write-Diag "    [+] ML Daemon active on PID: $pyPid" "STARTUP"
        }
    }
    Start-Sleep -Milliseconds 100
}

if ($null -eq $pyPid) {
    throw "CRITICAL: ML Daemon Handshake Timeout. Python did not return a PID."
}

# 2. Compile C# Sensor into RAM
try {
    # DEVELOPER NOTE: The CLR Fusion Loader aggressively JITs background threads.
    # We must preemptively load the main TraceEvent DLL AND all of its sibling
    # helper DLLs (like FastSerialization) into the Global AppDomain so the compiler
    # never has to guess where they are.
    $DllDir = Split-Path $ActualDllPath -Parent

    # DEVELOPER NOTE: We must explicitly exclude the unmanaged C++ native binaries
    # (including native YARA) from the references to prevent the CS0009 crash.
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

    # Append all discovered helper DLLs directly to the compiler references
    $RefAssemblies += $SiblingDlls.FullName

    Add-Type -TypeDefinition (Get-Content (Join-Path $ScriptDir "OsSensor.cs") -Raw) -ReferencedAssemblies $RefAssemblies -ErrorAction Stop

    # Inject PIDs, Drivers, and the full Sigma Compiled Arrays into unmanaged memory
    Write-Diag "    [*] Bootstrapping unmanaged memory structures..." "STARTUP"
    [DeepVisibilitySensor]::Initialize(
        $ActualDllPath,
        $PID, $CompiledTI.Drivers,
        $CompiledTI.CmdKeys, $CompiledTI.CmdTitles,
        $CompiledTI.ImgKeys, $CompiledTI.ImgTitles,
        $BenignExplorerValues, $BenignADSProcs
    )

    # 1. Sync and Compile YARA
    Sync-YaraIntelligence
    # Initialize the Context-Aware YARA matrices
    $YaraRulesPath = if ($OfflineRepoPath) { Join-Path $OfflineRepoPath "yara_rules" } else { Join-Path $ScriptDir "yara_rules" }
    [DeepVisibilitySensor]::InitializeYaraMatrices($YaraRulesPath)

    # 2. Compile and Boot the Kernel Driver (Handles SC creation and IPC bridge)
    Initialize-JitDriverCompilation

    # Arm the C# Engine if the user passed the flag
    [DeepVisibilitySensor]::IsArmed = $ArmedMode.IsPresent
    # 3. Start the ETW Session
    [DeepVisibilitySensor]::StartSession()

} catch {
    Write-Diag "CRITICAL: Engine Compilation Failed. Check OsSensor.cs syntax." "ERROR"
    Write-Diag "Error Detail: $($_.Exception.Message)" "ERROR"
    throw $_
}

# DACL Hardening LAST so it doesn't block the compilation phase above
Protect-SensorEnvironment

# ====================================================================
$totalEvents = 0; $mlSent = 0; $totalAlerts = 0
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()

$LastHeartbeat = Get-Date; $SensorBlinded = $false
$LastMlHealthPing = (Get-Date).AddSeconds(-115); $LastMlHeartbeat = Get-Date; $MlBlinded = $false
$LastPolicySync = Get-Date

[Console]::SetCursorPosition(0, 9)

# ====================== MAIN ORCHESTRATOR LOOP ======================
try {
    # Prevent OS from broadcasting the kill signal to Python
    try { [console]::TreatControlCAsInput = $true } catch {}
    Write-Diag "    [*] Press 'Ctrl+C' or 'Q' to gracefully terminate the sensor." "STARTUP"
    while ($true) {
        $now = Get-Date
        # Catch the keypress to trigger a graceful teardown
        if ([console]::KeyAvailable) {
            $key = [console]::ReadKey($true)
            if ($key.Key -eq 'Q' -or ($key.Key -eq 'C' -and $key.Modifiers -match 'Control')) {
                Write-Host "`n[!] Graceful shutdown initiated by user. Flushing memory..." -ForegroundColor Yellow
                break # Breaks the loop and naturally flows into the Phase 3 Teardown block
            }
        }

        # --- CENTRALIZED POLICY SYNC ---
        if (($now - $LastPolicySync).TotalMinutes -ge 60) {
            $LastPolicySync = $now

            # DEVELOPER NOTE: Temporarily lift the DACL lockdown so the engine can
            # extract the new YAML files to the sigma/ directory without crashing.
            icacls $ScriptDir /reset /T /C /Q | Out-Null

            $NewTI = Initialize-SigmaEngine
            [DeepVisibilitySensor]::UpdateThreatIntel($NewTI.Drivers, $NewTI.CmdKeys, $NewTI.CmdTitles, $NewTI.ImgKeys, $NewTI.ImgTitles)

            # Re-apply the anti-tamper lockdown immediately after writing
            Protect-SensorEnvironment

            Add-AlertMessage "POLICY SYNC COMPLETE" $cGreen
        }

        # ETW Sensor Health Canary
        if (($now - $LastHeartbeat).TotalSeconds -ge 60) {
        try {
                New-Item "C:\Temp\deepsensor_canary.tmp" -ItemType File -Force -ErrorAction Stop | Out-Null
                Write-Diag "    [+] Canary .tmp created for ETW heartbeat" "DEBUG"
            } catch {
                Write-Diag "    [!] Canary creation failed: $($_.Exception.Message)" "WARN"
            }
        }

        # --- ETW EVENT TRIAGE ---
        $maxDequeue = 1000
        $jsonStr = ""

        # DEVELOPER NOTE: Added a 1000-event governor to prevent UI thread starvation during bursts.
        while (($maxDequeue-- -gt 0) -and [DeepVisibilitySensor]::EventQueue.TryDequeue([ref]$jsonStr)) {
            if ([string]::IsNullOrWhiteSpace($jsonStr)) { continue }

            $evt = try { $jsonStr | ConvertFrom-Json } catch { $null }
            if ($null -eq $evt) { continue }

            if ($evt.Provider -eq "HealthCheck") {
                $LastHeartbeat = $now
                if ($SensorBlinded) { $SensorBlinded = $false; Add-AlertMessage "SENSOR RECOVERED" $cGreen }
                continue
            }

            # [CWE-391] (PowerShell Error Suppression)
            # [NEW LOGIC: Unmask C# Engine Errors]
            if ($evt.Provider -eq "Error") {
                # Surface unmanaged crashes to the UI immediately
                Add-AlertMessage "CORE ENGINE CRASH: $($evt.Message)" $cRed

                # Log the stack trace to your diagnostic file so you can actually debug it
                "[$((Get-Date).ToString('HH:mm:ss'))] CRITICAL FAULT: $($evt.Message)" | Out-File -FilePath "$env:ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log" -Append

                continue
            }

            if ($evt.Provider -eq "DiagLog") { continue }

            if ($evt.Category -eq "StaticAlert") {
                # FAST PATH: High-Fidelity / Zero-Tolerance Kernel Alerts (Bypasses UEBA)
                if ($evt.Type -match "SensorTampering|ProcessHollowing|PendingRename|UnbackedModule|EncodedCommand") {
                    $totalAlerts++

                    # Inject host data into the raw JSON string from C#
                    $enrichedJson = $jsonStr.Replace("{`"Category`"", "{$global:EnrichmentPrefix`"Category`"")
                    $script:logBatch.Add($enrichedJson)

                    Add-AlertMessage "CRITICAL: $($evt.Type) ($($evt.Process))" $cRed

                    Invoke-ActiveDefense -ProcName $evt.Process -PID_Id $evt.PID -TID_Id $evt.TID -TargetType "Process" -Reason "Critical Execution/Injection/Persistence"
                }
                # SLOW PATH: Noise-Prone Alerts (Sigma/Threat Intel) routed to UEBA ML Daemon
                else {
                    $dataBatch.Add($evt)
                }
            }
            elseif ($evt.Category -eq "RawEvent") {
                $totalEvents++
                $dataBatch.Add($evt)
            }
        }

        # --- IPC HANDOFF TO ML ENGINE ---
        if (($now - $LastMlHealthPing).TotalSeconds -ge 120) {
            $LastMlHealthPing = $now
            $dataBatch.Add([PSCustomObject]@{ Type = "Synthetic_Health_Check" })
        }

        if ($dataBatch.Count -gt 0) {
            $mlSent++

            # 1. Backpressure Awareness
            $currentPressure = [DeepVisibilitySensor]::EventQueue.Count

            # 2. Burst-Throttled Payload
            $payload = @{
                events   = $dataBatch
                pressure = $currentPressure
            } | ConvertTo-Json -Compress -Depth 10

            $pyIn.WriteLine($payload); $pyIn.Flush()

            # 3. STRICT 1-TO-1 IPC READ
            $timeout = 500
            while ($timeout-- -gt 0 -and -not $pyProcess.HasExited) {

                # Wait for the single consolidated JSON line from Python
                $line = $pyOut.ReadLine()

                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    $pyResponse = try { $line | ConvertFrom-Json } catch { $null }
                    if ($null -eq $pyResponse) { continue }

                    if ($pyResponse.daemon_error) {
                        Add-AlertMessage "ML ERROR: $($pyResponse.daemon_error)" $cRed; break
                    }

                    foreach ($alert in $pyResponse.alerts) {
                        # A. HEARTBEAT SYNCHRONIZATION
                        if ($alert.reason -eq "HEALTH_OK") {
                            $LastMlHeartbeat = [datetime]::UtcNow
                            if ($MlBlinded) { $MlBlinded = $false; Add-AlertMessage "ML ENGINE RECOVERED" $cGreen }
                            continue
                        }

                        # B. GLOBAL RULE PRUNING
                        if ($alert.score -eq -2.0) {
                            $ruleName = $alert.reason
                            Add-AlertMessage "GLOBAL SUPPRESSION: '$ruleName' pruned from Kernel." $cDark
                            [DeepVisibilitySensor]::SuppressSigmaRule($ruleName)
                            $logObj = "{$global:EnrichmentPrefix`"Category`":`"UEBA_Audit`", `"Type`":`"RuleDegraded`", `"Details`":`"Rule '$ruleName' triggered across 5+ unique processes.`"}"
                            $script:logBatch.Add($logObj)
                            continue
                        }

                        # C. UEBA MILESTONE
                        if ($alert.score -eq -1.0) {
                            Add-AlertMessage $alert.reason $cDark
                            $logObj = "{$global:EnrichmentPrefix`"Category`":`"UEBA_Audit`", `"Type`":`"SuppressionLearned`", `"Process`":`"$($alert.process)`", `"Details`":`"$($alert.reason)`"}"
                            $script:logBatch.Add($logObj)
                            continue
                        }

                        # D. LEARNING STATE
                        if ($alert.score -eq 0.0) {
                            Add-AlertMessage "LEARNING: $($alert.reason)" $cDark
                            continue
                        }

                        # E. SEVERITY-AWARE TRIAGE
                        if ($alert.severity -eq "CRITICAL") {
                            $totalAlerts++; Add-AlertMessage "CRITICAL THREAT: $($alert.reason)" $cRed
                            Write-Diag "[!] [$($alert.confidence)%] CRITICAL DETECTION: $($alert.reason)" "CRITICAL"
                        } elseif ($alert.severity -eq "HIGH") {
                            $totalAlerts++; Add-AlertMessage "HIGH RISK: $($alert.reason)" $cYellow
                        } elseif ($alert.severity -eq "WARNING") {
                            Add-AlertMessage "WARNING: $($alert.reason)" $cDark
                        } else { continue }

                        # F. SIEM LOGGING
                        $logObj = "{$global:EnrichmentPrefix`"Category`":`"ValidatedAlert`", `"Type`":`"ThreatDetection`", `"Process`":`"$($alert.process)`", `"PID`":$($alert.pid), `"TID`":$($alert.tid), `"Score`":$($alert.score), `"Severity`":`"$($alert.severity)`", `"Confidence`":$($alert.confidence), `"Details`":`"$($alert.reason)`"}"
                        $script:logBatch.Add($logObj)

                        # G. THE ARMED MODE GATEKEEPER
                        if ($ArmedMode -and $alert.severity -eq "CRITICAL") {

                            # 1. Trigger the wrapper function for forensics & thread quarantine
                            Invoke-ActiveDefense -ProcName $alert.process -PID_Id $alert.pid -TID_Id $alert.tid -TargetType "Process" -Reason $alert.reason

                            # 2. Trigger Network Isolation
                            Invoke-HostIsolation -Reason $alert.reason -TriggeringProcess $alert.process
                        }
                    }
                    break
                }
                Start-Sleep -Milliseconds 10
            }
            $dataBatch.Clear()
        }

        # --- SIEM API FORWARDING & LOG ROTATION ---
        if ($script:logBatch.Count -gt 0) {
            if ($SiemEndpoint) {
                try {
                    $siemPayload = '{"events": [' + ($script:logBatch -join ",") + ']}'
                    Invoke-RestMethod -Uri $SiemEndpoint -Method Post -Headers @{"Authorization"="Splunk $SiemToken"} -Body $siemPayload -ContentType "application/json" -ErrorAction SilentlyContinue | Out-Null
                } catch { }
            }

            if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 50MB) {
                Rename-Item -Path $LogPath -NewName ($LogPath.Replace(".jsonl", "_$(Get-Date -f 'yyyyMMdd_HHmm').jsonl"))
            }
            [System.IO.File]::AppendAllText($LogPath, ($script:logBatch -join "`r`n") + "`r`n")
            $script:logBatch.Clear()
        }

        # --- HEALTH WATCHDOGS ---
        $eState = if (($now - $LastHeartbeat).TotalSeconds -le 180) { "Good" } else { "BAD" }
        $mState = if (($now - $LastMlHeartbeat).TotalSeconds -le 300) { "Good" } else { "BAD" }

        Draw-Dashboard -Events $totalEvents -MlSent $mlSent -Alerts $totalAlerts -EtwHealth $eState -MlHealth $mState

        if ($eState -eq "BAD" -and -not $SensorBlinded) { $SensorBlinded = $true; Add-AlertMessage "CRITICAL: SENSOR BLINDED" $cRed }
        if ($mState -eq "BAD" -and -not $MlBlinded) { $MlBlinded = $true; Add-AlertMessage "CRITICAL: ML ENGINE FROZEN" $cRed }

        # --- NATIVE UI UNLOCKER ---
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'C' -and $key.Modifiers -match 'Control') {
                Write-Host "`n[!] Manual CTRL+C Interrupt Detected. Initiating teardown..." -ForegroundColor Yellow
                break
            }
        }

        Start-Sleep -Milliseconds 500
    }
} catch {
    # If the main Orchestrator thread crashes, log it before tearing down
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" -ForegroundColor Red
    "[$((Get-Date).ToString('HH:mm:ss'))] ORCHESTRATOR FATAL CRASH: $($_.Exception.Message)" | Out-File -FilePath "$env:ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log" -Append
} finally {
    Clear-Host
    Write-Host "`n[*] Initiating Graceful Shutdown..." -ForegroundColor Cyan
    try { [console]::TreatControlCAsInput = $false } catch {}

    # 1. Stop ETW Session and flush internal C# caches
    #
    try { [DeepVisibilitySensor]::StopSession() } catch {}

    # 2. Terminate Python Daemon Gracefully
    if ($pyProcess -and -not $pyProcess.HasExited) {
        Write-Host "    [*] Sending QUIT signal to ML Daemon..." -ForegroundColor Gray
        $pyProcess.StandardInput.WriteLine("QUIT")
        $pyIn.Flush()
        # Give Python enough time to commit the SQLite database to disk
        Start-Sleep -Milliseconds 1200

        if (-not $pyProcess.HasExited) {
            Stop-Process -Id $pyProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }

    # 3. Restore Project Directory Permissions (Unlock iacls)
    # DEVELOPER NOTE: Resets inheritance and removes the 'Deny' ACEs applied to the toolkit folder.
    Write-Host "    [*] Unlocking project directory permissions..." -ForegroundColor Gray
    $null = icacls $ScriptDir /reset /T /C /Q

    # 4. Clean up temporary libraries but preserve logs
    # DEVELOPER NOTE: Removes the TraceEvent NuGet artifacts from C:\Temp while sparing
    # the .jsonl events and .log diagnostic files.
    Write-Host "    [*] Cleaning up temporary library artifacts..." -ForegroundColor Gray
    $TempLibPath = "C:\Temp\TraceEventPackage"
    if (Test-Path $TempLibPath) {
        Remove-Item -Path $TempLibPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # DEVELOPER NOTE: Remove stray reference DLLs (like netstandard) that the CLR
    # or Add-Type compiler occasionally leaks into the root Temp directory during JIT.
    $StrayNetStandard = "C:\Temp\netstandard.dll"
    if (Test-Path $StrayNetStandard) {
        Remove-Item -Path $StrayNetStandard -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`n[+] Sensor Teardown Complete. Log artifacts preserved in C:\Temp." -ForegroundColor Green
}