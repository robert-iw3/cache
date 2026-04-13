<#
.SYNOPSIS
    PowerShell EDR Toolkit - Fileless & Evasion Hunting
.DESCRIPTION
    Full-spectrum hunt for hidden processes, fileless persistence (WMI, Registry, Tasks, BITS, COM),
    injection, BYOVD, ETW/AMSI tampering, PendingFileRenameOperations, ADS, timestomping, and more.
    Exports structured findings (CSV + styled HTML + JSON) with MITRE ATT&CK mappings.
    Includes -QuickMode (ultra-fast scan) and optional -AutoUpdateDrivers (live pull from loldrivers.io).
    Multi-threaded file hunts with smart exclusions and hashtable caching.
.PARAMETER ScanProcesses
    Hidden processes, unusual parents, suspicious command lines, LOLBins.
.PARAMETER ScanFileless
    Classic WMI + Run keys.
.PARAMETER ScanTasks
    Suspicious Scheduled Tasks.
.PARAMETER ScanDrivers
    Loaded drivers + known vulnerable (BYOVD).
.PARAMETER ScanInjection
    Reflective DLLs, foreign modules, process hollowing indicators.
.PARAMETER ScanADS
    NTFS Alternate Data Streams.
.PARAMETER ScanRegistry
    Expanded registry persistence (IFEO, AppInit_DLLs, Services).
.PARAMETER ScanETWAMSI
    ETW Autologger + AMSI tampering.
.PARAMETER ScanPendingRename
    PendingFileRenameOperations (MoveEDR-style EDR kill).
.PARAMETER ScanBITS
    BITS jobs (modern fileless persistence).
.PARAMETER ScanCOM
    COM hijacking (CLSID InProcServer32).
.PARAMETER TargetDirectory
    Directory for file-based hunts (entropy, cloaking, ADS, timestomping).
.PARAMETER Recursive
    Recursive file scan.
.PARAMETER QuickMode
    Ultra-fast scan: smaller entropy sample + skips large-file checks.
.PARAMETER AutoUpdateDrivers
    Fetch the latest vulnerable driver list from loldrivers.io API.
.PARAMETER ReportPath
    Output directory (default: current working directory).
.PARAMETER ExcludePaths
    Array of specific folder paths to skip during file enumeration.
.PARAMETER SeverityFilter
    Only report findings matching these severities (Critical, High, Medium, Low).
.PARAMETER OutputFormat
    Specific report formats to generate (All, CSV, JSON, HTML).
.PARAMETER Quiet
    Suppress all console output except for critical errors and the final summary.
.PARAMETER TestMode
    Injects dummy findings to validate SIEM ingestion and reporting pipelines.
.NOTES
    Author: Robert Weber
.EXAMPLE

    Usage:

    .\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode -AutoUpdateDrivers

    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Path\To\EDR_Toolkit.ps1" -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode -AutoUpdateDrivers

    Cancelling:

    # Immediate memory cleanup
    $filesToScan = $null
    $queue = $null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Write-Host "Memory cleanup completed." -ForegroundColor Green
#>

[CmdletBinding()]
param (
    [Switch]$ScanProcesses,
    [Switch]$ScanFileless,
    [Switch]$ScanTasks,
    [Switch]$ScanDrivers,
    [Switch]$ScanInjection,
    [Switch]$ScanADS,
    [Switch]$ScanRegistry,
    [Switch]$ScanETWAMSI,
    [Switch]$ScanPendingRename,
    [Switch]$ScanBITS,
    [Switch]$ScanCOM,
    [String]$TargetDirectory,
    [Switch]$Recursive,
    [Switch]$QuickMode,
    [Switch]$AutoUpdateDrivers,
    [String]$ReportPath = $PWD.Path,
    [String[]]$ExcludePaths = @(),
    [ValidateSet('Critical','High','Medium','Low')]
    [String[]]$SeverityFilter = @('Critical','High','Medium','Low'),
    [ValidateSet('All','CSV','JSON','HTML')]
    [String[]]$OutputFormat = @('All'),
    [Switch]$Quiet,
    [Switch]$TestMode
)

$script:Findings = @()

$Global:MITRE = @{
    HiddenProcess    = "T1014 (Rootkit)"
    EncodedCommand   = "T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)"
    HighEntropy      = "T1027 (Obfuscated Files or Information)"
    FileCloaking     = "T1014 (Rootkit), T1564 (Hide Artifacts)"
    WMIPersistence   = "T1546.003 (WMI Event Subscription)"
    RegPersistence   = "T1547.001 (Registry Run Keys)"
    ScheduledTask    = "T1053 (Scheduled Task/Job)"
    BYOVD            = "T1562.001 (Impair Defenses) + T1542"
    ProcessInjection = "T1055 (Process Injection)"
    ADS              = "T1564.004 (Hide Artifacts: NTFS ADS)"
    COMHijack        = "T1546.015 (Event Triggered Execution: COM Hijacking)"
    ETWTampering     = "T1562.002 (Disable Windows Event Logging)"
    AMSITampering    = "T1562.001 (Impair Defenses)"
    PendingRename    = "T1562.001 (MoveEDR)"
    Timestomping     = "T1070.006 (Indicator Removal: Timestomping)"
    ServiceTamper    = "T1543.003 (Windows Service)"
    BITSJob          = "T1197 (BITS Jobs)"
    RegIFEO          = "T1546.012 (Image File Execution Options)"
    AppInitDLL       = "T1546.010 (AppInit DLLs)"
}

function Write-Console {
    param([string]$Message, [string]$Color = "Gray")
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function Add-Finding {
    param([string]$Type, [string]$Target, [string]$Details, [string]$Severity, [string]$Mitre)

    if ($Severity -notin $SeverityFilter) { return }

    $obj = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Severity  = $Severity
        Type      = $Type
        Target    = $Target
        Details   = $Details
        MITRE     = $Mitre
    }
    $script:Findings += $obj

    if (-not $Quiet) {
        $color = if ($Severity -eq "Critical") { "Red" } elseif ($Severity -eq "High") { "DarkRed" } elseif ($Severity -eq "Medium") { "Yellow" } else { "Cyan" }
        Write-Host "[!] $Severity Finding: $Type | Target: $Target" -ForegroundColor $color
    }
}

# =============================================================================
# 1. Process & Memory / Injection Hunting
# =============================================================================
function Invoke-ProcessHunt {
    Write-Console "[*] Hunting for Hidden & Suspicious Processes..." "Cyan"

    $apiProcs = Get-Process -ErrorAction SilentlyContinue
    $apiDict = @{}
    foreach ($p in $apiProcs) { $apiDict[$p.Id] = $p }

    $wmiProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

    # Expanded whitelist for modern Windows + common vendor processes
    $coreAllowed = @(
        "System Idle Process", "System", "Secure System", "Registry", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "Memory Compression",
        "LsaIso.exe", "NgcIso.exe", "fontdrvhost.exe", "WUDFHost.exe", "dwm.exe", "sihost.exe",
        "taskhostw.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "SearchIndexer.exe",
        "spoolsv.exe", "svchost.exe", "conhost.exe", "ctfmon.exe", "explorer.exe", "StartMenuExperienceHost.exe",
        # Vendor services (ASUS, NVIDIA, Intel, Samsung, Realtek, etc.)
        "NVDisplay.Container.exe", "nvcontainer.exe", "igfx*", "Asus*", "ArmouryCrate*", "coreServiceShell.exe",
        "SamsungMagician*", "RtkAudUService64.exe", "esif_uf.exe", "Intel*", "OneApp.IGCC*", "PtSvcHost.exe",
        "DtsApo4Service.exe", "jhi_service.exe", "LMS.exe", "RstMwService.exe", "TbtP2pShortcutService.exe",
        "WMIRegistrationService.exe", "wslservice.exe", "vmms.exe", "vmcompute.exe", "VSSVC.exe"
    )

    foreach ($wmi in $wmiProcesses) {
        $name = $wmi.Name
        if (-not $apiDict.ContainsKey($wmi.ProcessId) -and $name -notin $coreAllowed) {
            Add-Finding -Type "Hidden Process" -Target "PID: $($wmi.ProcessId)" `
                -Details "Hidden from standard API. Name: $name" -Severity "High" -Mitre $Global:MITRE.HiddenProcess
        }

        if ($wmi.CommandLine -match "-enc|-encodedcommand|-w hidden|-windowstyle hidden|IEX|Invoke-Expression|certutil|bitsadmin|msiexec|regsvr32|rundll32|msbuild|wmic") {
            Add-Finding -Type "Suspicious Command Line" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Fileless/obfuscated execution: $($wmi.CommandLine)" -Severity "High" -Mitre $Global:MITRE.EncodedCommand
        }
    }
}

function Invoke-InjectionHunt {
    Write-Console "[*] Hunting for Reflective DLL Injection / Foreign Modules..." "Cyan"
    $procs = Get-Process -ErrorAction SilentlyContinue
    $sigCache = @{}
    foreach ($p in $procs) {
        try {
            $modules = Get-Module -InputObject $p -ErrorAction SilentlyContinue
            foreach ($m in $modules) {
                if ($m.ModuleName -like "*.dll" -and $m.Path) {
                    if (-not (Test-Path $m.Path)) {
                        Add-Finding -Type "Reflective DLL Injection" -Target "$($p.ProcessName) (PID $($p.Id))" `
                            -Details "Module '$($m.ModuleName)' loaded but file does not exist on disk" -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                        continue
                    }
                    if (-not $sigCache.ContainsKey($m.Path)) {
                        $sigCache[$m.Path] = (Get-AuthenticodeSignature -FilePath $m.Path -ErrorAction SilentlyContinue).Status
                    }
                    $sigStatus = $sigCache[$m.Path]
                    if ($sigStatus -ne "Valid" -and $p.ProcessName -notin @("explorer","svchost","lsass","winlogon","services")) {
                        Add-Finding -Type "Suspicious Injected DLL" -Target "$($p.ProcessName) (PID $($p.Id))" `
                            -Details "Unsigned DLL: $($m.Path)" -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                    }
                }
            }
        } catch {}
    }
}

# =============================================================================
# 2. Classic Fileless + Expanded Registry Persistence
# =============================================================================
function Invoke-FilelessHunt {
    Write-Console "[*] Hunting for Classic Fileless Persistence..." "Cyan"
    $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    foreach ($consumer in $wmiConsumers) {
        if ($consumer.Name -notmatch "BVTConsumer|SCM Event Log Consumer") {
            Add-Finding -Type "WMI Persistence" -Target "WMI Consumer: $($consumer.Name)" `
                -Details "Suspicious WMI Event Consumer" -Severity "High" -Mitre $Global:MITRE.WMIPersistence
        }
    }
    $runKeys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            foreach ($property in $entries.PSObject.Properties) {
                if ($property.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                    $val = $property.Value
                    if ($val -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin") {
                        Add-Finding -Type "Suspicious Registry Key" -Target "$key\$($property.Name)" `
                            -Details "LOLBin in Run Key: $val" -Severity "High" -Mitre $Global:MITRE.RegPersistence
                    }
                }
            }
        }
    }
}

function Invoke-AdvancedRegistryHunt {
    Write-Console "[*] Expanded Registry Persistence (IFEO, AppInit_DLLs, Services)..." "Cyan"
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        Get-ChildItem $ifeoPath | ForEach-Object {
            $dbg = Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($dbg.Debugger -match "powershell|cmd|wscript|mshta") {
                Add-Finding -Type "IFEO Debugger Hijack" -Target $_.PSChildName `
                    -Details "Debugger: $($dbg.Debugger)" -Severity "High" -Mitre $Global:MITRE.RegIFEO
            }
        }
    }
    $appinitPaths = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")
    foreach ($p in $appinitPaths) {
        if (Test-Path $p) {
            $val = Get-ItemProperty -Path $p -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
            if ($val.AppInit_DLLs) {
                Add-Finding -Type "AppInit_DLLs Hijack" -Target $p `
                    -Details "AppInit_DLLs: $($val.AppInit_DLLs)" -Severity "High" -Mitre $Global:MITRE.AppInitDLL
            }
        }
    }
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        if ($svc.PathName -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin" -or $svc.PathName -match "\\Temp|\\AppData") {
            Add-Finding -Type "Suspicious Service" -Target "$($svc.Name) ($($svc.PathName))" `
                -Details "Path: $($svc.PathName) | StartMode: $($svc.StartMode)" -Severity "High" -Mitre $Global:MITRE.ServiceTamper
        }
    }
}

# =============================================================================
# 3. BITS Jobs, COM Hijacking, ETW/AMSI, PendingRename
# =============================================================================
function Invoke-BITSHunt {
    Write-Console "[*] Hunting for Suspicious BITS Jobs..." "Cyan"
    $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    foreach ($job in $jobs) {
        if ($job.DisplayName -notmatch "Microsoft|Windows Update|Background Intelligent") {
            Add-Finding -Type "Suspicious BITS Job" -Target "Job: $($job.DisplayName)" `
                -Details "URL: $($job.FileList.Source) | State: $($job.JobState)" -Severity "High" -Mitre $Global:MITRE.BITSJob
        }
    }
}

function Invoke-COMHijackHunt {
    Write-Console "[*] Hunting for COM Hijacking..." "Cyan"
    $comPaths = @("HKLM:\Software\Classes\CLSID","HKCU:\Software\Classes\CLSID")
    foreach ($base in $comPaths) {
        if (Test-Path $base) {
            $clsids = Get-ChildItem $base -ErrorAction SilentlyContinue
            foreach ($clsid in $clsids) {
                $inproc = Join-Path $clsid.PSPath "InProcServer32"
                if (Test-Path $inproc) {
                    $dll = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(Default)'
                    if ($dll) {
                        # Much broader whitelist + handle bare filenames
                        if ($dll -notmatch "(?i)(system32|syswow64|Program Files|WinSxS|Microsoft\.NET|Windows Defender|Windows\\servicing|ProgramData\\Microsoft|Windows\\SystemApps)") {
                            Add-Finding -Type "COM Hijacking" -Target $clsid.PSChildName `
                                -Details "InProcServer32 points to suspicious DLL: $dll" -Severity "High" -Mitre $Global:MITRE.COMHijack
                        }
                    }
                }
            }
        }
    }
}

function Invoke-ETWAMSITamperHunt {
    Write-Console "[*] Hunting for ETW / AMSI Tampering..." "Cyan"
    $amsiProv = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiProv) {
        $count = (Get-ChildItem $amsiProv -ErrorAction SilentlyContinue).Count
        if ($count -eq 0) {
            Add-Finding -Type "AMSI Tampering" -Target "AMSI Providers" `
                -Details "0 providers registered. AMSI is completely blinded!" -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
        }
    }
    $amsiKey = "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings"
    if (Test-Path $amsiKey) {
        $val = Get-ItemProperty -Path $amsiKey -Name "AmsiEnable" -ErrorAction SilentlyContinue
        if ($val.AmsiEnable -eq 0) {
            Add-Finding -Type "AMSI Disabled" -Target "AmsiEnable = 0" `
                -Details "AMSI explicitly disabled in registry" -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
        }
    }
    $auto = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
    if (Test-Path $auto) {
        $sessions = Get-ChildItem $auto -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $enabled = Get-ItemProperty -Path $s.PSPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 0) {
                Add-Finding -Type "ETW Tampering" -Target $s.PSChildName `
                    -Details "Autologger session disabled" -Severity "High" -Mitre $Global:MITRE.ETWTampering
            }
        }
    }
}

function Invoke-PendingRenameHunt {
    Write-Console "[*] Checking PendingFileRenameOperations (MoveEDR)..." "Cyan"
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $val = Get-ItemProperty -Path $key -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($val.PendingFileRenameOperations) {
        Add-Finding -Type "PendingFileRenameOperations" -Target "Session Manager" `
            -Details "Entries present - possible boot-time EDR deletion" -Severity "High" -Mitre $Global:MITRE.PendingRename
    }
}

# =============================================================================
# 4. Driver & Scheduled Task Hunting
# =============================================================================
function Invoke-DriverHunt {
    Write-Host "[*] Hunting Loaded Drivers & Known Vulnerable (BYOVD)..." -ForegroundColor Cyan

    $knownVulnerable = @(
        "capcom.sys", "iqvw64.sys", "RTCore64.sys", "DBUtil_2_3.sys", "TfSysMon.sys",
        "gdrv.sys", "AsrDrv.sys", "AsrDrv101.sys", "AsrDrv102.sys", "AsrDrv103.sys",
        "AsrDrv104.sys", "AsrDrv105.sys", "amifldrv64.sys", "AMIFLDRV.sys",
        "aswArPot.sys", "aswSP.sys", "BdApiUtil64.sys", "ksapi64.sys", "ksapi64_del.sys",
        "NSecKrnl.sys", "TrueSight.sys", "ThrottleStop.sys", "probmon.sys", "IoBitUnlocker.sys",
        "Zemana.sys", "kavservice.sys", "agent64.sys", "AODDriver.sys", "ASUS.sys",
        "ASMMAP.sys", "ASRDRV.sys", "DBUtil.sys", "DBUtil_2_3_0_4.sys",
        "MsIo64.sys", "MsIo64_2.sys", "WinRing0x64.sys", "WinRing0.sys",
        "Truesight.sys", "wsftprm.sys", "BdApiUtil.sys", "K7RKScan.sys",
        "CcProtect.sys", "ProcessMonitorDriver.sys", "Safetica.sys"
    )

    if ($AutoUpdateDrivers) {
        try {
            Write-Host "[*] Fetching latest vulnerable drivers from loldrivers.io..." -ForegroundColor Cyan
            $apiDrivers = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers" -Method Get -ErrorAction Stop
            $liveList = $apiDrivers | Where-Object { $_.KnownVulnerable } | ForEach-Object { $_.Filename.ToLower() }
            $knownVulnerable = $knownVulnerable + $liveList | Select-Object -Unique
            Write-Host "[+] Loaded $($liveList.Count) live vulnerable drivers" -ForegroundColor Green
        } catch {
            Write-Host "[-] Could not reach loldrivers.io (offline?). Using built-in list." -ForegroundColor Yellow
        }
    }

    $drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
    foreach ($drv in $drivers) {
        if ([string]::IsNullOrWhiteSpace($drv.Name)) { continue }

        $name = $drv.Name.ToLower()
        $isUnsigned = $false
        $sigStatus = "N/A (Virtual Driver)"

        # Check Signature ONLY if the driver has a physical file path on disk
        if (-not [string]::IsNullOrWhiteSpace($drv.Path) -and (Test-Path -Path $drv.Path -ErrorAction SilentlyContinue)) {
            $sig = Get-AuthenticodeSignature -FilePath $drv.Path -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = $sig.Status
                if ($sig.Status -ne "Valid") {
                    $isUnsigned = $true
                }
            }
        }

        # Alert if in vulnerable list OR if it is a physical file that is unsigned
        if ($name -in $knownVulnerable -or $isUnsigned) {
            Add-Finding -Type "Suspicious Kernel Driver" `
                -Target "$($drv.DisplayName) ($($drv.Path))" `
                -Details "Signed: $sigStatus | Vulnerable/Unsigned driver loaded (BYOVD risk)" `
                -Severity "Critical" `
                -Mitre $Global:MITRE.BYOVD
        }
    }
}

function Invoke-ScheduledTaskHunt {
    Write-Console "[*] Hunting Scheduled Tasks for suspicious persistence..." "Cyan"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }

    foreach ($task in $tasks) {
        $cmdLine = ""
        if ($task.Actions) {
            $cmdLine = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " "
        }

        # Only flag if it uses LOLBins **outside** System32 OR has obvious obfuscation
        if ($cmdLine -match "(?i)powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|certutil|bitsadmin" -and
            $cmdLine -notmatch "(?i)Windows\\System32\\|Windows\\SysWOW64\\") {

            Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                -Details "Action: $cmdLine" -Severity "High" -Mitre $Global:MITRE.ScheduledTask
        }
        elseif ($cmdLine -match "-enc|-encodedcommand|-w hidden|IEX|Invoke-Expression") {
            Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                -Details "Action: $cmdLine" -Severity "High" -Mitre $Global:MITRE.ScheduledTask
        }
    }
}

# =============================================================================
# 5. File Hunt (Entropy, Cloaking, Timestomping) / Alt Data Stream
# =============================================================================
function Invoke-FileHunt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$Recurse,
        [int]$MaxSizeBytes = 52428800,
        [int]$EntropySampleBytes = 1048576,
        [switch]$QuickMode,
        [string[]]$ExcludePaths = @(),
        [switch]$Quiet,
        [int]$MaxThreads = 0,
        [int]$FilesPerChunk = 180,
        [switch]$LowMemoryMode
    )

    if ($MaxThreads -le 0) { $MaxThreads = [Environment]::ProcessorCount }
    if ($LowMemoryMode) {
        $MaxThreads = [math]::Max(4, [math]::Floor($MaxThreads / 2))
        $FilesPerChunk = [math]::Min(80, $FilesPerChunk)
        $EntropySampleBytes = 131072
        Write-Console "[*] LowMemoryMode enabled - reduced threads/chunks/entropy sample" "Yellow"
    }
    if ($QuickMode) { $EntropySampleBytes = 262144 }

    # ── Phase 1: Fast native recursive enumeration ─────────────────────────
    $CleanPath = $Path.TrimEnd('\')
    if ($CleanPath -eq "") { $CleanPath = $Path } # Fallback for root

    $BaseExcludedDirs = @(
        "$CleanPath\Windows\WinSxS", "$CleanPath\Windows\System32\config",
        "$CleanPath\System Volume Information", "$CleanPath\ProgramData\Microsoft\Windows\WER",
        "$CleanPath\ProgramData\Microsoft\Windows\SystemData", "$CleanPath\ProgramData\Microsoft\Windows\Containers",
        "$CleanPath\Program Files", "$CleanPath\Program Files (x86)",

        # Cloud Exclusions
        "*OneDrive*", "*DropBox*", "*Google Drive*", "*iCloudDrive*", "*Creative Cloud*",

        # Windows Kernel/AV "Tarpit" Folders & AMSI Deadlocks
        "*Microsoft\Windows Defender\Scans*", "*Microsoft\Search\Data*",
        "*System32\LogFiles\WMI\RtBackup*", "*System32\config\systemprofile*",
        "*Microsoft.PowerShell.Security*",

        # Third-Party AV & EDR Self-Defense Tarpits
        "*Bitdefender*", "*SentinelOne*", "*CrowdStrike*", "*Symantec*",
        "*Kaspersky*", "*McAfee*", "*Trend Micro*", "*Sophos*", "*ESET*"
    )

    $ActiveExclusions = $BaseExcludedDirs + $ExcludePaths

    Write-Console "[*] High-Speed File Hunt in: $Path $(if($QuickMode){'(QuickMode)'}) $(if($LowMemoryMode){'(LowMemory)'})" "Cyan"

    $filesToScan = [System.Collections.Generic.List[string]]::new()
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Path)
    $folderCount = 0

    try {
        while ($queue.Count -gt 0) {
            $currentPath = $queue.Dequeue()
            $folderCount++

            if ($folderCount % 100 -eq 0 -and -not $Quiet) {
                $uiPath = if ($currentPath.Length -gt 50) { "..." + $currentPath.Substring($currentPath.Length - 47) } else { $currentPath }
                Write-Progress -Activity "Phase 1/2 - Enumerating Directories" `
                               -Status "Fldrs: $folderCount | Cands: $($filesToScan.Count) | $uiPath" `
                               -PercentComplete -1
            }

            $skip = $false
            foreach ($ex in $ActiveExclusions) {
                if ($currentPath -like $ex -or $currentPath -like "$ex\*") { $skip = $true; break }
            }
            if ($skip) { continue }

            try {
                $di = [System.IO.DirectoryInfo]::new($currentPath)
                $dirAttr = $di.Attributes.ToString()
                if ($dirAttr -match "ReparsePoint|Offline|RecallOnData|RecallOnOpen") { continue }

                if ($Recurse) {
                    foreach ($subDir in $di.EnumerateDirectories()) { $queue.Enqueue($subDir.FullName) }
                }

                foreach ($file in $di.EnumerateFiles()) {
                    if ($file.Extension -match "\.(exe|dll|sys|ps1|bat|vbs|js)$") {
                        $fileAttr = $file.Attributes.ToString()
                        if ($fileAttr -match "Offline|RecallOnData|RecallOnOpen|ReparsePoint") { continue }
                        if ($file.Length -le $MaxSizeBytes) {
                            $filesToScan.Add($file.FullName)
                        }
                    }
                }
            } catch {}
        }
    }
    finally {
        if (-not $Quiet) { Write-Progress -Activity "Phase 1/2 - Enumerating Directories" -Completed }
        [System.GC]::Collect()
    }

    Write-Console "[*] Found $($filesToScan.Count) candidate files. Starting parallel scan..." "Gray"
    if ($filesToScan.Count -eq 0) { return }

    # ── Chunking for smoother progress & lower memory pressure ─────────────
    $chunks = [System.Collections.Generic.List[System.Object[]]]::new()
    for ($i = 0; $i -lt $filesToScan.Count; $i += $FilesPerChunk) {
        $end = [math]::Min($i + $FilesPerChunk, $filesToScan.Count)
        $chunks.Add($filesToScan.GetRange($i, $end - $i).ToArray())
    }

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $jobs = @()

    # ── Worker scriptblock ─────────────────────────────────────────────────
    $huntingBlock = {
        param([string[]]$fileList, [int]$SampleBytes, [bool]$IsQuickMode)
        $threadResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($filePath in $fileList) {
            try {
                $file = [System.IO.FileInfo]::new($filePath)

                # Decloaking check
                Add-Type -AssemblyName System.Core -ErrorAction SilentlyContinue
                $mmap = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($filePath, [System.IO.FileMode]::Open, $null, 0, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
                $view = $mmap.CreateViewAccessor(0, 0, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
                $mmapSize = $view.Capacity
                $view.Dispose(); $mmap.Dispose()

                if ($file.Length -ne $mmapSize) {
                    $threadResults.Add([PSCustomObject]@{Type="Cloaked File"; Target=$filePath; Details="Size mismatch!"; Severity="High"; Mitre="T1014"})
                }

                # High Entropy check
                if (-not $IsQuickMode -or $file.Length -le 10485760) {
                    $bytes = if ($file.Length -gt $SampleBytes) {
                        $fs = [System.IO.File]::OpenRead($filePath)
                        $buf = New-Object byte[] $SampleBytes
                        $fs.Read($buf, 0, $SampleBytes) | Out-Null
                        $fs.Close()
                        $buf
                    } else { [System.IO.File]::ReadAllBytes($filePath) }
                    $fileSize = $bytes.Count
                    if ($fileSize -gt 0) {
                        $byteCounts = New-Object 'int[]' 256
                        foreach ($b in $bytes) { $byteCounts[$b]++ }
                        $entropy = 0.0
                        foreach ($count in $byteCounts) {
                            if ($count -gt 0) {
                                $prob = $count / $fileSize
                                $entropy -= $prob * [math]::Log($prob, 2)
                            }
                        }
                        if ($entropy -ge 7.2) {
                            $threadResults.Add([PSCustomObject]@{Type="High Entropy File"; Target=$filePath; Details="Entropy: $([math]::Round($entropy,2))"; Severity="High"; Mitre="T1027"})
                        }
                    }
                }

                # Timestomping check
                if ($file.CreationTime -gt $file.LastWriteTime -or $file.CreationTime.Year -lt 2018) {
                    $threadResults.Add([PSCustomObject]@{Type="Timestomped File"; Target=$filePath; Details="Modified before Creation"; Severity="Medium"; Mitre="T1070"})
                }
            } catch {}
        }
        return $threadResults
    }

    # Launch parallel jobs (simple, reliable style that actually scans)
    try {
        foreach ($chunk in $chunks) {
            $ps = [powershell]::Create().AddScript($huntingBlock).AddArgument($chunk).AddArgument($EntropySampleBytes).AddArgument([bool]$QuickMode)
            $ps.RunspacePool = $runspacePool
            $jobs += [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }

        # ── Real-time progress tracking ─────────────────────────────────────
        $totalBatches = $jobs.Count
        $completedBatches = 0
        $lastUpdate = Get-Date
        $startTime = Get-Date
        $updateInterval = [TimeSpan]::FromMilliseconds(250)

        while ($completedBatches -lt $totalBatches) {
            $now = Get-Date
            if (($now - $lastUpdate) -ge $updateInterval) {
                $completedBatches = ($jobs | Where-Object { $_.Handle.IsCompleted }).Count
                $processedFiles = [math]::Min(($completedBatches * $FilesPerChunk), $filesToScan.Count)
                $pct = [int][math]::Round((($completedBatches / $totalBatches) * 100), 0)

                $elapsedSecs = ($now - $startTime).TotalSeconds
                $rate = if ($elapsedSecs -gt 0) { [math]::Round($processedFiles / $elapsedSecs, 0) } else { 0 }
                $remainingSecs = if ($rate -gt 0) { [int](($filesToScan.Count - $processedFiles) / $rate) } else { -1 }

                if (-not $Quiet) {
                    $statusStr = "Files: $processedFiles / $($filesToScan.Count) | Speed: $rate/sec | Batches: $completedBatches/$totalBatches"
                    Write-Progress -Activity "Phase 2/2 - Deep File Scanning" -Status $statusStr -PercentComplete $pct -SecondsRemaining $remainingSecs
                }
                $lastUpdate = $now
            }
            Start-Sleep -Milliseconds 180
        }

        foreach ($job in $jobs) {
            $results = $job.PowerShell.EndInvoke($job.Handle)
            if ($results) {
                foreach ($res in $results) {
                    Add-Finding -Type $res.Type -Target $res.Target -Details $res.Details -Severity $res.Severity -Mitre $res.Mitre
                }
            }
        }
    }
    finally {
        if (-not $Quiet) { Write-Progress -Activity "Phase 2/2 - Deep File Scanning" -Completed }
        Write-Console " [Cleanup] Disposing runspaces & forcing GC..." "DarkGray"
        foreach ($job in $jobs) {
            if ($job.PowerShell) { $job.PowerShell.Stop(); $job.PowerShell.Dispose() }
        }
        if ($runspacePool) { $runspacePool.Close(); $runspacePool.Dispose() }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Invoke-ADSHunt {
    Write-Console "[*] Parallel ADS Hunt targeting High-Risk Locations..." "Cyan"

    $HighRiskPaths = @("$env:SystemDrive\ProgramData", "$env:SystemDrive\Users\Public", "$env:SystemDrive\Windows\Temp")
    $users = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    foreach ($u in $users) { $HighRiskPaths += "$u\AppData\Local\Temp"; $HighRiskPaths += "$u\AppData\Roaming"; $HighRiskPaths += "$u\Downloads" }

    $ActiveExclusions = @("$env:SystemDrive\ProgramData\Microsoft\Windows\WER", "$env:SystemDrive\ProgramData\Microsoft\Windows\SystemData", "$env:SystemDrive\ProgramData\Microsoft\Windows\Containers") + $ExcludePaths

    $filesToScan = [System.Collections.Generic.List[string]]::new()
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($p in $HighRiskPaths) { if (Test-Path -LiteralPath $p) { $queue.Enqueue($p) } }

    $folderCount = 0
    while ($queue.Count -gt 0) {
        $currentPath = $queue.Dequeue()
        $folderCount++

        if ($folderCount % 50 -eq 0 -and -not $Quiet) {
            Write-Progress -Activity "Enumerating ADS Folders" -Status "Scanned $folderCount folders..." -PercentComplete -1
        }

        $skip = $false
        foreach ($ex in $ActiveExclusions) { if ($currentPath -like $ex -or $currentPath -like "$ex\*") { $skip = $true; break } }
        if ($skip) { continue }

        try {
            $di = [System.IO.DirectoryInfo]::new($currentPath)
            if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or ($di.Attributes -band [System.IO.FileAttributes]::Offline)) { continue }
            foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($currentPath)) { $queue.Enqueue($subDir) }
            foreach ($filePath in [System.IO.Directory]::EnumerateFiles($currentPath)) {
                $attrib = [System.IO.File]::GetAttributes($filePath)
                if (-not ($attrib -band [System.IO.FileAttributes]::Offline)) { $filesToScan.Add($filePath) }
            }
        } catch {}
    }
    if (-not $Quiet) { Write-Progress -Activity "Enumerating ADS Folders" -Completed }

    Write-Console "[*] Found $($filesToScan.Count) files in high-risk zones. Batching jobs..." "Gray"
    if ($filesToScan.Count -eq 0) { return }

    $MaxThreads = [Environment]::ProcessorCount
    $ChunkSize = [math]::Ceiling($filesToScan.Count / ($MaxThreads * 2))
    if ($ChunkSize -lt 100) { $ChunkSize = 100 }

    $chunks = [System.Collections.Generic.List[System.Object[]]]::new()
    for ($i = 0; $i -lt $filesToScan.Count; $i += $ChunkSize) {
        $end = [math]::Min($i + $ChunkSize, $filesToScan.Count) - $i
        $chunks.Add($filesToScan.GetRange($i, $end).ToArray())
    }

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $jobs = @()

    $adsBlock = {
        param([array]$fileList)
        $threadResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($filePath in $fileList) {
            try {
                $streams = Get-Item -LiteralPath $filePath -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
                foreach ($stream in $streams) {
                    if ($stream.Length -gt 0) {
                        $threadResults.Add([PSCustomObject]@{ Type = "Alternate Data Stream"; Target = $filePath; Details = "Stream '$($stream.Stream)'"; Severity = "High"; Mitre = "T1564.004" })
                    }
                }
            } catch {}
        }
        return $threadResults
    }

    try {
        foreach ($chunk in $chunks) {
            $ps = [powershell]::Create().AddScript($adsBlock).AddArgument($chunk)
            $ps.RunspacePool = $runspacePool
            $jobs += [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }

        $totalBatches = $jobs.Count
        $completedBatches = 0

        while ($completedBatches -lt $totalBatches) {
            $currentCompleted = 0
            foreach ($job in $jobs) { if ($job.Handle.IsCompleted) { $currentCompleted++ } }

            if ($currentCompleted -gt $completedBatches) {
                $completedBatches = $currentCompleted
                $pct = [math]::Round(($completedBatches / $totalBatches) * 100, 1)
                if (-not $Quiet) { Write-Progress -Activity "ADS Stream Scan" -Status "Processed $pct%" -PercentComplete $pct }
            }
            Start-Sleep -Milliseconds 500
        }

        foreach ($job in $jobs) {
            $results = $job.PowerShell.EndInvoke($job.Handle)
            if ($results) { foreach ($res in $results) { Add-Finding -Type $res.Type -Target $res.Target -Details $res.Details -Severity $res.Severity -Mitre $res.Mitre } }
        }
    } finally {
        if (-not $Quiet) { Write-Progress -Activity "ADS Stream Scan" -Completed }
        Write-Console "    [Cleanup] Disposing of background ADS threads..." "DarkGray"
        foreach ($job in $jobs) { if ($job.PowerShell) { $job.PowerShell.Stop(); $job.PowerShell.Dispose() } }
        if ($runspacePool) { $runspacePool.Close(); $runspacePool.Dispose() }
    }
}

# -----------------------------------------------------------------------------
# Reporting
# -----------------------------------------------------------------------------
function Export-Reports {
    param([string]$OutDir)
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    if ($script:Findings.Count -eq 0) {
        Write-Host "`n[+] Scan complete. No anomalies detected matching current filters." -ForegroundColor Green
        return
    }
    Write-Host "`n===================================================" -ForegroundColor Green
    Write-Host " TOP 10 FINDINGS SUMMARY " -ForegroundColor White
    Write-Host "===================================================" -ForegroundColor Green
    $script:Findings | Group-Object Type | Sort-Object Count -Descending | Select-Object -First 10 Count, Name | Format-Table -AutoSize

    # === CSV ===
    if ($OutputFormat -contains 'All' -or $OutputFormat -contains 'CSV') {
        $csvPath = "$OutDir\EDR_Report_$timestamp.csv"
        $script:Findings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Console "[+] CSV Report saved to: $csvPath" "Green"
    }

    # === HTML ===
    if ($OutputFormat -contains 'All' -or $OutputFormat -contains 'HTML') {
        $htmlPath = "$OutDir\EDR_Report_$timestamp.html"
        $totalFindings = $script:Findings.Count
        $highCrit = ($script:Findings | Where-Object { $_.Severity -in @('Critical','High') }).Count
        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EDR_HUNTER_SYS | NEURAL LINK</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;700&display=swap');
        body { font-family: 'Fira Code', monospace; background-color: #050505; color: #e2e8f0; }
        .neon-border-cyan { box-shadow: 0 0 10px rgba(6, 182, 212, 0.5); border: 1px solid #06b6d4; }
        .neon-border-pink { box-shadow: 0 0 15px rgba(236, 72, 153, 0.4); border: 1px solid #ec4899; }
        .neon-text-cyan { text-shadow: 0 0 5px rgba(6, 182, 212, 0.8); }
        .neon-text-pink { text-shadow: 0 0 5px rgba(236, 72, 153, 0.8); }
        .grid-bg {
            background-image: linear-gradient(rgba(6, 182, 212, 0.05) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(6, 182, 212, 0.05) 1px, transparent 1px);
            background-size: 30px 30px;
        }
        .Critical { color: #f43f5e; text-shadow: 0 0 6px #f43f5e; }
        .High { color: #ec4899; text-shadow: 0 0 6px #ec4899; }
        .Medium { color: #eab308; text-shadow: 0 0 4px #eab308; }
    </style>
</head>
<body class="grid-bg min-h-screen p-6">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center border-b border-cyan-800 pb-4 mb-6">
            <div>
                <h1 class="text-3xl font-bold text-cyan-400 neon-text-cyan tracking-widest">EDR_HUNTER_SYS</h1>
                <p class="text-xs text-pink-500 mt-1 uppercase tracking-widest">// ACTIVE DEFENSE ENCLAVE</p>
            </div>
            <div class="text-xs bg-black px-3 py-1 rounded-sm border border-cyan-500 text-cyan-400 neon-text-cyan">
                [ UPLINK_SECURE : PENDING ]
            </div>
        </header>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div class="bg-black/60 p-5 rounded-sm neon-border-cyan">
                <h2 class="text-lg font-bold mb-4 border-b border-cyan-800 pb-2 text-cyan-300 uppercase tracking-wide">SCAN SUMMARY</h2>
                <p class="text-5xl font-bold text-white">TOTAL: <span class="text-cyan-400">@TOTAL@</span></p>
                <p class="text-pink-400 mt-2">HIGH/CRITICAL: <span class="font-bold">@HIGHCRIT@</span></p>
            </div>
            <div class="bg-black/60 p-5 rounded-sm neon-border-cyan md:col-span-2">
                <h2 class="text-lg font-bold mb-4 border-b border-cyan-800 pb-2 text-cyan-300 uppercase tracking-wide">ACTIVE DETECTIONS</h2>
                <div class="text-xs text-gray-400 bg-gray-900/80 p-3 rounded-sm h-32 overflow-y-auto border border-gray-800" id="detections-list"></div>
            </div>
        </div>
        <div class="bg-black/80 p-5 rounded-sm neon-border-pink">
            <h2 class="text-lg font-bold mb-4 border-b border-pink-900 pb-2 text-pink-500 neon-text-pink uppercase tracking-wide">ACTIVE DETECTIONS</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="text-cyan-400 bg-black border-b border-cyan-900 text-xs uppercase tracking-wider">
                        <tr>
                            <th class="p-3">TIMESTAMP</th>
                            <th class="p-3">SEVERITY</th>
                            <th class="p-3">TYPE</th>
                            <th class="p-3">TARGET</th>
                            <th class="p-3">DETAILS</th>
                            <th class="p-3">MITRE</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800 text-gray-300">
'@
        foreach ($f in $script:Findings) {
            $html += "<tr class='hover:bg-gray-900/50'>"
            $html += "<td class='p-3 whitespace-nowrap text-xs'>$($f.Timestamp)</td>"
            $html += "<td class='p-3 font-bold $($f.Severity)'>$($f.Severity)</td>"
            $html += "<td class='p-3'>$($f.Type)</td>"
            $html += "<td class='p-3 text-cyan-300'>$($f.Target)</td>"
            $html += "<td class='p-3 text-gray-400'>$($f.Details)</td>"
            $html += "<td class='p-3 text-purple-400'>$($f.MITRE)</td>"
            $html += "</tr>"
        }
        $html += @'
                    </tbody>
                </table>
            </div>
        </div>
        <div class="text-center text-xs text-gray-500 mt-8">
            Generated by EDR Toolkit • @TIMESTAMP@
        </div>
    </div>
    <script>
        document.getElementById('detections-list').innerHTML = `
            <div class="text-cyan-300">Total anomalies detected: <span class="font-bold text-white">@TOTAL@</span></div>
            <div class="text-pink-400">High/Critical threats: <span class="font-bold">@HIGHCRIT@</span></div>
            <div class="mt-4 text-xs text-gray-400">Scan completed successfully.</div>
        `;
    </script>
</body>
</html>
'@
        $html = $html -replace '@TOTAL@', $totalFindings
        $html = $html -replace '@HIGHCRIT@', $highCrit
        $html = $html -replace '@TIMESTAMP@', (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $html | Set-Content -Path $htmlPath -Encoding UTF8
        Write-Console "[+] HTML Report saved to: $htmlPath" "Green"
    }

    # === JSON ===
    if ($OutputFormat -contains 'All' -or $OutputFormat -contains 'JSON') {
        $jsonPath = "$OutDir\EDR_Report_$timestamp.json"
        $script:Findings | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath
        Write-Console "[+] JSON Report saved to: $jsonPath" "Green"
    }
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
Write-Console "===================================================" "Green"
Write-Console "=========== Windows EDR Hunting Toolkit ===========" "Green"
Write-Console "===================================================" "Green"

if ($TestMode) {
    Write-Host "[*] RUNNING IN TEST MODE: Injecting simulated artifacts to test pipeline routing..." -ForegroundColor Magenta
    Add-Finding -Type "AMSI Tampering" -Target "Simulated Evasion Check" -Details "Only 0 provider(s) registered" -Severity "Critical" -Mitre "T1562.001"
    Add-Finding -Type "High Entropy File" -Target "C:\Temp\TestPayload.exe" -Details "Simulated Entropy: 7.99" -Severity "High" -Mitre "T1027"
    Export-Reports -OutDir $ReportPath
    exit
}

if (-not ($ScanProcesses -or $ScanFileless -or $TargetDirectory -or $ScanTasks -or $ScanDrivers -or $ScanInjection -or $ScanADS -or $ScanRegistry -or $ScanETWAMSI -or $ScanPendingRename -or $ScanBITS -or $ScanCOM)) {
    Write-Host "Usage examples:" -ForegroundColor Yellow
    Write-Host " .\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM"
    Write-Host " .\EDR_Toolkit.ps1 -TargetDirectory 'C:\' -Recursive -ScanADS -QuickMode -SeverityFilter Critical,High -OutputFormat JSON -Quiet"
    Exit
}

if ($ScanProcesses)  { Invoke-ProcessHunt }
if ($ScanInjection)  { Invoke-InjectionHunt }
if ($ScanFileless)   { Invoke-FilelessHunt }
if ($ScanRegistry)   { Invoke-AdvancedRegistryHunt }
if ($ScanTasks)      { Invoke-ScheduledTaskHunt }
if ($ScanDrivers)    { Invoke-DriverHunt }
if ($ScanBITS)       { Invoke-BITSHunt }
if ($ScanCOM)        { Invoke-COMHijackHunt }
if ($ScanETWAMSI)    { Invoke-ETWAMSITamperHunt }
if ($ScanPendingRename) { Invoke-PendingRenameHunt }

if ($TargetDirectory) {
    Invoke-FileHunt -Path $TargetDirectory -Recurse:$Recursive
    if ($ScanADS) { Invoke-ADSHunt -Path $TargetDirectory -Recurse:$Recursive }
}

Export-Reports -OutDir $ReportPath
