<#
.SYNOPSIS
    Native Endpoint DFIR Collector (v3.0)
.DESCRIPTION
    Comprehensively collects volatile memory, deep persistence, network context, and
    high-fidelity logs using native PowerShell. Optimized for low CPU/Memory overhead.

.NOTES
    Example Usage:
    .\collect_forensics.ps1 -CollectionServerURI "https://dfir-collector.local/api/upload" -AuthToken "YOUR_BEARER_TOKEN" -StagingDir "C:\Windows\Temp\DFIR_Collect" -EventLogDays 3 -KeepLocalCopy

    Author: @RW
#>

param (
    [string]$CollectionServerURI = "https://dfir-collector.local/api/upload",
    [string]$AuthToken = "YOUR_BEARER_TOKEN",
    [string]$StagingDir = "C:\Windows\Temp\DFIR_Collect",
    [int]$EventLogDays = 3,
    [switch]$KeepLocalCopy
)

# === Environment variable overrides ===
if ($env:DFIR_COLLECTION_URI) { $CollectionServerURI = $env:DFIR_COLLECTION_URI }
if ($env:DFIR_AUTH_TOKEN) { $AuthToken = $env:DFIR_AUTH_TOKEN }

$ErrorActionPreference = "SilentlyContinue"
$StartTime = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname = $env:COMPUTERNAME
$OutPath = Join-Path $StagingDir "$Hostname-$StartTime"

# === Structured logging to file ===
$LogFile = Join-Path $StagingDir "DFIR_Collection_$Hostname.log"
function Write-Log($Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[*] $Stamp - $Message"
    Write-Host $Line -ForegroundColor Green
    $Line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Export-DFIRData ($Data, $Filename) {
    if ($Data) {
        $FilePath = Join-Path $OutPath "$Filename.json"
        $Data | ConvertTo-Json -Depth 3 -Compress | Out-File $FilePath -Encoding UTF8
        Write-Log "  -> Collected: $Filename"
    }
}

# --- PRE-FLIGHT ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "DFIR Collection requires Administrator privileges."; exit 1 }

if (-not (Test-Path $OutPath)) { New-Item -ItemType Directory -Path $OutPath -Force | Out-Null }
Write-Log "Starting Optimized DFIR Collection for $Hostname"

# ==========================================
# PHASE 1: SYSTEM, NETWORK & BROWSER CONTEXT
# ==========================================
Write-Log "PHASE 1: Context & Network"

$SysInfo = Get-CimInstance Win32_OperatingSystem | Select-Object CSName, Caption, Version, InstallDate, LastBootUpTime
Export-DFIRData $SysInfo "SystemInfo"

$NetConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime
$NetUDP = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime
Export-DFIRData @{ TCP = $NetConnections; UDP = $NetUDP } "ActiveNetworkConnections"

$DNSCache = Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status
Export-DFIRData $DNSCache "DNSCache"

if (Test-Path "C:\Windows\System32\drivers\etc\hosts") {
    $HostsFile = Get-Content "C:\Windows\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch "^\s*#" -and $_ -match "\S" }
    Export-DFIRData $HostsFile "HostsFile"
}

# ==========================================
# PHASE 2: EXECUTION & PROCESSES
# ==========================================
Write-Log "PHASE 2: Processes & Execution Artifacts"

$Processes = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath
Export-DFIRData $Processes "ProcessTree"

$Services = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName
Export-DFIRData $Services "Services"

if (Test-Path "C:\Windows\Prefetch") {
    $Prefetch = Get-ChildItem "C:\Windows\Prefetch\*.pf" | Select-Object Name, CreationTime, LastWriteTime
    Export-DFIRData $Prefetch "PrefetchListing"
}

$PSHistoryPath = (Get-PSReadLineOption).HistorySavePath
if (Test-Path $PSHistoryPath) {
    $PSHistory = Get-Content $PSHistoryPath
    Export-DFIRData $PSHistory "PowerShell_ConsoleHistory"
}

# ==========================================
# PHASE 3: DEEP PERSISTENCE HUNTING
# ==========================================
Write-Log "PHASE 3: Deep Persistence & Evasion"

$Tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\Windows\*"} | Select-Object TaskName, TaskPath, State, Principal, @{N='Action';E={$_.Actions.Execute + " " + $_.Actions.Arguments}}
Export-DFIRData $Tasks "ScheduledTasks"

$WMIFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name, Query
$WMIConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate, ExecutablePath
$WMIBindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Select-Object Filter, Consumer
Export-DFIRData @{ Filters = $WMIFilters; Consumers = $WMIConsumers; Bindings = $WMIBindings } "WMIPersistence"

$LSAPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (Test-Path $LSAPath) {
    $LSA = Get-ItemProperty $LSAPath | Select-Object "Security Packages", "Authentication Packages", "Notification Packages"
    Export-DFIRData $LSA "LSA_SecurityPackages"
}

try {
    $DefExclusions = Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess
    Export-DFIRData $DefExclusions "DefenderExclusions"
} catch {}

$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
$StartupReg = foreach ($Path in $RegPaths) {
    if (Test-Path $Path) { Get-ItemProperty $Path | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider }
}
Export-DFIRData $StartupReg "RegistryStartup"

# ==========================================
# ADDITION: PHASE 3 - DEEP REGISTRY ARTIFACTS
# ==========================================
Write-Log "PHASE 3: Deep Registry (AMCache, SRUM, COM Hijacking)"

# 1. AMCache: History of executed applications (persists after Prefetch/Event Log wipes)
$AMCachePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppInstaller\*"
$AMCacheData = Get-ItemProperty $AMCachePath | Select-Object PSChildName, Publisher, Version
Export-DFIRData $AMCacheData "AMCache_Metadata"

# 2. SRUM: State of the System Resource Usage Monitor (Tracks network usage per app)
$SRUMService = Get-Service -Name "srumbk" | Select-Object Name, Status, StartType
Export-DFIRData $SRUMService "SRUM_Service_State"

# 3. COM Hijacking: Detects malicious DLLs injected into System Classes
$COMPath = "HKCU:\Software\Classes\CLSID"
if (Test-Path $COMPath) {
    $COMHijacks = Get-ChildItem $COMPath | ForEach-Object {
        $Inproc = Join-Path $_.PSPath "InprocServer32"
        if (Test-Path $Inproc) {
            Get-ItemProperty $Inproc | Select-Object "(default)", PSParentPath
        }
    }
    Export-DFIRData $COMHijacks "COM_Hijack_Audit"
}

# === AMCache.hve + ShimCache ===
Write-Log "PHASE 3: AMCache.hve + ShimCache (fixed)"
$AmcacheHive = "C:\Windows\AppCompat\Programs\Amcache.hve"
if (Test-Path $AmcacheHive) { Copy-Item $AmcacheHive -Destination (Join-Path $OutPath "Amcache.hve") -Force }
$ShimCachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
if (Test-Path $ShimCachePath) {
    Get-ItemProperty $ShimCachePath | Select-Object AppCompatCache | ConvertTo-Json -Compress | Out-File (Join-Path $OutPath "ShimCache.json")
}

# ==========================================
# PHASE 4: USERS & LATERAL MOVEMENT
# ==========================================
Write-Log "PHASE 4: Users, Shares, & Exfiltration"

$LocalUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon
$AdminGroup = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource
Export-DFIRData @{ Users = $LocalUsers; Administrators = $AdminGroup } "LocalAccounts"

$SmbShares = Get-SmbShare | Select-Object Name, Path, Description
$SmbSessions = Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
Export-DFIRData @{ Shares = $SmbShares; Sessions = $SmbSessions } "SMBSharesAndSessions"

$USBPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $USBPath) {
    $USBDevices = Get-ChildItem $USBPath -Recurse | ForEach-Object { Get-ItemProperty $_.PSPath } | Select-Object FriendlyName, HardwareID
    Export-DFIRData $USBDevices "USBStorageHistory"
}

# ==========================================
# PHASE 5: HIGH-FIDELITY EVENT LOGS
# ==========================================
Write-Log "PHASE 5: High-Fidelity Event Logs (Last $EventLogDays Days)"
$EventStartTime = (Get-Date).AddDays(-$EventLogDays)

$EventFilter = @(
    # 1102: Security Audit Log Cleared
    @{LogName='Security'; ID=4624,4625,1102; StartTime=$EventStartTime},
    @{LogName='Security'; ID=4688; StartTime=$EventStartTime},

    # 104: System Event Log Cleared
    @{LogName='System'; ID=7045,104; StartTime=$EventStartTime},

    @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=$EventStartTime},
    @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=21,24,25; StartTime=$EventStartTime}
)

$ParsedEvents = New-Object System.Collections.Generic.List[System.Object]

foreach ($Filter in $EventFilter) {
    try {
        $Logs = Get-WinEvent -FilterHashtable $Filter -MaxEvents 5000 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, ProviderName, Message
        if ($Logs) {
            foreach ($Log in $Logs) {
                $ParsedEvents.Add($Log)
            }
        }
    } catch {}
}
Export-DFIRData $ParsedEvents "CriticalEventLogs"

# ==========================================
# PHASE 6: PACKAGING & RESILIENT EXFILTRATION (original + chain-of-custody)
# ==========================================
Write-Log "PHASE 6: Packaging and Exfiltration"
$ZipPath = Join-Path $StagingDir "$Hostname-$StartTime.zip"
Compress-Archive -Path "$OutPath\*" -DestinationPath $ZipPath -Force

# === Chain-of-custody SHA256 ===
$ZipHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
$Manifest = @{ Hostname = $Hostname; Timestamp = $StartTime; ZipSHA256 = $ZipHash }
$Manifest | ConvertTo-Json | Out-File (Join-Path $OutPath "manifest.json")
Write-Log "Chain-of-Custody ZIP SHA256: $($ZipHash.Substring(0,16))..."

$ZipBytes = [System.IO.File]::ReadAllBytes($ZipPath)
$Base64Payload = [Convert]::ToBase64String($ZipBytes)

$ExportData = @{
    hostname = $Hostname
    timestamp = $StartTime
    payload = $Base64Payload
} | ConvertTo-Json -Depth 3

Write-Log "Payload packaged and encoded. Attempting transmission..."

$Headers = @{ "Authorization" = "Bearer $AuthToken"; "Content-Type" = "application/json" }
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$MaxRetries = 3
$RetryCount = 0
$Success = $false

while (-not $Success -and $RetryCount -lt $MaxRetries) {
    try {
        Invoke-RestMethod -Uri $CollectionServerURI -Method Post -Headers $Headers -Body $ExportData
        Write-Log "Transmission Successful."
        $Success = $true
    } catch {
        $RetryCount++
        Write-Host "[!] Transmission failed (Attempt $RetryCount of $MaxRetries). Retrying in 5 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
}

if (-not $Success) { Write-Host "[!] FATAL: Exfiltration failed after $MaxRetries attempts." -ForegroundColor Red }

if (-not $KeepLocalCopy) {
    Remove-Item -Path $OutPath -Recurse -Force
    Remove-Item -Path $ZipPath -Force
    Write-Log "Local staging artifacts securely deleted."
}