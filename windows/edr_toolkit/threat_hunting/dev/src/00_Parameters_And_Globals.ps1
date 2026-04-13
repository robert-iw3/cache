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