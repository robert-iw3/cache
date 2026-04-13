<#
.SYNOPSIS
    Automated Memory Analysis
.DESCRIPTION
    Automates debugger acquisition, executes multi-level forensic commands,
    and generates a report.

    1. Checks for CDB.exe
    2. Installs via Winget if missing
    3. Analyzes .dmp for C2/BYOVD artifacts
    4. Exports report to C:\Temp
    5. Uninstalls and cleans up temporary files
.NOTES
    Author: Robert Weber
    V5
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$DumpPath,
    [string]$ReportDir = "C:\temp",
    [string]$SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
    [switch]$Orchestrated
)

$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"
$cCyan = "$ESC[38;2;0;200;255m"
$cGreen = "$ESC[38;2;10;210;130m"
$cDark = "$ESC[38;2;100;100;100m"
$cYellow = "$ESC[38;2;255;180;50m"
$cReset = "$ESC[0m"

$ErrorActionPreference = "Stop"
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmm"
$ReportFile = Join-Path $ReportDir "Deep_Forensic_Analysis_$TimeStamp.txt"
$InstallerPath = "$ReportDir\winsdksetup.exe"
$InstalledByScript = $false

# 1. DISCOVERY
function Get-CdbPath {
    $SearchRoots = @("${env:ProgramFiles(x86)}\Windows Kits", "${env:ProgramFiles}\Windows Kits")
    foreach ($Root in $SearchRoots) {
        if (Test-Path $Root) {
            # Speed Triage: Target specific versioned Debugger folders
            $PossiblePaths = Resolve-Path "$Root\*\Debuggers\x64\cdb.exe" -ErrorAction SilentlyContinue
            if ($PossiblePaths) { return $PossiblePaths[0].Path }

            # Deep Fallback: Recursive search
            $Match = Get-ChildItem -Path $Root -Filter "cdb.exe" -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
            if ($Match) { return $Match.FullName }
        }
    }
    return $null
}

$CdbPath = Get-CdbPath

if (-not $CdbPath) {
    Write-Output "  $cCyan[*] Debugger missing. Downloading latest Web Installer...$cReset"

    # Newer SDK redirect (as of 2025-2026)
    $SdkUrl = "https://go.microsoft.com/fwlink/?linkid=2120843"
    $InstallerPath = "$ReportDir\winsdksetup.exe"

    Invoke-WebRequest -Uri $SdkUrl -OutFile $InstallerPath -UseBasicParsing

    Write-Output "  $cYellow[!] Installing ONLY Debugging Tools (Silent)...$cReset"

    # Correct feature ID + better silent flags
    $InstallProc = Start-Process -FilePath $InstallerPath `
        -ArgumentList "/features OptionId.WindowsDesktopDebuggers /quiet /norestart" `
        -Wait -PassThru

    if ($InstallProc.ExitCode -ne 0) {
        Write-Error "Installer failed with Exit Code: $($InstallProc.ExitCode).`nThis is usually a network/firewall issue during the component download."
        Write-Output "  $cRed[!]Try running the installer manually (double-click $InstallerPath) and select only 'Debugging Tools for Windows'.$cReset"
        exit
    }

    # Filesystem Grace Period: Loop discovery for up to 15 seconds
    Write-Output "  $cDark[*] Waiting for filesystem indexing...$cReset"
    $RetryCount = 0
    while (-not $CdbPath -and $RetryCount -lt 5) {
        Start-Sleep -Seconds 3
        $CdbPath = Get-CdbPath
        $RetryCount++
    }

    if (-not $CdbPath) {
        Write-Error "CDB.exe still missing after 'successful' install. Verify installer can access Microsoft servers."
        exit
    }
    $InstalledByScript = $true
}

# 2. ANALYSIS EXECUTION
# !analyze -v: Tier 1 | !peb/lm: Tier 2 | !address: Tier 3 | kL: Tier 4/5
$DebugCmds = "!analyze -v; .echo [PEB_DATA]; !peb; .echo [MODULE_DATA]; lm t n; .echo [MEMORY_DATA]; !address -summary; .echo [STACK_DATA]; kL 100; q"

Write-Output "  $cCyan[*] Executing deep-dive analysis on $DumpPath...$cReset"
$RawOutput = & $CdbPath -z $DumpPath -y $SymbolPath -c $DebugCmds

# 3. DATA PARSING
$ProcName = ($RawOutput | Select-String "PROCESS_NAME:\s+(.*)").Matches.Groups[1].Value
$CmdLine  = ($RawOutput | Select-String -Pattern 'CommandLine: (.*)' -Context 0,1).Context.PostContext[0]
$RWXCheck = if ($RawOutput -match "PAGE_EXECUTE_READWRITE") { "CRITICAL: RWX Memory Detected (Shellcode/Injection)" } else { "Nominal" }

# 4. TIERED REPORT GENERATION
$FinalReport = @"
================================================================================
  DEEP FORENSIC REPORT: $ProcName
================================================================================
REPORT GENERATED : $(Get-Date)
DUMP SOURCE      : $DumpPath

[ TIER 1: TRIAGE SUMMARY ]
--------------------------------------------------------------------------------
VERDICT          : $(if ($RWXCheck -match "CRITICAL") {"MALICIOUS / INJECTED"} else {"SUSPICIOUS"})
TARGET PROCESS   : $ProcName
THREAT INDICATOR : $RWXCheck

[ TIER 2: PERSISTENCE & METADATA ]
--------------------------------------------------------------------------------
COMMAND LINE     : $CmdLine
MODULE TIMESTAMPS: (Check [MODULE_DATA] below for anomalies/timestomping)

[ TIER 3: MEMORY ANALYSIS ]
--------------------------------------------------------------------------------
RWX STATUS       : $RWXCheck
(RWX indicates fileless shellcode typically used by Havoc or Cobalt Strike.)

[ TIER 4/5: RAW FORENSIC TELEMETRY ]
--------------------------------------------------------------------------------
$RawOutput
================================================================================
"@

$FinalReport | Out-File -FilePath $ReportFile -Encoding UTF8
Write-Output "  $cGreen[+] Report generated at: $ReportFile$cReset"

# 5. CLEANUP
if ($InstalledByScript) {
    Write-Output "  $cCyan[*] Cleaning up installer...$cReset"
    Remove-Item $InstallerPath -Force
}
Write-Output "  $cGreen[+] Analysis Complete.$cReset"