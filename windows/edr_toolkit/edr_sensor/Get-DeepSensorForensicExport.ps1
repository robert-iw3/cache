# Get-DeepSensorForensicExport.ps1 (v2.1)
# Purpose: Extract all PIDs/TIDs from logs and gather context.

$LogPath = "C:\ProgramData\DeepSensor\Data\DeepSensor_Events.jsonl"
$OutFile = ".\DeepSensor_Context_Analysis.csv"

if (-not (Test-Path $LogPath)) {
    Write-Host "[!] Log file not found at $LogPath" -ForegroundColor Red
    return
}

Write-Host "[*] Parsing JSONL for unique PIDs and TIDs..." -ForegroundColor Cyan
$RawEvents = Get-Content $LogPath | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $null -ne $_.PID }

# Group by PID/TID to capture every unique thread mentioned
$UniqueEntities = $RawEvents | Group-Object PID, TID | Select-Object Name,
    @{Name='PID'; Expression={$_.Group[0].PID}},
    @{Name='TID'; Expression={$_.Group[0].TID}},
    @{Name='OriginalProcess'; Expression={$_.Group[0].Process}},
    @{Name='Details'; Expression={$_.Group[-1].Details}}

$ConsolidatedData = @()

Write-Host "[*] Gathering context for $($UniqueEntities.Count) entities..." -ForegroundColor Cyan

foreach ($entity in $UniqueEntities) {
    $fpid = $entity.PID
    $tid = $entity.TID

    # 1. Live Process Lookup
    $proc = Get-Process -Id $fpid -ErrorAction SilentlyContinue
    $wmiInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $fpid" -ErrorAction SilentlyContinue

    # 2. Extract User/Owner Safely (CIM Method Fix)
    $owner = "N/A"
    if ($null -ne $wmiInfo) {
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $wmiInfo -MethodName "GetOwner" -ErrorAction SilentlyContinue
            if ($ownerInfo.User) { $owner = $ownerInfo.User }
        } catch { $owner = "UNKNOWN" }
    }

    # 3. Parent Lineage
    $parentName = "UNKNOWN/EXITED"
    if ($null -ne $wmiInfo -and $wmiInfo.ParentProcessId) {
        $parentProc = Get-Process -Id $wmiInfo.ParentProcessId -ErrorAction SilentlyContinue
        if ($parentProc) { $parentName = $parentProc.ProcessName }
    }

    # 4. Thread Specific Context (Check if the TID from the log is still active)
    $threadStatus = "TERMINATED"
    $threadWait   = "N/A"
    if ($null -ne $proc) {
        $liveThread = $proc.Threads | Where-Object { $_.Id -eq $tid }
        if ($liveThread) {
            $threadStatus = $liveThread.ThreadState
            $threadWait   = $liveThread.WaitReason
        }
    }

    $ConsolidatedData += [PSCustomObject]@{
        Log_PID          = $fpid
        Log_TID          = $tid
        Log_ProcessName  = $entity.OriginalProcess
        Live_Status      = if ($null -ne $proc) { "ACTIVE" } else { "EXITED" }
        CommandLine      = if ($null -ne $wmiInfo) { $wmiInfo.CommandLine } else { "N/A" }
        ParentProcess    = $parentName
        ParentPID        = if ($null -ne $wmiInfo) { $wmiInfo.ParentProcessId } else { 0 }
        User             = $owner
        ThreadState      = $threadStatus
        ThreadWaitReason = $threadWait
        LastSeenAlert    = $entity.Details
    }
}

# Export to CSV
$ConsolidatedData | Export-Csv -Path $OutFile -NoTypeInformation -Force
Write-Host "[+] Forensic Context Exported to: $OutFile" -ForegroundColor Green