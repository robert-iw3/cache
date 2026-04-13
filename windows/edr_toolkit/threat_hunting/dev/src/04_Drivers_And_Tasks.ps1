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
