<#
.SYNOPSIS
    Automated BYOVD Eradication and Memory Acquisition Engine
.DESCRIPTION
    Dynamically reads threat intelligence from a correlation CSV report.
    Iterates through all findings to download ProcDump, acquire memory dumps
    of compromised processes, extract vulnerable kernel drivers for forensics,
    destroy persistence mechanisms, and trigger a reboot.

    1. Proactive BYOVD sweep using live loldrivers.io database (SHA256 match)
    2. Processes advanced_memory_injections.csv for C2 processes
    3. Memory dumps + full driver neutralization + evidence collection
    4. Reboot option
.NOTES
    Author: Robert Weber
    Version: 1.0
#>
#Requires -RunAsAdministrator

param (
    [string]$ReportCSV = "C:\ProgramData\C2Sensor\Evidence\DFIR_Collect\advanced_memory_injections.csv",
    [string]$EvidenceFolder = "C:\ProgramData\C2Sensor\Evidence\DFIR_Collect",
    [switch]$AutoReboot,
    [switch]$ArmedMode,
    [switch]$Orchestrated,
    [switch]$ScanDriversOnly
)

$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"; $cCyan = "$ESC[38;2;0;200;255m"; $cGreen = "$ESC[38;2;10;210;130m"
$cDark = "$ESC[38;2;100;100;100m"; $cYellow = "$ESC[38;2;255;180;50m"; $cReset = "$ESC[0m"

$Host.UI.RawUI.WindowTitle = "V1 DFIR // ORCHESTRATED ERADICATION SWEEPER"
[Console]::CursorVisible = $false
Clear-Host
[Console]::SetCursorPosition(0, 6)

function Update-UI([int]$Progress, [int]$Threats, [string]$ActionText) {
    if ($Orchestrated) {
        Write-Output "[HUD]|$Progress|$Threats|$ActionText"
    } else {
        $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, 0)
        $TitleStr = " ⚡ C2 SENSOR V1 | ORCHESTRATED ERADICATION SWEEPER"
        $StatsStr = " Progress : $Progress% | Targets: $Threats"
        if ($ActionText.Length -gt 70) { $ActionText = $ActionText.Substring(0,67) + "..." }
        $ActionStr = " Action : $ActionText"
        $PadTitle = " " * [math]::Max(0, (86 - $TitleStr.Length))
        $PadStats = " " * [math]::Max(0, (86 - $StatsStr.Length))
        $PadAction = " " * [math]::Max(0, (86 - $ActionStr.Length))
        Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════╗$cReset"
        Write-Host "$cCyan║$cReset $cRed⚡ C2 SENSOR V1$cReset | ORCHESTRATED ERADICATION SWEEPER$PadTitle$cCyan║$cReset"
        Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════╣$cReset"
        Write-Host "$cCyan║$cReset Progress : $cCyan$Progress%$cReset | Targets: $cRed$Threats$cReset$PadStats$cCyan║$cReset"
        Write-Host "$cCyan║$cReset Action : $cYellow$ActionText$cReset$PadAction$cCyan║$cReset"
        Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════╝$cReset"
        [Console]::SetCursorPosition($curLeft, $curTop)
    }
}

$EvidenceFolder = if (-not (Test-Path $EvidenceFolder)) { New-Item -ItemType Directory -Force -Path $EvidenceFolder | Out-Null; $EvidenceFolder }
$LogFile = Join-Path $EvidenceFolder "Eradication_Log.txt"
"[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] V1 ERADICATION SWEEP INITIATED" | Out-File -FilePath $LogFile -Force

Update-UI 5 0 "Downloading latest vulnerable driver database (loldrivers.io)..."

$DriverDBPath = Join-Path $EvidenceFolder "loldrivers.csv"
try {
    Invoke-WebRequest -Uri "https://www.loldrivers.io/api/drivers.csv" -OutFile $DriverDBPath -UseBasicParsing -ErrorAction Stop
    $VulnDB = Import-Csv $DriverDBPath
    Write-Output " $cGreen[+] LOLDRIVERS DB LOADED:$cReset $($VulnDB.Count) entries"
} catch {
    # Built-in fallback
    $VulnDB = @(
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "46dcd5a62f0ea9c6c41f100ce93287ab0711ed7694fcbc13bbf37795bfac1a98" ; DriverName = "AsIO3.sys (ASUS)" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "2bc72d11fa0beda25dc1dbc372967db49bd3c3a3903913f0877bff6792724dfe" ; DriverName = "DriversCloud_amd64.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "40c855d20d497823716a08a443dc85846233226985ee653770bc3b245cf2ed0f" ; DriverName = "CorMem.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "ea8c8f834523886b07d87e85e24f124391d69a738814a0f7c31132b6b712ed65" ; DriverName = "rspot.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "fa0902daefbd9e716faaac8e854144ea0573e2a41192796f3b3138fe7a1d19f1" ; DriverName = "athpexnt.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd" ; DriverName = "RtCore64.sys (MSI Afterburner)" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427" ; DriverName = "gdrv.sys (Gigabyte)" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24" ; DriverName = "capcom.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "45f42c5d874369d6be270ea27a5511efcca512aeac7977f83a51b7c4dee6b5ef" ; DriverName = "zamguard64.sys (Zemana)" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "58c071cfe72e9ee867bba85cbd0abe72eb223d27978d6f0650d0103553839b59" ; DriverName = "LgDCatcher.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374" ; DriverName = "EneIo64.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "0abca92512fc98fe6c2e7d0a33935686fc3acbd0a4c68b51f4a70ece828c0664" ; DriverName = "GtcKmdfBs.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "22da5a055b7b17c69def9f5af54e257c751507e7b6b9a835fcf6245ab90ae750" ; DriverName = "Netfilter.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "dfaefd06b680f9ea837e7815fc1cc7d1f4cc375641ac850667ab20739f46ad22" ; DriverName = "windows-xp-64.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "b7703a59c39a0d2f7ef6422945aaeaaf061431af0533557246397551b8eed505" ; DriverName = "CSAgent.sys (CrowdStrike masquerade)" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "7a1feb8649a5c0679e1073e6d8a02c8a6ebc5825f02999f16c9459284f1b198b" ; DriverName = "iobitunlocker.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "017933be6023795e944a2a373e74e2cc6885b5c9bc1554c437036250c20c3a7d" ; DriverName = "HwRwDrv.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df" ; DriverName = "STProcessMonitor.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "e9fda504c9bdbe785c55a279ebb27e31783155570ab0c242e1de5bf79fbca6ed" ; DriverName = "tm_filter.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "83bfa50a528762ec52a011302ac3874636fb7e26628cd7acfbf2bdc9faa8110d" ; DriverName = "termdd.sys (legacy Microsoft)" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e" ; DriverName = "ksapi.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "206f27ae820783b7755bca89f83a0fe096dbb510018dd65b63fc80bd20c03261" ; DriverName = "NSecKrnl.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "32198295d2a2700b9895fff999c2b233f9befb0bc175815ec4b71ee926b6edfc" ; DriverName = "BdApiUtil.sys" ; Category = "Vulnerable driver" },
        [PSCustomObject]@{ KnownVulnerableSamples_SHA256 = "5c6ce55a85f5d4640bd1485a72d0812bc4f5188ee966c5fe334248a7175d9040" ; DriverName = "K7RKScan.sys" ; Category = "Vulnerable driver" }
    )

    Write-Output " $cYellow[INFO]$cReset Using built-in fallback of $($VulnDB.Count) known vulnerable drivers (2026)"
}

Update-UI 10 0 "Scanning system drivers + DriverStore for known vulnerable BYOVD..."

$DriverPaths = @("C:\Windows\system32\drivers", "C:\Windows\System32\DriverStore\FileRepository")
$AllDrivers = @()
foreach ($path in $DriverPaths) {
    if (Test-Path $path) {
        $AllDrivers += Get-ChildItem -Path $path -Filter "*.sys" -File -Recurse -ErrorAction SilentlyContinue
    }
}

$FoundVulnDrivers = @()
$TotalDrivers = $AllDrivers.Count
$Processed = 0

foreach ($drv in $AllDrivers) {
    $Processed++
    if ($Processed % 50 -eq 0) { Update-UI ([math]::Round(10 + ($Processed / $TotalDrivers * 20))) 0 "Scanning drivers... ($Processed/$TotalDrivers)" }

    $hash = (Get-FileHash -Path $drv.FullName -Algorithm SHA256).Hash.ToLower()

    foreach ($entry in $VulnDB) {
        $vulnHashes = $entry.KnownVulnerableSamples_SHA256 -split ',' | ForEach-Object { $_.Trim().ToLower() }
        if ($hash -in $vulnHashes -and $entry.Category -like "*vulnerable driver*") {
            $service = (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.PathName -like "*$($drv.Name)" }).Name
            $FoundVulnDrivers += [PSCustomObject]@{
                Name    = $drv.Name
                Path    = $drv.FullName
                Hash    = $hash
                Service = $service
            }
            break
        }
    }
}

if ($FoundVulnDrivers.Count -gt 0) {
    Write-Output " $cRed[!] VULNERABLE DRIVERS FOUND:$cReset $($FoundVulnDrivers.Count) high-risk drivers"
    foreach ($vuln in $FoundVulnDrivers) {
        $ZipPath = Join-Path $EvidenceFolder "BYOVD_Evidence_$($vuln.Name).zip"
        Compress-Archive -Path $vuln.Path -DestinationPath $ZipPath -Force
        Write-Output " $cCyan[*] BACKED UP:$cReset $($vuln.Name) → $ZipPath"
        if ($vuln.Service) {
            sc.exe stop $vuln.Service | Out-Null
            sc.exe config $vuln.Service start= disabled | Out-Null
            sc.exe delete $vuln.Service | Out-Null
        }
        Remove-Item -Path $vuln.Path -Force -ErrorAction SilentlyContinue
        Write-Output " $cGreen[+] NEUTRALIZED:$cReset $($vuln.Name)"
        "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] BYOVD neutralized: $($vuln.Name) ($($vuln.Hash))" | Out-File -FilePath $LogFile -Append
    }
} else {
    Write-Output " $cGreen[+] NO VULNERABLE DRIVERS FOUND$cReset – system clean of known BYOVD"
}

Update-UI 30 0 "BYOVD sweep complete."

if ($ScanDriversOnly) {
    Write-Output " $cGreen[+] DRIVER-ONLY SCAN COMPLETE$cReset"
    [Console]::CursorVisible = $true
    exit
}

if (-not (Test-Path $ReportCSV)) {
    Write-Output " $cRed[-] FATAL:$cReset Threat report not found at $ReportCSV"
    [Console]::CursorVisible = $true
    exit
}
$ThreatList = Import-Csv $ReportCSV
$TotalThreats = @($ThreatList).Count
if ($TotalThreats -eq 0) {
    Write-Output " $cGreen[+] ALL CLEAR:$cReset No threats found in the report."
    [Console]::CursorVisible = $true
    exit
}
Update-UI 35 $TotalThreats "Initializing Evidence Container..."

# 2. Download ProcDump from Sysinternals Live
Update-UI 40 $TotalThreats "Downloading ProcDump from Sysinternals..."
$ProcDumpPath = Join-Path $EvidenceFolder "procdump64.exe"
if (-not (Test-Path $ProcDumpPath)) {
    try {
        Invoke-WebRequest -Uri "https://live.sysinternals.com/procdump64.exe" -OutFile $ProcDumpPath -UseBasicParsing -ErrorAction Stop
        Write-Output " $cGreen[+] TOOL ACQUIRED:$cReset procdump64.exe downloaded successfully."
    } catch {
        Write-Output " $cRed[-] FATAL:$cReset Failed to download ProcDump. Check network/proxy."
        [Console]::CursorVisible = $true
        exit
    }
}

$CurrentIdx = 0
foreach ($Threat in $ThreatList) {
    $CurrentIdx++
    $ProgressPct = [math]::Round(($CurrentIdx / $TotalThreats) * 60) + 40

    $TargetName = $Threat.Process
    $TargetPID = $Threat.PID
    $ServiceName = $Threat.ServiceName
    $DriverPath = $Threat.DriverPath

    Update-UI $ProgressPct $TotalThreats "Engaging Target $CurrentIdx of ${TotalThreats}: $TargetName"
    Write-Output "`n $cCyan============================================================$cReset"
    Write-Output " $cRed[!] ENGAGING TARGET:$cReset $TargetName (Reported PID: $TargetPID)"

    $ActiveProc = Get-Process -Id $TargetPID -ErrorAction SilentlyContinue
    if (-not $ActiveProc -or $ActiveProc.Name -ne $TargetName) {
        $ActiveProc = Get-Process -Name $TargetName -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if ($ActiveProc) {
        $ActivePID = $ActiveProc.Id
        $DumpFile = Join-Path $EvidenceFolder "TargetDump_$($ActivePID)_$($TargetName).dmp"
        try {
            Write-Output " $cCyan[*] FORENSICS:$cReset Executing memory acquisition on PID $ActivePID..."
            $ProcDumpArgs = "-accepteula -ma $ActivePID `"$DumpFile`""
            Start-Process -FilePath $ProcDumpPath -ArgumentList $ProcDumpArgs -Wait -NoNewWindow -PassThru | Out-Null
            if (Test-Path $DumpFile) {
                Write-Output " $cGreen[+] DUMP SUCCESS:$cReset Saved to $DumpFile"
                "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] Dump acquired: $DumpFile" | Out-File -FilePath $LogFile -Append
            }
        } catch { Write-Output " $cYellow[-] DUMP FAILED:$cReset $($_.Exception.Message)" }
    } else {
        Write-Output " $cYellow[-] TARGET MISSING:$cReset $TargetName is no longer running in memory."
    }

        # =====================================================================
        # TRIAGE PERSISTENCE SCRUBBER
        # =====================================================================
        $TriageReport = Join-Path $EvidenceFolder "C2_Triage_Report_PID_$TargetPID.txt"
        if (Test-Path $TriageReport) {
            Write-Output "  $cCyan[*] ERADICATION:$cReset Scrubbing persistence mechanisms from Triage Report..."
            $TriageData = Get-Content $TriageReport -Raw

            # 1. Scrub Scheduled Tasks & Dropper Files
            $TaskRegex = [regex]::Matches($TriageData, "TaskName:\s*([^\r\n]+).*?Action:\s*([^\r\n]+)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($Match in $TaskRegex) {
                $TaskName = $Match.Groups[1].Value.Trim()
                $TaskAction = $Match.Groups[2].Value.Trim()

                # Filter for tasks executing out of user-writable directories
                if ($TaskAction -match "(?i)AppData|Temp|Public|Powershell|wscript|cscript") {
                    if ($ArmedMode) {
                        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
                        Write-Output "    $cGreen[+] TASK SCRUBBED:$cReset Malicious task removed: $TaskName"
                        "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] Task scrubbed: $TaskName" | Out-File -FilePath $LogFile -Append

                        # Extract and delete the specific .exe or .ps1 dropper file
                        if ($TaskAction -match '(C:\\[^\s"]+)') {
                            $DropperFile = $matches[1]
                            Remove-Item -Path $DropperFile -Force -ErrorAction SilentlyContinue
                            Write-Output "    $cGreen[+] DROPPER REMOVED:$cReset Staging dropper deleted: $DropperFile"
                            "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] Dropper wiped: $DropperFile" | Out-File -FilePath $LogFile -Append
                        }
                    } else {
                        Write-Output "    $cDark[?] DRY-RUN:$cReset Would have scrubbed Task '$TaskName'"
                    }
                }
            }

            # 2. Scrub Registry Run Keys
            $RegRegex = [regex]::Matches($TriageData, "RunKey:\s*([^\r\n]+)\s*->\s*([^\r\n]+)")
            foreach ($Match in $RegRegex) {
                $KeyName = $Match.Groups[1].Value.Trim()
                $DropperPath = $Match.Groups[2].Value.Trim()
                if ($ArmedMode) {
                    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $KeyName -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $DropperPath -Force -ErrorAction SilentlyContinue
                    Write-Output "    $cGreen[+] REGISTRY SCRUBBED:$cReset Registry Dropper '$KeyName' wiped."
                    "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] Registry scrubbed: $KeyName" | Out-File -FilePath $LogFile -Append
                } else {
                    Write-Output "    $cDark[?] DRY-RUN:$cReset Would have scrubbed Run Key '$KeyName'"
                }
            }
        }
}

# 4. Reboot
Write-Output "`n $cCyan============================================================$cReset"
Update-UI 100 $TotalThreats "Sweep Complete. Initiating Flush."
Write-Output " $cGreen[+] SWEEP COMPLETE:$cReset All targets processed."

if ($AutoReboot) {
    Write-Output " $cRed[!] INITIATING REBOOT IN 5 SECONDS...$cReset"
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} else {
    Write-Output " $cCyan[*] ACTION REQUIRED:$cReset A reboot is required to flush protected payloads from RAM."
    Write-Output " Run 'Restart-Computer -Force' to finalize the remediation sequence."
}

if (-not $Orchestrated) { [Console]::CursorVisible = $true }