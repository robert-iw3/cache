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