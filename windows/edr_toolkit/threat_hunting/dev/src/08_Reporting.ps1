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