<#
.SYNOPSIS
    Generates safe "Attack Simulation" telemetry to verify Sysmon config and C2 Monitor logic.
#>

Write-Host "[-] Starting C2 Validation Suite..." -ForegroundColor Cyan

# 1. Simulate "Encoded Command" (Event 1)
Write-Host "   [+] Simulating Encoded PowerShell Command..." -NoNewline
try {
    # This is a safe command (echo 'test') encoded in Base64
    $cmd = "Write-Host 'This is a test beacon'"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
    $encoded = [Convert]::ToBase64String($bytes)

    # Sysmon should see "powershell -EncodedCommand ..."
    $null = Start-Process powershell.exe -ArgumentList "-EncodedCommand $encoded", "-WindowStyle Hidden" -Wait -PassThru
    Write-Host "Done." -ForegroundColor Green
} catch {
    Write-Host "Failed." -ForegroundColor Red
}

# 2. Simulate "Network Beaconing" (Event 3)
Write-Host "   [+] Simulating Network Beaconing (Low Jitter)..." -NoNewline
$target = "8.8.8.8" # Google DNS (Safe target)
for ($i=1; $i -le 5; $i++) {
    # Connect to port 443 (HTTPS)
    $null = Test-NetConnection -ComputerName $target -Port 443 -InformationLevel Quiet
    Start-Sleep -Seconds 2 # Exactly 2 seconds (0 jitter) -> Should trigger StdDev check
}
Write-Host "Done." -ForegroundColor Green

# 3. Simulate "DGA / High Entropy DNS" (Event 22)
Write-Host "   [+] Simulating DGA DNS Queries..." -NoNewline
$domains = @("x83nf29a.com", "q92mz84p.org", "v74kd92l.net")
foreach ($d in $domains) {
    try { [System.Net.Dns]::GetHostEntry($d) } catch { } # Ignore NXDOMAIN errors
}
Write-Host "Done." -ForegroundColor Green

# 4. Simulate "Suspicious File Creation" (Event 11)
Write-Host "   [+] Simulating Suspicious File Creation..." -NoNewline
$testFile = "$env:TEMP\malicious_script.ps1"
New-Item -Path $testFile -ItemType File -Force | Out-Null
Write-Host "Done." -ForegroundColor Green

Write-Host "[-] Simulation Complete. Telemetry generated." -ForegroundColor Cyan