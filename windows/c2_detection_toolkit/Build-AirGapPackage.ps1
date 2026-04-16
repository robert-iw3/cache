<#
.SYNOPSIS
    C2 Beacon Sensor v1 - Air-Gap Package Builder
.DESCRIPTION
    Stages all core binaries, TraceEvent dependencies, and the full suite of
    Suricata and SigmaHQ rules. Generates a per-file hash manifest and a
    final ZIP hash for secure offline deployment.
#>

param(
    [string]$StagingDir = "C:\Temp\C2Sensor_AirGap_Staging",
    [string]$OutFile = "C:\Temp\C2Sensor_AirGap_Package.zip"
)

Write-Host "[*] Initializing Air-Gap Staging Directory at $StagingDir..." -ForegroundColor Cyan
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $StagingDir -Force

$TransitManifest = @{}

# Function to register file hashes for the manifest
function Register-FileHash([string]$FilePath, [string]$LogicalName) {
    if (Test-Path $FilePath) {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $TransitManifest[$LogicalName] = $hash
        Write-Host "    [+] Hashed $LogicalName : $hash" -ForegroundColor DarkGray
    }
}

# ============================================================================
# 1. CORE DEPENDENCIES (TraceEvent)
# ============================================================================
Write-Host "`n[*] Downloading TraceEvent NuGet Package..." -ForegroundColor Gray
$TeUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.0.2"
$ZipPath = Join-Path $StagingDir "TraceEvent.zip"
try {
    Invoke-WebRequest -Uri $TeUrl -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
    Register-FileHash $ZipPath "TraceEvent_Package"
} catch {
    Write-Host "[!] Failed to download TraceEvent library." -ForegroundColor Red
}

# ============================================================================
# 2. THREAT INTEL: FULL SURICATA RULESETS
# ============================================================================
Write-Host "`n[*] Downloading Full Suricata Ruleset Suite..." -ForegroundColor Gray
$SuricataDir = New-Item -Path (Join-Path $StagingDir "suricata") -ItemType Directory -Force

$SuricataUrls = @(
    @{ Name = "ET_DNS"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules" },
    @{ Name = "ET_C2"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-c2.rules" },
    @{ Name = "ET_Malware"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-malware.rules" },
    @{ Name = "ThreatView_CS_C2"; Url = "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/threatview_CS_c2.rules" },
    @{ Name = "ET_BotCC"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-botcc.rules" },
    @{ Name = "ET_Compromised"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-compromised.rules" },
    @{ Name = "ET_Policy"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-policy.rules" },
    @{ Name = "ET_Info"; Url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-info.rules" }
)

foreach ($feed in $SuricataUrls) {
    $dest = Join-Path $SuricataDir "$($feed.Name).rules"
    try {
        Invoke-WebRequest -Uri $feed.Url -OutFile $dest -UseBasicParsing -ErrorAction Stop
        Register-FileHash $dest "Suricata_$($feed.Name)"
        Write-Host "    [+] Gathered: $($feed.Name)" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Failed to download feed: $($feed.Name)" -ForegroundColor Yellow
    }
}

# ============================================================================
# 3. THREAT INTEL: SIGMAHQ
# ============================================================================
Write-Host "`n[*] Bundling SigmaHQ Network Rules..." -ForegroundColor Gray
$SigmaUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
$SigmaZip = Join-Path $StagingDir "sigma_rules.zip"
try {
    Invoke-WebRequest -Uri $SigmaUrl -OutFile $SigmaZip -UseBasicParsing -ErrorAction Stop
    Register-FileHash $SigmaZip "Sigma_Rules_Package"
} catch {
    Write-Host "[!] Failed to download SigmaHQ rules." -ForegroundColor Red
}

# ============================================================================
# 4. CORE ENGINE PAYLOADS
# ============================================================================
Write-Host "`n[*] Copying Core Sensor Payloads..." -ForegroundColor Gray
$Payloads = @("C2Sensor_Launcher.ps1", "C2Sensor.cs", "c2sensor_ml.dll")

foreach ($p in $Payloads) {
    if (Test-Path $p) {
        $destPath = Join-Path $StagingDir $p
        Copy-Item -Path $p -Destination $destPath -Force
        Register-FileHash $destPath "Payload_$p"
        Write-Host "    [+] Staged: $p" -ForegroundColor Green
    } else {
        Write-Host "    [!] WARNING: $p not found in current directory." -ForegroundColor Yellow
    }
}

# ============================================================================
# 5. PACKAGING & FINAL VERIFICATION
# ============================================================================
Write-Host "`n[*] Generating Integrity Manifest..." -ForegroundColor Cyan
$ManifestPath = Join-Path $StagingDir "AirGap_Manifest.json"
$TransitManifest | ConvertTo-Json | Out-File -FilePath $ManifestPath -Encoding UTF8

Write-Host "[*] Compressing Package..." -ForegroundColor Cyan
if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
Compress-Archive -Path "$StagingDir\*" -DestinationPath $OutFile -Force

$FinalZipHash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash

Write-Host "`n[+] Build Complete. Portable Deployment Archive: $OutFile" -ForegroundColor Green
Write-Host "[+] FINAL PACKAGE HASH (SHA256): $FinalZipHash" -ForegroundColor White -BackgroundColor DarkGreen