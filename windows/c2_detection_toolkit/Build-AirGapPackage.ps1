<#
.SYNOPSIS
    C2 Beacon Sensor v1 - Air-Gap Package Builder

.DESCRIPTION
    Executes on an internet-connected staging system to gather all required dependencies,
    TraceEvent packages, and the pre-compiled Rust ML binary. Compresses them into a
    portable ZIP archive for secure, offline deployment.

@RW
#>

param(
    [string]$StagingDir = "C:\Temp\C2Sensor_AirGap_Staging",
    [string]$OutFile = "C:\Temp\C2Sensor_AirGap_Package.zip"
)

Write-Host "[*] Initializing Air-Gap Staging Directory at $StagingDir..." -ForegroundColor Cyan
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $StagingDir -Force

$TransitManifest = @{}
function Register-FileHash([string]$FilePath, [string]$LogicalName) {
    if (Test-Path $FilePath) {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $TransitManifest[$LogicalName] = $hash
        Write-Host "    [+] Hashed $LogicalName : $hash" -ForegroundColor DarkGray
    }
}

# ============================================================================
# 1. C# ETW DEPENDENCIES (TraceEvent is required for ETW ingestion)
# ============================================================================
Write-Host "`n[*] Downloading C# TraceEvent & Unsafe NuGet Packages (v3.2.2)..." -ForegroundColor Gray
$TeUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.2"
$UnUrl = "https://www.nuget.org/api/v2/package/System.Runtime.CompilerServices.Unsafe/5.0.0"
$TeOut = Join-Path $StagingDir "traceevent.nupkg"
$UnOut = Join-Path $StagingDir "unsafe.nupkg"

Invoke-WebRequest -Uri $TeUrl -OutFile $TeOut
Invoke-WebRequest -Uri $UnUrl -OutFile $UnOut
Register-FileHash -FilePath $TeOut -LogicalName "TraceEvent_NuGet"
Register-FileHash -FilePath $UnOut -LogicalName "Unsafe_NuGet"

# ============================================================================
# 2. THREAT INTELLIGENCE (JA3 SSLBL)
# ============================================================================
Write-Host "`n[*] Fetching Latest JA3 Threat Intel (Abuse.ch)..." -ForegroundColor Gray
$Ja3Url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.json"
$Ja3Out = Join-Path $StagingDir "ja3_fingerprints.json"
try {
    Invoke-WebRequest -Uri $Ja3Url -OutFile $Ja3Out
    Register-FileHash -FilePath $Ja3Out -LogicalName "JA3_ThreatIntel"
} catch {
    Write-Host "    [!] Could not reach Abuse.ch. Deploying with offline cache only." -ForegroundColor Yellow
}

# ============================================================================
# 3. CORE SENSOR PAYLOADS
# ============================================================================
Write-Host "`n[*] Copying Core Sensor Payloads from Local Workspace..." -ForegroundColor Gray
$Payloads = @("C2Sensor_Launcher.ps1", "C2Sensor.cs", "c2sensor_ml.dll")

foreach ($p in $Payloads) {
    if (Test-Path $p) {
        Copy-Item -Path $p -Destination $StagingDir -Force
        Write-Host "    [+] Staged: $p" -ForegroundColor Green
    } else {
        Write-Host "    [!] WARNING: $p not found in current directory." -ForegroundColor Yellow
        if ($p -match "\.dll$") {
            Write-Host "        -> Run Build-RustEngine.ps1 before building the Air-Gap package." -ForegroundColor Red
        }
    }
}

# ============================================================================
# 4. COMPRESSION & CLEANUP
# ============================================================================
Write-Host "`n[*] Generating Transit Manifest..." -ForegroundColor Gray
$ManifestPath = Join-Path $StagingDir "AirGap_Manifest.json"
$TransitManifest | ConvertTo-Json | Out-File -FilePath $ManifestPath -Encoding UTF8

Write-Host "[*] Compressing Air-Gap Package to $OutFile..." -ForegroundColor Cyan
if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
Compress-Archive -Path "$StagingDir\*" -DestinationPath $OutFile -Force

$FinalZipHash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash

Write-Host "`n[+] Build Complete. Portable Deployment Archive: $OutFile" -ForegroundColor Green
Write-Host "[+] PACKAGE SHA256: $FinalZipHash" -ForegroundColor Yellow