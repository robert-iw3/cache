<#
.SYNOPSIS
    Deep Sensor V2 - Air-Gap Package Builder

.DESCRIPTION
    Executes on an internet-connected system to gather all required dependencies,
    threat intelligence files, and binaries. Stages the files into a structured directory
    and compresses them into a portable ZIP archive for UNC path deployment.
#>

param(
    [string]$StagingDir = "C:\Temp\DeepSensor_AirGap_Staging",
    [string]$OutFile = "C:\Temp\DeepSensor_AirGap_Package.zip"
)

Write-Host "[*] Initializing Air-Gap Staging Directory at $StagingDir..." -ForegroundColor Cyan
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $StagingDir -Force

# --- Transit Integrity Manifest ---
$TransitManifest = @{}

function Register-FileHash([string]$FilePath, [string]$LogicalName) {
    if (Test-Path $FilePath) {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $TransitManifest[$LogicalName] = $hash
        Write-Host "    [+] Hashed $LogicalName : $hash" -ForegroundColor DarkGray
    }
}

# --- 1. Python Engine ---
Write-Host "[*] Downloading Python 3.11.8 Installer..." -ForegroundColor Gray
$PyUrl = "https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe"
$PyOut = Join-Path $StagingDir "python-3.11.8-amd64.exe"
Invoke-WebRequest -Uri $PyUrl -OutFile (Join-Path $StagingDir "python-3.11.8-amd64.exe")
Register-FileHash -FilePath $PyOut -LogicalName "Python_Installer"

# --- 2. Python Dependencies (Wheels) ---
Write-Host "[*] Downloading ML Dependency Wheels (scikit-learn, numpy, joblib, scipy)..." -ForegroundColor Gray
$WheelDir = Join-Path $StagingDir "wheels"
$null = New-Item -ItemType Directory -Path $WheelDir -Force
# Use pip to download wheels without installing them
& python -m pip download scikit-learn numpy joblib scipy -d $WheelDir --quiet

# --- 3. C# ETW Dependencies ---
Write-Host "[*] Downloading C# TraceEvent & Unsafe NuGet Packages (v3.1.28)..." -ForegroundColor Gray
# DEVELOPER NOTE: Updated to stable v3.1.28 to resolve 404 errors found in diagnostic logs.
$TeUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.1.28"
$UnUrl = "https://www.nuget.org/api/v2/package/System.Runtime.CompilerServices.Unsafe/5.0.0"
$TeOut = Join-Path $StagingDir "traceevent.nupkg"
$UnOut = Join-Path $StagingDir "unsafe.nupkg"
Invoke-WebRequest -Uri $TeUrl -OutFile (Join-Path $StagingDir "traceevent.nupkg")
Invoke-WebRequest -Uri $UnUrl -OutFile (Join-Path $StagingDir "unsafe.nupkg")
Register-FileHash -FilePath $TeOut -LogicalName "TraceEvent_NuGet"
Register-FileHash -FilePath $UnOut -LogicalName "Unsafe_NuGet"

# --- 4. Context-Aware YARA Dependencies ---
Write-Host "[*] Downloading C# libyara.NET NuGet Package (v3.5.2)..." -ForegroundColor Gray
# DEVELOPER NOTE: Updated to v3.5.2 for compatibility.
$YaraUrl = "https://www.nuget.org/api/v2/package/libyara.NET/3.5.2"
$YaraOut = Join-Path $StagingDir "libyaranet.nupkg"
Invoke-WebRequest -Uri $YaraUrl -OutFile (Join-Path $StagingDir "libyaranet.nupkg")
Register-FileHash -FilePath $YaraOut -LogicalName "LibYara_NuGet"

Write-Host "[*] Generating Category Folders for Context-Aware Routing..." -ForegroundColor Gray
$YaraRuleDir = Join-Path $StagingDir "yara_rules"
$null = New-Item -ItemType Directory -Path $YaraRuleDir -Force
$Vectors = @("WebInfrastructure", "SystemExploits", "LotL", "MacroPayloads", "BinaryProxy", "SystemPersistence", "InfostealerTargets", "RemoteAdmin", "DevOpsSupplyChain", "Core_C2")
foreach ($v in $Vectors) {
    New-Item -ItemType Directory -Path (Join-Path $YaraRuleDir $v) -Force | Out-Null
}

# --- 5. Threat Intelligence (Sigma & LOLDrivers) ---
Write-Host "[*] Fetching Latest LOLDrivers Database..." -ForegroundColor Gray
$LolUrl = "https://loldrivers.io/api/drivers.json"
$LOLout = Join-Path $StagingDir "drivers.json"
Invoke-WebRequest -Uri $LolUrl -OutFile (Join-Path $StagingDir "drivers.json")
Register-FileHash -FilePath $LOLout -LogicalName "LOLDriver_DB"

Write-Host "[*] Fetching SigmaHQ Ruleset..." -ForegroundColor Gray
$SigmaUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
$SigmaOut = Join-Path $StagingDir "sigma_master.zip"
Invoke-WebRequest -Uri $SigmaUrl -OutFile (Join-Path $StagingDir "sigma_master.zip")
Register-FileHash -FilePath $SigmaOut -LogicalName "Sigma_Rules"

# --- YARA Intelligence (Elastic & ReversingLabs) ---
Write-Host "[*] Fetching YARA Intelligence for Air-Gap Staging..." -ForegroundColor Gray
$YaraSources = @(
    @{ Name = "ElasticLabs"; Url = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip" },
    @{ Name = "ReversingLabs"; Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip" }
)

$ElOut = Join-Path $StagingDir "ElasticLabs.zip"
$RlOut = Join-Path $StagingDir "ReversingLabs.zip"

foreach ($src in $YaraSources) {
    Invoke-WebRequest -Uri $src.Url -OutFile (Join-Path $StagingDir "$($src.Name).zip")
}

Register-FileHash -FilePath $ElOut -LogicalName "Elastic_Rules"
Register-FileHash -FilePath $RlOut -LogicalName "ReversingLabs_Rules"

# --- 6. Core Sensor Payloads ---
Write-Host "[*] Copying Core Sensor Payloads from Local Workspace..." -ForegroundColor Gray
$Payloads = @("DeepSensor_Launcher.ps1", "OsSensor.cs", "OsAnomalyML.py", "requirements.txt")
foreach ($p in $Payloads) {
    if (Test-Path $p) {
        Copy-Item -Path $p -Destination $StagingDir -Force
    } else {
        Write-Host "    [!] Warning: $p not found in current directory. Ensure you run this from the project root." -ForegroundColor Yellow
    }
}

# --- 7. Compression & Cleanup ---
Write-Host "[*] Generating Transit Manifest..." -ForegroundColor Gray
$ManifestPath = Join-Path $StagingDir "AirGap_Manifest.json"
$TransitManifest | ConvertTo-Json | Out-File -FilePath $ManifestPath -Encoding UTF8

Write-Host "[*] Compressing Air-Gap Package to $OutFile..." -ForegroundColor Cyan
if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
Compress-Archive -Path "$StagingDir\*" -DestinationPath $OutFile -Force

# --- Hash the Final ZIP Archive ---
$FinalZipHash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash

Write-Host "`n[+] Build Complete. Portable Deployment Archive: $OutFile" -ForegroundColor Green
Write-Host "[+] PACKAGE SHA256: $FinalZipHash" -ForegroundColor Yellow