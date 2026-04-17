<#
.SYNOPSIS
    Automated Build Pipeline for C2Sensor v2 (.NET 8)
.DESCRIPTION
    This script verifies build tools, scaffolds the .NET project file, downloads
    required NuGet dependencies (TraceEvent), and compiles the C# source into 
    a highly optimized native Windows executable with its accompanying DLLs.
#>
Requires -Version 5.1

# ====================== CONFIGURATION ======================
$ProjectName = "C2Sensor"
$TargetFramework = "net8.0-windows"
$RuntimeIdentifier = "win-x64"
$BaseDir = $PSScriptRoot
$BuildOutDir = Join-Path $BaseDir "Release_Build"
$RustDllName = "c2sensor_ml.dll"

$cGreen = "`e[38;2;57;255;20m"
$cCyan  = "`e[38;2;0;255;255m"
$cRed   = "`e[38;2;255;49;49m"
$cReset = "`e[0m"

function Write-Step([string]$Message) {
    Write-Host "$cCyan[*] $Message$cReset"
}

function Write-Success([string]$Message) {
    Write-Host "$cGreen[+] $Message$cReset"
}

function Write-ErrorMsg([string]$Message) {
    Write-Host "$cRed[!] $Message$cReset"
}

Clear-Host
Write-Step "Initializing C2Sensor v2 Build Pipeline..."

# ====================== 1. VERIFY TOOLCHAIN ======================
Write-Step "Verifying .NET 8 SDK installation..."
try {
    $dotnetVersion = dotnet --version 2>&1
    if ($dotnetVersion -notmatch "^8\.") {
        Write-ErrorMsg "Warning: .NET 8 SDK is recommended. Found version: $dotnetVersion"
    } else {
        Write-Success ".NET 8 SDK Found: $dotnetVersion"
    }
} catch {
    Write-ErrorMsg "FATAL: .NET SDK is not installed or not in PATH."
    Write-Host "Download it here: https://dotnet.microsoft.com/en-us/download/dotnet/8.0"
    exit
}

# ====================== 2. SCAFFOLD PROJECT FILE ======================
$CsprojPath = Join-Path $BaseDir "$ProjectName.csproj"

Write-Step "Generating Project File ($ProjectName.csproj)..."
$CsprojContent = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$TargetFramework</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <Platforms>x64</Platforms>
    <RuntimeIdentifier>$RuntimeIdentifier</RuntimeIdentifier>
    <PublishReadyToRun>true</PublishReadyToRun>
    <TieredCompilation>true</TieredCompilation>
    <Optimize>true</Optimize>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Diagnostics.Tracing.TraceEvent" Version="3.1.15" />
    <PackageReference Include="System.Text.Json" Version="8.0.0" />
  </ItemGroup>
</Project>
"@

Set-Content -Path $CsprojPath -Value $CsprojContent -Force
Write-Success "Project configuration created."

# ====================== 3. RESTORE DEPENDENCIES ======================
Write-Step "Fetching NuGet dependencies (TraceEvent)..."
$restoreResult = dotnet restore $CsprojPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Dependency resolution failed:`n$restoreResult"
    exit
}
Write-Success "All packages restored successfully."

# ====================== 4. COMPILE AND PUBLISH ======================
Write-Step "Compiling C2Sensor engine..."

# Clean previous builds
if (Test-Path $BuildOutDir) { Remove-Item -Path $BuildOutDir -Recurse -Force }

# Execute standard framework-dependent publish (Exe + Dlls)
$publishCommand = "dotnet publish $CsprojPath -c Release -r $RuntimeIdentifier -o `"$BuildOutDir`" --self-contained false"
Invoke-Expression $publishCommand | Out-Null

if (-not (Test-Path (Join-Path $BuildOutDir "$ProjectName.exe"))) {
    Write-ErrorMsg "Compilation failed. Check syntax in .cs files."
    exit
}
Write-Success "C# Compilation complete."

# ====================== 5. UNMANAGED RUST FFI LINK ======================
Write-Step "Integrating unmanaged Rust ML engine..."
$SourceRustDll = Join-Path $BaseDir $RustDllName

if (Test-Path $SourceRustDll) {
    Copy-Item -Path $SourceRustDll -Destination $BuildOutDir -Force
    Write-Success "Copied $RustDllName to deployment directory."
} else {
    Write-ErrorMsg "WARNING: $RustDllName not found in source directory."
    Write-Host "    Make sure to manually place it in the Release_Build folder before running the sensor." -ForegroundColor Yellow
}

# ====================== CLEANUP ======================
Write-Step "Cleaning up staging artifacts..."
Remove-Item -Path (Join-Path $BaseDir "obj") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $BaseDir "bin") -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Success "BUILD SUCCESSFUL!"
Write-Host "Your compiled executable and DLLs are ready in:" -ForegroundColor Gray
Write-Host "$BuildOutDir" -ForegroundColor White
Write-Host "========================================================`n" -ForegroundColor Cyan