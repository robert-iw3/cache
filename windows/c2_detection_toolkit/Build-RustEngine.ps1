<#
.SYNOPSIS
    C2 Beacon Sensor v1 - Rust Engine Compiler Pipeline

.DESCRIPTION
    Compiles the native Rust Machine Learning engine into a C-Compatible Dynamic
    Link Library (.dll). This allows the C# ETW sensor to map the engine directly
    into memory via FFI, completely eliminating Python IPC pipe latency.

@RW
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$WorkingDir = $PWD.Path
$ProjectName = "c2sensor_ml"
$ProjectDir = Join-Path $WorkingDir $ProjectName
$FinalBinaryName = "c2sensor_ml.dll"

$ESC = [char]27
$cRed = "$ESC[91m"; $cCyan = "$ESC[96m"; $cGreen = "$ESC[92m"; $cYellow = "$ESC[93m"; $cReset = "$ESC[0m"

Write-Host "`n$cCyan[*] INITIATING C2 SENSOR RUST COMPILER PIPELINE (v1.0)$cReset"

# ============================================================================
# 1. MSVC BUILD TOOLS VALIDATION
# ============================================================================
Write-Host "    [*] Verifying MSVC Desktop Workload & Universal C Runtime (UCRT)..." -ForegroundColor Gray
$vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstallPath = $null

if (Test-Path $vsWherePath) {
    $paths = & $vsWherePath -latest -products * -property installationPath
    if ($paths) { if ($paths -is [array]) { $vsInstallPath = $paths[0] } else { $vsInstallPath = $paths } }
}

if ([string]::IsNullOrWhiteSpace($vsInstallPath)) {
    $FallbackPaths = @("${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools", "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community")
    foreach ($fp in $FallbackPaths) {
        if (Test-Path (Join-Path $fp "VC\Auxiliary\Build\vcvars64.bat")) { $vsInstallPath = $fp; break }
    }
}

if (-not [string]::IsNullOrWhiteSpace($vsInstallPath) -and (Test-Path $vsInstallPath)) {
    Write-Host "    $cGreen[+] Visual Studio environment located at: $vsInstallPath$cReset"
} else {
    Write-Host "`n$cRed[!] CRITICAL: MSVC Build Tools missing. Please install the C++ Desktop Workload.$cReset"; Exit
}

# ============================================================================
# 2. TOOLCHAIN VALIDATION
# ============================================================================
Write-Host "    [*] Verifying Rust Toolchain (Cargo)..." -ForegroundColor Gray
try {
    $null = Get-Command cargo -ErrorAction Stop
    Write-Host "    $cGreen[+] Rust toolchain is installed and accessible.$cReset"
} catch {
    Write-Host "`n$cRed[!] CRITICAL: Rust toolchain (cargo) not found in PATH.$cReset"; Exit
}

# ============================================================================
# 3. PROJECT SCAFFOLDING
# ============================================================================
Write-Host "    [*] Scaffolding Rust Library Architecture..." -ForegroundColor Gray
if (Test-Path $ProjectDir) { Remove-Item $ProjectDir -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $ProjectDir "src") -Force | Out-Null

$CargoTomlContent = @"
[package]
name = "c2sensor_ml"
version = "1.0.0"
edition = "2021"

[lib]
name = "c2sensor_ml"
crate-type = ["cdylib"]

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = 'abort'
strip = true

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rusqlite = { version = "0.31", features = ["bundled"] }
linfa = "0.7"
linfa-clustering = "0.7"
linfa-nn = "0.7"
ndarray = "0.15"
rand = "0.8"
regex = "1.10"
"@
Set-Content -Path (Join-Path $ProjectDir "Cargo.toml") -Value $CargoTomlContent

$MainRsRoot = Join-Path $WorkingDir "lib.rs"
$MainRsSrc = Join-Path $WorkingDir "src\lib.rs"
$MainRsTarget = Join-Path $ProjectDir "src\lib.rs"

if (Test-Path $MainRsRoot) { Copy-Item -Path $MainRsRoot -Destination $MainRsTarget -Force }
elseif (Test-Path $MainRsSrc) { Copy-Item -Path $MainRsSrc -Destination $MainRsTarget -Force }
else { Write-Host "`n$cRed[!] CRITICAL: 'lib.rs' not found.$cReset"; Exit }

# ============================================================================
# 4. NATIVE VCVARS COMPILATION PIPELINE
# ============================================================================
Write-Host "    [*] Constructing Native MSVC Compilation Context..." -ForegroundColor Gray

$VcvarsPath = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
$CompileWrapper = Join-Path $ProjectDir "Invoke-NativeCompiler.cmd"
$WrapperLogic = @"
@echo off
call "$VcvarsPath" >nul 2>&1
cd /d "$ProjectDir"
cargo build --release
exit /b %ERRORLEVEL%
"@
Set-Content -Path $CompileWrapper -Value $WrapperLogic

& cmd.exe /c $CompileWrapper

if ($LASTEXITCODE -ne 0) { Write-Host "`n$cRed[!] COMPILATION FAILED: Cargo returned exit code $LASTEXITCODE$cReset"; Exit }

# ============================================================================
# 5. EXTRACTION & CLEANUP
# ============================================================================
$CompiledDll = Join-Path $ProjectDir "target\release\c2sensor_ml.dll"
$FinalDest = Join-Path $WorkingDir $FinalBinaryName

if (Test-Path $CompiledDll) {
    Copy-Item -Path $CompiledDll -Destination $FinalDest -Force

    $HashVal = (Get-FileHash $FinalDest -Algorithm SHA256).Hash
    $HashDest = Join-Path $WorkingDir ($FinalBinaryName -replace "\.dll$", ".sha256")
    $HashVal | Out-File -FilePath $HashDest -Encoding ascii -NoNewline

    Remove-Item $ProjectDir -Recurse -Force
    Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue

    $SizeMB = [math]::Round(((Get-Item $FinalDest).Length / 1MB), 2)
    Write-Host "`n$cCyan╔══════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset $cGreen SUCCESS: Native C2 Engine Compiled Successfully"
    Write-Host "$cCyan║$cReset  Target : $FinalBinaryName"
    Write-Host "$cCyan║$cReset  SHA256 : $HashVal"
    Write-Host "$cCyan║$cReset  Size   : $SizeMB MB"
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════╝$cReset"
}