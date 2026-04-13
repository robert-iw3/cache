<#
.SYNOPSIS
    Deep Sensor v2.1 - Rust Engine Compiler Pipeline

.DESCRIPTION
    Compiles the Rust Machine Learning engine into a Native C-Compatible Dynamic
    Link Library (.dll). This allows the C# ETW sensor to map the engine directly
    into memory via FFI, completely eliminating IPC pipe latency.

.NOTES
    Author: Robert Weber
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$WorkingDir = $PWD.Path
$ProjectName = "deep_sensor_ml"
$ProjectDir = Join-Path $WorkingDir $ProjectName
$FinalBinaryName = "DeepSensor_ML_v2.1.dll"

# Console Colors
$ESC = [char]27
$cRed = "$ESC[91m"; $cCyan = "$ESC[96m"; $cGreen = "$ESC[92m"; $cYellow = "$ESC[93m"; $cReset = "$ESC[0m"

Write-Host "`n$cCyan[*] INITIATING RUST ENGINE COMPILER PIPELINE (v2.1)$cReset"

# ============================================================================
# 1. MSVC BUILD TOOLS & UCRT WORKLOAD VALIDATION
# ============================================================================
Write-Host "    [*] Verifying MSVC Desktop Workload & Universal C Runtime (UCRT)..." -ForegroundColor Gray
$vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstallPath = $null

if (Test-Path $vsWherePath) {
    $paths = & $vsWherePath -latest -products * -property installationPath
    if ($paths) {
        if ($paths -is [array]) { $vsInstallPath = $paths[0] } else { $vsInstallPath = $paths }
    }
}

if ([string]::IsNullOrWhiteSpace($vsInstallPath)) {
    $FallbackPaths = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community"
    )
    foreach ($fp in $FallbackPaths) {
        if (Test-Path (Join-Path $fp "VC\Auxiliary\Build\vcvars64.bat")) {
            $vsInstallPath = $fp; break
        }
    }
}

Write-Host "    [*] Fetching Microsoft Master Bootstrapper..." -ForegroundColor DarkGray
$vsBuildTools = Join-Path $env:TEMP "vs_buildtools.exe"
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile $vsBuildTools -UseBasicParsing

if (-not [string]::IsNullOrWhiteSpace($vsInstallPath) -and (Test-Path $vsInstallPath)) {
    Write-Host "    $cGreen[+] Visual Studio environment located at: $vsInstallPath$cReset"
    Write-Host "    [*] Enforcing C++ Workload and Windows SDK on existing installation (Silent)..." -ForegroundColor DarkGray

    # FIX: Using vs_buildtools.exe to modify instead of setup.exe to support the --wait flag
    $modArgs = "modify --installPath `"$vsInstallPath`" --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --quiet --wait --norestart --nocache"
    $modProc = Start-Process -FilePath $vsBuildTools -ArgumentList $modArgs -Wait -PassThru

    if ($modProc.ExitCode -eq 0 -or $modProc.ExitCode -eq 3010) {
        Write-Host "    $cGreen[+] C++ Workload and Windows SDK dependencies fully synced.$cReset"
    } else {
        Write-Host "    $cRed[!] Bootstrapper returned code $($modProc.ExitCode). Compilation may fail if SDK was not added.$cReset"
    }
} else {
    Write-Host "    $cYellow[-] Visual Studio Build Tools missing. Initiating automated deployment...$cReset"
    Write-Host "    $cYellow[!] WARNING: Downloading the full C++ workload (~2GB). This may take 5-10 minutes.$cReset"

    $installArgs = "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    $installProc = Start-Process -FilePath $vsBuildTools -ArgumentList $installArgs -Wait -PassThru

    if ($installProc.ExitCode -eq 0 -or $installProc.ExitCode -eq 3010) {
        Write-Host "    $cGreen[+] MSVC Build Tools deployed successfully.$cReset"
        $vsInstallPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools"
    } else {
        Write-Host "`n$cRed[!] CRITICAL: MSVC Build Tools installation failed (Exit Code: $($installProc.ExitCode)).$cReset"
        Remove-Item $vsBuildTools -Force -ErrorAction SilentlyContinue
        Exit
    }
}
Remove-Item $vsBuildTools -Force -ErrorAction SilentlyContinue

# ============================================================================
# 2. TOOLCHAIN VALIDATION
# ============================================================================
Write-Host "    [*] Verifying Rust Toolchain (Cargo)..." -ForegroundColor Gray
try {
    $null = Get-Command cargo -ErrorAction Stop
    Write-Host "    $cGreen[+] Rust toolchain is installed and accessible.$cReset"
} catch {
    Write-Host "    $cYellow[-] Rust toolchain not found. Attempting automated installation...$cReset"
    $RustUpPath = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile $RustUpPath -UseBasicParsing
    $installProc = Start-Process -FilePath $RustUpPath -ArgumentList "-y --default-toolchain stable --default-host x86_64-pc-windows-msvc" -Wait -PassThru

    if ($installProc.ExitCode -ne 0) { Write-Host "`n$cRed[!] CRITICAL: Rust installation failed.$cReset"; Exit }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "    $cGreen[+] Rust toolchain installed successfully.$cReset"
    Remove-Item $RustUpPath -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# 3. PROJECT SCAFFOLDING
# ============================================================================
Write-Host "    [*] Scaffolding Rust Library Architecture..." -ForegroundColor Gray
if (Test-Path $ProjectDir) { Remove-Item $ProjectDir -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $ProjectDir "src") -Force | Out-Null

$CargoTomlContent = @"
[package]
name = "deep_sensor_ml"
version = "2.1.0"
edition = "2021"
authors = ["Robert Weber"]

[lib]
name = "deep_sensor_ml"
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
regex = "1.10"
md-5 = "0.10"
hex = "0.4"
rusqlite = { version = "0.31", features = ["bundled"] }
extended-isolation-forest = "0.2"
chrono = "0.4"
"@
Set-Content -Path (Join-Path $ProjectDir "Cargo.toml") -Value $CargoTomlContent

# DEVELOPER NOTE: Targeting lib.rs for DLL compilation instead of main.rs
$MainRsRoot = Join-Path $WorkingDir "lib.rs"
$MainRsSrc = Join-Path $WorkingDir "src\lib.rs"
$MainRsTarget = Join-Path $ProjectDir "src\lib.rs"

if (Test-Path $MainRsRoot) { Copy-Item -Path $MainRsRoot -Destination $MainRsTarget -Force }
elseif (Test-Path $MainRsSrc) { Copy-Item -Path $MainRsSrc -Destination $MainRsTarget -Force }
else { Write-Host "`n$cRed[!] CRITICAL: 'lib.rs' not found. Please rename main.rs to lib.rs.$cReset"; Exit }

# ============================================================================
# 4. NATIVE VCVARS COMPILATION PIPELINE
# ============================================================================
Write-Host "    [*] Constructing Native MSVC Compilation Context..." -ForegroundColor Gray

$VcvarsPath = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $VcvarsPath)) {
    Write-Host "`n$cRed[!] CRITICAL: vcvars64.bat not found at $VcvarsPath.$cReset"
    Exit
}

$CompileWrapper = Join-Path $ProjectDir "Invoke-NativeCompiler.cmd"
$WrapperLogic = @"
@echo off
echo     [*] Initializing MSVC x64 Linkers and Windows SDK...
call "$VcvarsPath"

if %ERRORLEVEL% NEQ 0 (
    echo     [!] CRITICAL: vcvars64.bat failed to initialize the environment.
    exit /b %ERRORLEVEL%
)

echo     [*] Environment successfully mapped.
cd /d "$ProjectDir"
cargo clean >nul 2>&1

echo     [*] Executing Cargo Release Build...
cargo build --release
exit /b %ERRORLEVEL%
"@
Set-Content -Path $CompileWrapper -Value $WrapperLogic

# Execute natively to prevent PowerShell from hanging on MSVC background daemons (mspdbsrv.exe)
& cmd.exe /c $CompileWrapper

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n$cRed[!] COMPILATION FAILED: Cargo returned exit code $LASTEXITCODE$cReset"
    Exit
}

# ============================================================================
# 5. EXTRACTION & CLEANUP
# ============================================================================
$CompiledDll = Join-Path $ProjectDir "target\release\deep_sensor_ml.dll"
$FinalDest = Join-Path $WorkingDir $FinalBinaryName

if (Test-Path $CompiledDll) {
    Copy-Item -Path $CompiledDll -Destination $FinalDest -Force
    Remove-Item $ProjectDir -Recurse -Force
    Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue

    $SizeMB = [math]::Round(((Get-Item $FinalDest).Length / 1MB), 2)
    Write-Host "`n$cCyan╔══════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset $cGreen SUCCESS: Native FFI Engine Compiled Successfully                          $cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Target : $FinalBinaryName"
    Write-Host "$cCyan║$cReset  Size   : $SizeMB MB"
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════╝$cReset"
} else {
    Write-Host "`n$cRed[!] CRITICAL: Expected output DLL not found.$cReset"
}