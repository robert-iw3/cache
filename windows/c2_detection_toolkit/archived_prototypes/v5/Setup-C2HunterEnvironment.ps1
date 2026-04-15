#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bootstrap script for Kernel C2 Beacon Hunter Environment.
    Installs Python, updates PATH, and installs required ML dependencies.
#>

$ScriptDir = Split-Path $PSCommandPath -Parent
$RequirementsPath = Join-Path $ScriptDir "requirements.txt"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  C2 Hunter - Environment Bootstrap" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

# 1. Set Execution Policy
Write-Host "[*] Configuring PowerShell Execution Policy..." -ForegroundColor Yellow
try {
    # Attempt to set the global policy. If the Orchestrator has already set the Process scope to Bypass,
    # this will throw a harmless override exception which we catch and safely ignore.
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
    Write-Host "    [+] Execution Policy set to RemoteSigned." -ForegroundColor Green
} catch {
    Write-Host "    [-] Execution Policy already bypassed at the Orchestrator level. Continuing..." -ForegroundColor Gray
}

# 2. Check/Install Python
Write-Host "`n[*] Checking for Python..." -ForegroundColor Yellow
$pythonInstalled = $false

try {
    $null = python --version 2>&1
    $pythonInstalled = $true
    Write-Host "    [+] Python is already installed." -ForegroundColor Green
} catch {
    Write-Host "    [-] Python not found. Initiating unattended installation..." -ForegroundColor DarkYellow

    # Download Python 3.11 Installer (Stable for Scikit-Learn)
    $PythonInstallerUrl = "https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe"
    $InstallerPath = "$env:TEMP\python-3.11.8-amd64.exe"

    Write-Host "    [*] Downloading Python 3.11..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $InstallerPath

    Write-Host "    [*] Installing Python (Silent)... This may take a minute." -ForegroundColor Gray
    $InstallProcess = Start-Process -FilePath $InstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru

    if ($InstallProcess.ExitCode -eq 0) {
        Write-Host "    [+] Python installed successfully." -ForegroundColor Green
        $pythonInstalled = $true
    } else {
        Write-Host "    [!] Python installation failed with exit code $($InstallProcess.ExitCode)." -ForegroundColor Red
    }

    # Cleanup
    if (Test-Path $InstallerPath) { Remove-Item $InstallerPath -Force }

    # Refresh environment variables so the current session recognizes 'python'
    Write-Host "    [-] Refreshing Environment Variables..." -ForegroundColor Gray
    foreach ($level in "Machine", "User") {
        [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
            Set-Item -Path "Env:\$($_.Name)" -Value $_.Value -ErrorAction SilentlyContinue
        }
    }
}

# 3. Install ML Dependencies
if ($pythonInstalled) {
    Write-Host "`n[*] Upgrading pip and installing ML dependencies..." -ForegroundColor Yellow

    # Ensure pip is up to date
    python -m pip install --upgrade pip --quiet

    if (Test-Path $RequirementsPath) {
        Write-Host "    [-] Installing from requirements.txt..." -ForegroundColor Gray
        python -m pip install -r $RequirementsPath
        Write-Host "    [+] Dependencies installed successfully." -ForegroundColor Green
    } else {
        Write-Host "    [!] requirements.txt not found! Installing default ML packages..." -ForegroundColor DarkYellow
        python -m pip install scikit-learn==1.3.0 numpy==1.25.2 joblib==1.3.2 scipy==1.11.2
        Write-Host "    [+] Default ML packages installed." -ForegroundColor Green
    }
}

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host " [+] Environment Setup Complete!" -ForegroundColor Green
Write-Host "===================================================`n" -ForegroundColor Cyan