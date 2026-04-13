<#
.SYNOPSIS
    Test Runner for EDR Toolkit
#>

$ErrorActionPreference = "Stop"

# 1. Ensure Pester 5+ is installed
$Pester = Get-Module -ListAvailable Pester
if (-not $Pester -or $Pester.Version.Major -lt 5) {
    Write-Host "[!] Pester v5+ not found. Installing for CurrentUser..." -ForegroundColor Yellow
    Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
    Import-Module Pester -MinimumVersion 5.0.0 -Force
} else {
    Import-Module Pester -MinimumVersion 5.0.0
}

Write-Host "[*] Executing EDR Toolkit Test Suite..." -ForegroundColor Cyan

# 2. Run all tests in the \tests directory
$TestResults = Invoke-Pester -Path ".\tests" -PassThru -Output Detailed

# 3. Output Pass/Fail Summary
Write-Host "`n===================================================" -ForegroundColor Cyan
if ($TestResults.FailedCount -gt 0) {
    Write-Host " [X] BUILD FAILED: $($TestResults.FailedCount) Tests Failed!" -ForegroundColor Red
} else {
    Write-Host " [+] BUILD PASSED: All $($TestResults.PassedCount) Tests Successful." -ForegroundColor Green
}
Write-Host "===================================================" -ForegroundColor Cyan