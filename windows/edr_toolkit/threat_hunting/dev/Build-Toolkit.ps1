<#
.SYNOPSIS
    EDR Toolkit Compiler
.DESCRIPTION
    Concatenates modular .ps1 source files into a single monolithic
    payload for easy WinRM / EDR deployment.
#>

$SourceDir = ".\src"
$ReleaseDir = ".\Release"
$OutputFile = "$ReleaseDir\EDR_Toolkit_Deploy.ps1"

# Ensure Release directory exists
if (-not (Test-Path $ReleaseDir)) { New-Item -ItemType Directory -Path $ReleaseDir | Out-Null }

Write-Host "[*] Compiling EDR Toolkit..." -ForegroundColor Cyan
$SourceFiles = Get-ChildItem -Path "$SourceDir\*.ps1" | Sort-Object Name

# Clear old build
Clear-Content $OutputFile -ErrorAction SilentlyContinue

foreach ($File in $SourceFiles) {
    Write-Host "    -> Injecting: $($File.Name)" -ForegroundColor Gray

    # Read raw to preserve formatting, output as UTF8 to prevent encoding breaks
    $Content = Get-Content $File.FullName -Raw
    $Content + "`r`n`r`n" | Out-File $OutputFile -Append -Encoding UTF8
}

Write-Host "[+] Build Complete! Payload ready at: $OutputFile" -ForegroundColor Green