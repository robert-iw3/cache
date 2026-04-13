<#
.SYNOPSIS
    PowerShell script to install Sysmon with a configurable configuration enabling logging for C2 detection events.

.DESCRIPTION
    Downloads Sysmon, creates a config to log ProcessCreate (1), NetworkConnect (3), ImageLoad (7), FileCreate (11), RegistryEvent (12/13/14), DnsQuery (22).
    Includes exclusions for known good to reduce noise (e.g., Microsoft-signed DLLs).

.EXAMPLE
    .\InstallSysmonForC2Detection.ps1 -ExcludeSignatures @('Microsoft Windows') -ExcludeImages @('C:\Windows\System32\iexplore.exe')

.PARAMETER ExcludeSignatures
    Array of signatures to exclude (e.g., @('Microsoft Windows')) for events like ImageLoad/DriverLoad.

.PARAMETER ExcludeImages
    Array of image paths to exclude (e.g., @('C:\Windows\System32\iexplore.exe')) for events like ProcessCreate/ImageLoad.

.PARAMETER ExcludeCommandLines
    Array of command lines to exclude (e.g., @('net stop')) for ProcessCreate.

.PARAMETER ExcludePorts
    Array of ports to exclude (e.g., @('80', '443')) for NetworkConnect.

.PARAMETER ExcludeRegistryKeys
    Array of registry keys to exclude (e.g., @('HKLM\Software\Microsoft\Windows\CurrentVersion\Run')) for RegistryEvent.

.PARAMETER ExcludeDomains
    Array of domains to exclude (e.g., @('microsoft.com')) for DnsQuery.

.PARAMETER HashAlgorithms
    Hash algorithms to use (default: md5,sha256,IMPHASH).

.NOTES
    Author: Robert Weber

    v2 Updates:
    Fixed Sysmon Installer for C2 Monitor Interoperability.
    Fixes: Broken FileCreate/Registry rules, DLL Sideloading blindspots, XML structure.
#>

### Example exclusions, tune for your environment ###
#Requires -RunAsAdministrator

param (
    # Reduced default exclusions to prevent blinding the monitor
    [string[]]$ExcludeImages = @('C:\Windows\System32\SearchIndexer.exe', 'C:\Windows\System32\wbem\WmiPrvSE.exe'),
    [string[]]$ExcludeDomains = @('microsoft.com', 'windowsupdate.com', 'msftncsi.com'),
    [string]$HashAlgorithms = "md5,sha256,IMPHASH"
)

$tempDir = "$env:TEMP\SysmonInstall"
if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null }

# Download Sysmon
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$tempDir\Sysmon.zip"
try {
    Write-Host "Downloading Sysmon..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -ErrorAction Stop
} catch {
    Write-Error "Download failed: $($_.Exception.Message)"
    exit
}

Expand-Archive -Path $sysmonZip -DestinationPath $tempDir -Force

$configPath = "$tempDir\sysmonconfig.xml"

$configHeader = @"
<Sysmon schemaversion="4.82">
  <HashAlgorithms>$HashAlgorithms</HashAlgorithms>
  <EventFiltering>
"@

$configFooter = @"
  </EventFiltering>
</Sysmon>
"@

# 1. PROCESS CREATE (Event 1)
# Exclude known noisy processes, but keep most for the Monitor's command-line analysis
$rulesProcess = @"
    <RuleGroup name=""ProcessCreate"" groupRelation=""or"">
      <ProcessCreate onmatch=""exclude"">
        <Image condition=""is"">C:\Windows\System32\svchost.exe</Image>
        <Image condition=""end with"">\wbem\WmiPrvSE.exe</Image>
"@
foreach ($img in $ExcludeImages) { $rulesProcess += "`n        <Image condition=""is"">$img</Image>" }
$rulesProcess += "`n      </ProcessCreate>`n    </RuleGroup>"

# 2. NETWORK CONNECT (Event 3)
# Monitor needs this for Beacon detection.
$rulesNetwork = @"
    <RuleGroup name=""NetworkConnect"" groupRelation=""or"">
      <NetworkConnect onmatch=""exclude"">
        <DestinationPort condition=""is"">53</DestinationPort> <Image condition=""image"">C:\Windows\System32\svchost.exe</Image>
      </NetworkConnect>
    </RuleGroup>
"@

# 3. IMAGE LOAD (Event 7)
$rulesImageLoad = @"
    <RuleGroup name=""ImageLoad"" groupRelation=""or"">
      <ImageLoad onmatch=""exclude"">
        <Rule groupRelation=""and"">
            <Signature condition=""contains"">Microsoft Windows</Signature>
            <SignatureStatus condition=""is"">Valid</SignatureStatus>
            </Rule>
        <ImageLoaded condition=""is"">C:\Windows\System32\ntdll.dll</ImageLoaded>
        <ImageLoaded condition=""is"">C:\Windows\System32\kernel32.dll</ImageLoaded>
        <ImageLoaded condition=""is"">C:\Windows\System32\kernelbase.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
"@

# 4. FILE CREATE (Event 11)
$rulesFileCreate = @"
    <RuleGroup name=""FileCreate"" groupRelation=""or"">
      <FileCreate onmatch=""exclude"">
        <TargetFilename condition=""end with"">.tmp</TargetFilename>
        <TargetFilename condition=""end with"">.log</TargetFilename>
        <Image condition=""is"">C:\Windows\System32\svchost.exe</Image>
      </FileCreate>
    </RuleGroup>
"@

# 5. REGISTRY (Event 12, 13, 14)
$rulesRegistry = @"
    <RuleGroup name=""RegistryEvent"" groupRelation=""or"">
      <RegistryEvent onmatch=""include"">
        <TargetObject condition=""contains"">\CurrentVersion\Run</TargetObject>
        <TargetObject condition=""contains"">\CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition=""contains"">\Services\</TargetObject>
        <TargetObject condition=""contains"">\Image File Execution Options\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
"@

# 6. DNS QUERY (Event 22)
$rulesDns = @"
    <RuleGroup name=""DnsQuery"" groupRelation=""or"">
      <DnsQuery onmatch=""exclude"">
        <QueryName condition=""end with"">.arpa</QueryName>
        <QueryName condition=""end with"">.local</QueryName>
"@
foreach ($dom in $ExcludeDomains) { $rulesDns += "`n        <QueryName condition=""end with"">$dom</QueryName>" }
$rulesDns += "`n      </DnsQuery>`n    </RuleGroup>"

# Combine
$finalConfig = $configHeader + $rulesProcess + $rulesNetwork + $rulesImageLoad + $rulesFileCreate + $rulesRegistry + $rulesDns + $configFooter

try {
    $finalConfig | Out-File -FilePath $configPath -Encoding utf8 -ErrorAction Stop
    Write-Host "Configuration generated successfully." -ForegroundColor Green
} catch {
    Write-Error "Config creation failed: $($_.Exception.Message)"
    exit
}

# Install
$sysmonExe = "$tempDir\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    Write-Host "Installing/Updating Sysmon..." -ForegroundColor Cyan
    $args = @("-i", $configPath, "-accepteula")
    if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { $args = @("-c", $configPath) }

    Start-Process -FilePath $sysmonExe -ArgumentList $args -Wait -NoNewWindow
    Write-Host "Done. Sysmon is now feeding data to the Monitor script." -ForegroundColor Green
}