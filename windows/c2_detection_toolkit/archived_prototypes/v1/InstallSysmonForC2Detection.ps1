#Requires -RunAsAdministrator

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
#>

### Example exclusions, tune for your environment ###
param (
    [string[]]$ExcludeSignatures = @('Microsoft Windows', 'Microsoft Corporation'),
    [string[]]$ExcludeImages = @('C:\Windows\System32\svchost.exe', 'C:\Windows\System32\SearchIndexer.exe', 'C:\Windows\explorer.exe', 'C:\Windows\System32\wbem\WmiPrvSE.exe'),
    [string[]]$ExcludeCommandLines = @(),
    [string[]]$ExcludePorts = @(),
    [string[]]$ExcludeRegistryKeys = @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer'),
    [string[]]$ExcludeDomains = @('microsoft.com', 'windowsupdate.com', 'msftncsi.com'),
    [string]$HashAlgorithms = "md5,sha256,IMPHASH"
)

$tempDir = "$env:TEMP\SysmonInstall"
if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null }

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$tempDir\Sysmon.zip"
try {
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -ErrorAction Stop
} catch {
    Write-Error "Download failed: $($_.Exception.Message)"
    exit
}

Expand-Archive -Path $sysmonZip -DestinationPath $tempDir -Force

$configPath = "$tempDir\sysmonconfig.xml"

# Build dynamic config content with exclusions
$configContent = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>{0}</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
'@ -f $HashAlgorithms

# Add exclusions for ProcessCreate
foreach ($image in $ExcludeImages) {
    $configContent += "        <Image condition=`"is`">$image</Image>`n"
}
foreach ($cmd in $ExcludeCommandLines) {
    $configContent += "        <CommandLine condition=`"contains`">$cmd</CommandLine>`n"
}
$configContent += '      </ProcessCreate>'
$configContent += '    </RuleGroup>'

$configContent += @'
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
'@

# Add exclusions for NetworkConnect
foreach ($port in $ExcludePorts) {
    $configContent += "        <DestinationPort condition=`"is`">$port</DestinationPort>`n"
}
$configContent += '      </NetworkConnect>'
$configContent += '    </RuleGroup>'

$configContent += @'
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="exclude">
'@

# Add exclusions for ImageLoad
foreach ($sig in $ExcludeSignatures) {
    $configContent += "        <Signature condition=`"contains`">$sig</Signature>`n"
}
foreach ($image in $ExcludeImages) {
    $configContent += "        <ImageLoaded condition=`"is`">$image</ImageLoaded>`n"
}
$configContent += '      </ImageLoad>'
$configContent += '    </RuleGroup>'

$configContent += @'
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="exclude">
'@

# Add exclusions for RegistryEvent
foreach ($key in $ExcludeRegistryKeys) {
    $configContent += "        <TargetObject condition=`"begin with`">$key</TargetObject>`n"
}
$configContent += '      </RegistryEvent>'
$configContent += '    </RuleGroup>'

$configContent += @'
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
'@

# Add exclusions for DnsQuery
foreach ($domain in $ExcludeDomains) {
    $configContent += "        <QueryName condition=`"end with`">$domain</QueryName>`n"
}
$configContent += '      </DnsQuery>'
$configContent += '    </RuleGroup>'

$configContent += @'
  </EventFiltering>
</Sysmon>
'@

try {
    $configContent | Out-File -FilePath $configPath -Encoding utf8 -ErrorAction Stop
} catch {
    Write-Error "Config creation failed: $($_.Exception.Message)"
    exit
}

$sysmonExe = "$tempDir\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    try {
        $sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
        if ($sysmonService) {
            & $sysmonExe -c $configPath
            Write-Output "Sysmon configuration updated with custom exclusions."
        } else {
            & $sysmonExe -i $configPath -accepteula
            Write-Output "Sysmon installed with custom configuration."
        }
    } catch {
        Write-Error "Install/update failed: $($_.Exception.Message)"
        exit
    }
} else {
    Write-Error "Sysmon exe not found."
    exit
}

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "Installation complete. Sysmon logging enabled for C2 detection events with noise reduction exclusions."