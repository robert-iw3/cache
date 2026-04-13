<#
.SYNOPSIS
    PowerShell script to install and configure a Cribl Stream Worker Node on a Windows Event Collector (WEC) server.

.DESCRIPTION
    This script downloads Cribl Stream, installs it, enables HTTPS with self-signed cert, configures it to ingest ForwardedEvents logs,
    applies basic transformations, and forwards to Splunk or Elastic. It also sets up monitoring for archived .evtx files and parsed Docker JSON logs.

.PARAMETER OutputType
    'Splunk' or 'Elastic' for the destination.

.PARAMETER SplunkHecUrl
    Splunk HEC URL (e.g., "https://your-splunk:8088/services/collector/event/1.0").

.PARAMETER SplunkHecToken
    Splunk HEC token.

.PARAMETER ElasticUrl
    Elastic URL (e.g., "https://your-elastic:9200").

.PARAMETER ElasticIndex
    Elastic index name (default: "logs").

.PARAMETER ArchivePath
    Path for monitoring archived .evtx files (default: "D:\Logs").

.PARAMETER DockerJsonPath
    Path for monitoring parsed JSON files from Docker (default: "D:\Logs\parsed"). Ensure Docker mounts/output to this path.

.PARAMETER ElasticUsername
    Username for Elastic basic authentication (optional for Elastic).

.PARAMETER ElasticPassword
    Password for Elastic basic authentication (optional for Elastic).

.PARAMETER ElasticApiKey
    API Key for Elastic authentication (alternative to username/password).

.PARAMETER ElasticCaCertPath
    Optional path to CA cert for Elastic HTTPS verification (PEM format). If not provided, rejects unauthorized certs (false for self-signed).

.EXAMPLE
    .\Install-CriblWorker.ps1 -OutputType Elastic -ElasticUrl "https://elastic:9200" -ElasticIndex "winlogs" -ElasticUsername "elastic" -ElasticPassword "yourpass" -ArchivePath "D:\Logs" -DockerJsonPath "D:\Logs\parsed" -ElasticCaCertPath "C:\certs\elastic-ca.pem"

.NOTES
    Assumes Cribl API endpoints and wineventlog source are available post-install.
    If OpenSSL is not installed, the script logs a warning and falls back to certutil
    (no syntax error, but manual PEM conversion may be needed post-run).

    Author: Robert Weber
#>

param (
    [ValidateSet("Splunk", "Elastic")]
    [string]$OutputType = "Elastic",
    [string]$SplunkHecUrl = "",
    [string]$SplunkHecToken = "",
    [string]$ElasticUrl = "https://localhost:9200",
    [string]$ElasticIndex = "logs",
    [string]$ArchivePath = "D:\Logs",
    [string]$DockerJsonPath = "D:\Logs\parsed",
    [string]$ElasticUsername = "",
    [string]$ElasticPassword = "",
    [string]$ElasticApiKey = "",
    [string]$ElasticCaCertPath = ""
)

# ────────────────────────────────────────────────────────────────────────────────
#  Global Error Handling & Logging Setup
# ────────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$logFile = "$env:TEMP\CriblInstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    Write-Host $logLine -ForegroundColor $(if($Level -eq "ERROR"){"Red"}elseif($Level -eq "WARN"){"Yellow"}else{"White"})
    Add-Content -Path $logFile -Value $logLine
}

function Cleanup {
    param([string]$Reason)
    Log "Cleaning up due to: $Reason" "WARN"
    try { Stop-Service -Name "cribl" -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item "$env:TEMP\cribl-stream.msi" -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item "$env:TEMP\temp.pfx" -Force -ErrorAction SilentlyContinue } catch {}
}

trap {
    Log "CRITICAL FAILURE: $($_.Exception.Message)" "ERROR"
    Log $_.ScriptStackTrace "ERROR"
    Cleanup "Critical error"
    exit 1
}

# Check admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log "Script must run as Administrator." "ERROR"
    exit 1
}

# Validate params
if ($OutputType -eq "Splunk" -and ($SplunkHecUrl -eq "" -or $SplunkHecToken -eq "")) {
    Log "For Splunk, both -SplunkHecUrl and -SplunkHecToken are required." "ERROR"
    exit 1
}

Log "Starting Cribl Stream Worker Node installation on WEC server" "INFO"

# ────────────────────────────────────────────────────────────────────────────────
#  Download Cribl Stream
# ────────────────────────────────────────────────────────────────────────────────
try {
    $downloadUrl = "https://cribl.io/dl/latest-x64.msi"
    $msiPath = "$env:TEMP\cribl-stream.msi"
    Log "Downloading Cribl Stream from $downloadUrl" "INFO"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
}
catch {
    Log "Failed to download Cribl Stream: $($_.Exception.Message)" "ERROR"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Install Cribl Stream
# ────────────────────────────────────────────────────────────────────────────────
try {
    Log "Installing Cribl Stream (silent mode)..." "INFO"
    $installArgs = "/i `"$msiPath`" /quiet /norestart /l*v `"$env:TEMP\CriblInstall.log`""
    $process = Start-Process msiexec -ArgumentList $installArgs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "msiexec failed with exit code $($process.ExitCode). Check $env:TEMP\CriblInstall.log"
    }
}
catch {
    Log "Installation failed: $($_.Exception.Message)" "ERROR"
    Cleanup "Installation failure"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Generate Self-Signed Certificate for HTTPS
# ────────────────────────────────────────────────────────────────────────────────
try {
    Log "Generating self-signed certificate for HTTPS..." "INFO"
    $certPath = "C:\Program Files\Cribl\cert.pem"
    $keyPath = "C:\Program Files\Cribl\key.pem"
    $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(5) -ErrorAction Stop

    Export-Certificate -Cert $cert -FilePath $certPath -Type CERT -ErrorAction Stop
    $pfxPath = "$env:TEMP\temp.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -ErrorAction Stop

    # Convert PFX to PEM key (requires OpenSSL installed or use certutil fallback)
    if (Test-Path "C:\Program Files\OpenSSL-Win64\bin\openssl.exe") {
        & "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in $pfxPath -nocerts -out $keyPath -nodes -passin pass:P@ssw0rd123! 2>$null
    } else {
        Log "OpenSSL not found. Using certutil fallback for key export (less secure)" "WARN"
        certutil -exportpfx -p "P@ssw0rd123!" $cert.Thumbprint $pfxPath
        # Note: Manual PEM conversion needed if OpenSSL missing
        Log "Manual PEM key conversion required if OpenSSL not installed." "WARN"
    }
    Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
}
catch {
    Log "Certificate generation failed: $($_.Exception.Message)" "ERROR"
    Cleanup "Certificate failure"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Enable HTTPS in Cribl configuration
# ────────────────────────────────────────────────────────────────────────────────
try {
    $criblYmlPath = "C:\Program Files\Cribl\default\cribl\local\_system\cribl.yml"
    if (-not (Test-Path $criblYmlPath)) {
        New-Item -Path $criblYmlPath -ItemType File -Force | Out-Null
    }

    $criblYmlContent = @"
server:
  http:
    enabled: false
  https:
    enabled: true
    cert: $certPath
    key: $keyPath
    port: 9000
"@
    Set-Content -Path $criblYmlPath -Value $criblYmlContent -ErrorAction Stop
    Log "HTTPS enabled in cribl.yml" "INFO"
}
catch {
    Log "Failed to configure HTTPS: $($_.Exception.Message)" "ERROR"
    Cleanup "HTTPS config failure"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Restart Cribl Service
# ────────────────────────────────────────────────────────────────────────────────
try {
    Log "Starting/Restarting Cribl service..." "INFO"
    Set-Service -Name "cribl" -StartupType Automatic -ErrorAction Stop
    Restart-Service -Name "cribl" -Force -ErrorAction Stop
    Start-Sleep -Seconds 45  # Give time for API to become available
}
catch {
    Log "Failed to start/restart Cribl service: $($_.Exception.Message)" "ERROR"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Configure Cribl via HTTPS API
# ────────────────────────────────────────────────────────────────────────────────
try {
    Log "Configuring Cribl via API[](https://localhost:9000)..." "INFO"

    # Trust self-signed cert for this session
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    $apiBase = "https://localhost:9000/api/v1"
    $headers = @{
        "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:admin"))
        "Content-Type" = "application/json"
    }

    # Source 1: Live ForwardedEvents
    $liveSourceBody = @{
        id = "forwarded_events_live"
        type = "wineventlog"
        config = @{
            logs = @("Microsoft-Windows-ForwardedEvents/Operational")
        }
    } | ConvertTo-Json -Depth 5 -Compress

    Invoke-RestMethod -Uri "$apiBase/m/default/sources" -Method Post -Headers $headers -Body $liveSourceBody -ErrorAction Stop

    # Source 2: Archived .evtx files
    $archiveSourceBody = @{
        id = "forwarded_events_archives"
        type = "file"
        config = @{
            path = "$ArchivePath\*"
            fileFilter = "*.evtx"
            recursive = $true
        }
    } | ConvertTo-Json -Depth 5 -Compress

    Invoke-RestMethod -Uri "$apiBase/m/default/sources" -Method Post -Headers $headers -Body $archiveSourceBody -ErrorAction Stop

    # Source 3: Docker parsed JSON files
    $dockerJsonSourceBody = @{
        id = "docker_parsed_json"
        type = "file"
        config = @{
            path = "$DockerJsonPath\*"
            fileFilter = "*.json"
            recursive = $true
        }
    } | ConvertTo-Json -Depth 5 -Compress

    Invoke-RestMethod -Uri "$apiBase/m/default/sources" -Method Post -Headers $headers -Body $dockerJsonSourceBody -ErrorAction Stop

    # Pipeline: Basic transformation (common to all sources)
    $pipelineBody = @{
        id = "wef_transform"
        conf = @{
            functions = @(
                @{ id = "parse"; type = "eval"; conf = @{ expression = "JSON.parse(_raw)" } },
                @{ id = "trim"; type = "drop_fields"; conf = @{ fields = @("EventData.RawData") } },
                @{ id = "json_out"; type = "eval"; conf = @{ expression = "_raw = JSON.stringify(event)" } }
            )
        }
    } | ConvertTo-Json -Depth 5 -Compress

    Invoke-RestMethod -Uri "$apiBase/m/default/pipelines" -Method Post -Headers $headers -Body $pipelineBody -ErrorAction Stop

    # Destination
    if ($OutputType -eq "Splunk") {
        $destBody = @{
            id = "splunk_dest"
            type = "splunk"
            config = @{
                hec_url = $SplunkHecUrl
                hec_token = $SplunkHecToken
                index = "main"
            }
        } | ConvertTo-Json -Depth 5 -Compress
    } else {
        $authConfig = @{
            auth = @{
                type = if ($ElasticApiKey -ne "") { "api_key" } elseif ($ElasticUsername -ne "" -and $ElasticPassword -ne "") { "basic" } else { "none" }
                username = $ElasticUsername
                password = $ElasticPassword
                api_key = $ElasticApiKey
            }
        }
        $tlsConfig = @{
            tlsEnabled = $true
            rejectUnauthorized = if ($ElasticCaCertPath -ne "") { $true } else { $false }
        }
        if ($ElasticCaCertPath -ne "") {
            $tlsConfig.caCert = (Get-Content $ElasticCaCertPath -Raw) -replace "`n", "\n"
        }

        $destBody = @{
            id = "elastic_dest"
            type = "elasticsearch"
            config = @{
                hosts = @($ElasticUrl)
                index = $ElasticIndex
            } + $authConfig + $tlsConfig
        } | ConvertTo-Json -Depth 5 -Compress
    }

    Invoke-RestMethod -Uri "$apiBase/m/default/destinations" -Method Post -Headers $headers -Body $destBody -ErrorAction Stop

    # Route: All sources → Pipeline → Destination
    $routeBody = @{
        id = "wef_to_dest"
        expression = "true"
        pipeline = "wef_transform"
        output = if ($OutputType -eq "Splunk") { "splunk_dest" } else { "elastic_dest" }
    } | ConvertTo-Json -Depth 5 -Compress

    Invoke-RestMethod -Uri "$apiBase/m/default/routes" -Method Post -Headers $headers -Body $routeBody -ErrorAction Stop

    # Commit & Deploy
    Invoke-RestMethod -Uri "$apiBase/m/default/commit" -Method Post -Headers $headers -Body '{"message":"WEC Worker Config"}' -ErrorAction Stop
    Invoke-RestMethod -Uri "$apiBase/m/default/deploy" -Method Post -Headers $headers -ErrorAction Stop

    Log "Cribl Worker Node successfully configured with HTTPS" "INFO"
}
catch {
    Log "API configuration failed: $($_.Exception.Message)" "ERROR"
    Cleanup "API configuration failure"
    exit 1
}

Log "Installation and configuration complete." "INFO"
Log "Access Cribl UI at: https://localhost:9000 (admin/admin)" "INFO"
Log "Monitoring live ForwardedEvents, archived .evtx ($ArchivePath), and Docker JSON ($DockerJsonPath)" "INFO"
Log "Output destination: $OutputType" "INFO"
Log "Full log saved to: $logFile" "INFO"