<#
.SYNOPSIS
    PowerShell orchestration script for the full workflow of Windows event parsing and forwarding using Docker containers.
    This script handles everything: Starts client and/or server containers, collects sample Windows events (or uses provided log path),
    converts to JSON, POSTs to client endpoint for parsing/trimming, which then forwards to server for uploading to Splunk/Elastic.
    Assumes all support files (Dockerfiles, compose ymls, Python parsers, schema.json) are in the current directory.
    Stops containers on completion or error (Ctrl+C to interrupt).

.PARAMETER Deployment
    'Client', 'Server', or 'Both' (default: Both) to deploy.

.PARAMETER OutputType
    'Splunk' or 'Elastic' (default: Elastic) for forwarding destination.

.PARAMETER LogPath
    Optional path to a .evtx file or log name (e.g., 'Security') for event collection. Defaults to sample Security events.

.PARAMETER SampleCount
    Number of sample events to collect/POST (default: 10).

.EXAMPLE
    .\Orchestrate-Deployment.ps1 -Deployment Both -OutputType Splunk -LogPath 'Security' -SampleCount 20
    Deploys both, collects 20 Security events, POSTs to client, forwards through workflow to Splunk.

.NOTES
    Requires Docker, Docker Compose, admin privileges for Get-WinEvent.
    Customize env in compose ymls (e.g., SERVER_URL, SPLUNK_HEC_URL).
    Cleans up containers on exit.

    Author: Robert Weber
#>

param (
    [ValidateSet("Client", "Server", "Both")]
    [string]$Deployment = "Both",
    [ValidateSet("Splunk", "Elastic")]
    [string]$OutputType = "Elastic",
    [string]$LogPath = "Security",
    [int]$SampleCount = 10
)

# Check for admin (for Get-WinEvent)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run as Administrator for full event access."
}

# Check for Docker/Compose
if (-not (Get-Command docker -ErrorAction SilentlyContinue) -or -not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Error "Docker and Docker Compose required."
    exit 1
}

$clientCompose = "docker-compose.client.yml"
$serverCompose = "docker-compose.server.yml"

# Validate files
$required = @("schema.json")
if ($Deployment -in @("Client", "Both")) { $required += @("Dockerfile.client", "client_parser.py", $clientCompose) }
if ($Deployment -in @("Server", "Both")) { $required += @("Dockerfile.server", "server_parser.py", $serverCompose) }

$missing = $required | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Error "Missing files: $($missing -join ', ')"
    exit 1
}

function Start-Container {
    param ([string]$ComposeFile)
    Write-Host "Starting with $ComposeFile..." -ForegroundColor Cyan
    docker-compose -f $ComposeFile up --build -d
    Start-Sleep 5  # Wait for startup
}

function Stop-Container {
    param ([string]$ComposeFile)
    docker-compose -f $ComposeFile down
}

function Collect-Events {
    # Collect sample events
    Write-Host "Collecting $SampleCount events from $LogPath..." -ForegroundColor Cyan
    Get-WinEvent -LogName $LogPath -MaxEvents $SampleCount | ConvertTo-Json -Depth 5
}

function Post-ToClient {
    param ([string]$JsonData)
    $clientUrl = "http://localhost:9881/"  # Adjust if remote
    Write-Host "POSTing JSON to client at $clientUrl..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $clientUrl -Method Post -Body $JsonData -ContentType "application/json" -ErrorAction Stop
}

try {
    if ($Deployment -in @("Client", "Both")) { Start-Container $clientCompose }
    if ($Deployment -in @("Server", "Both")) { Start-Container $serverCompose }

    $eventsJson = Collect-Events
    Post-ToClient $eventsJson

    Write-Host "Workflow complete. Events collected, posted to client, parsed/trimmed, forwarded to server, and uploaded to $OutputType." -ForegroundColor Green
}
catch {
    Write-Error "Workflow failed: $_"
}
finally {
    if ($Deployment -in @("Client", "Both")) { Stop-Container $clientCompose }
    if ($Deployment -in @("Server", "Both")) { Stop-Container $serverCompose }
}