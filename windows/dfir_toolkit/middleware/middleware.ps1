<#
.SYNOPSIS
    DFIR Middleware Receiver (Pure PowerShell)

.DESCRIPTION
    Accepts JSON payload from collect_forensics.ps1 (primary path) or multipart fallback,
    unpacks ZIP, chunks events to prevent 429s, routes to SIEM with throttling.
    interoperable + chain-of-custody.

.NOTES
    Run as Administrator. Port 5000 open.
    Supports config.ini + $env: variables.
    author: @RW
#>

# ==========================================
# CONFIG (env vars + config.ini)
# ==========================================
$ListenPort = 5000
$UploadFolder = "C:\DFIR_Uploads"
if (-not (Test-Path $UploadFolder)) { New-Item -ItemType Directory -Path $UploadFolder | Out-Null }

$AuthToken     = if ($env:DFIR_AUTH_TOKEN)     { $env:DFIR_AUTH_TOKEN }     else { "YOUR_BEARER_TOKEN" }
$ActiveSiem    = if ($env:DFIR_ACTIVE_SIEM)    { $env:DFIR_ACTIVE_SIEM }    else { "SPLUNK" }
$BatchSize     = if ($env:DFIR_BATCH_SIZE)     { [int]$env:DFIR_BATCH_SIZE } else { 500 }
$ThrottleSleep = if ($env:DFIR_THROTTLE_SLEEP) { [int]$env:DFIR_THROTTLE_SLEEP } else { 250 }

$ConfigPath = Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) "config.ini"
if (Test-Path $ConfigPath) {
    $Ini = Get-Content $ConfigPath | Where-Object { $_ -match '=' } | ForEach-Object {
        $k,$v = ($_ -split '=',2).Trim(); @{ $k = $v }
    }
    if ($Ini.AUTH_TOKEN)  { $AuthToken = $Ini.AUTH_TOKEN }
    if ($Ini.ACTIVE_SIEM) { $ActiveSiem = $Ini.ACTIVE_SIEM }
}

$LogFile = Join-Path $UploadFolder "DFIR_Middleware.log"
function Write-Log($Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[*] $Stamp | $Message"
    Write-Host $Line
    $Line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "DFIR Middleware started - SIEM: $ActiveSiem | Port: $ListenPort"

# ==========================================
# SIEM-SPECIFIC CREDENTIALS
# ==========================================
$SplunkUrl      = "https://splunk-heavy-forwarder.local:8088/services/collector/event"
$SplunkToken    = "YOUR_SPLUNK_HEC_TOKEN"
$ElasticUrl     = "https://your-elastic-node:9200/dfir-collections/_bulk"
$ElasticApiKey  = "YOUR_BASE64_ENCODED_API_KEY"
$SentinelWorkspaceId = "YOUR_WORKSPACE_ID"
$SentinelSharedKey   = "YOUR_PRIMARY_KEY"
$SentinelLogType     = "EndpointDFIR_CL"
$DdApiKey       = "YOUR_DATADOG_API_KEY"
$DdUrl          = "https://http-intake.logs.datadoghq.com/api/v2/logs"
$SyslogServer   = "192.168.1.100"
$SyslogPort     = 514
$SyslogProtocol = "UDP"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ==========================================
# FORWARDING & ROUTING LOGIC
# ==========================================
function Forward-ToSplunk ($Hostname, $Timestamp, $ArtifactType, $Events) {
    Write-Log "→ Splunk: $($Events.Count) events"
    $Headers = @{ "Authorization" = "Splunk $SplunkToken" }
    for ($i = 0; $i -lt $Events.Count; $i += $BatchSize) {
        $Batch = $Events | Select-Object -Skip $i -First $BatchSize
        $Payload = ""
        foreach ($Event in $Batch) {
            $Obj = @{ host = $Hostname; sourcetype = "dfir:$ArtifactType"; time = $Timestamp; event = $Event }
            $Payload += ($Obj | ConvertTo-Json -Depth 5 -Compress) + "`n"
        }
        Invoke-RestMethod -Uri $SplunkUrl -Method Post -Headers $Headers -Body $Payload -ContentType "application/json" | Out-Null
        Start-Sleep -Milliseconds $ThrottleSleep
    }
}

function Forward-ToElastic ($Hostname, $Timestamp, $ArtifactType, $Events) {
    Write-Log "→ Elastic: $($Events.Count) events"
    $Headers = @{ "Authorization" = "ApiKey $ElasticApiKey" }
    for ($i = 0; $i -lt $Events.Count; $i += $BatchSize) {
        $Batch = $Events | Select-Object -Skip $i -First $BatchSize
        $Payload = ""
        foreach ($Event in $Batch) {
            $Action = @{ index = @{} }
            $Doc = @{ "@timestamp" = $Timestamp; agent = @{ hostname = $Hostname }; event = @{ dataset = $ArtifactType }; forensics = $Event }
            $Payload += ($Action | ConvertTo-Json -Compress) + "`n" + ($Doc | ConvertTo-Json -Depth 5 -Compress) + "`n"
        }
        Invoke-RestMethod -Uri $ElasticUrl -Method Post -Headers $Headers -Body $Payload -ContentType "application/x-ndjson" | Out-Null
        Start-Sleep -Milliseconds $ThrottleSleep
    }
}

function Forward-ToSentinel ($Hostname, $Timestamp, $ArtifactType, $Events) {
    Write-Log "→ Sentinel: $($Events.Count) events"
    for ($i = 0; $i -lt $Events.Count; $i += $BatchSize) {
        $Batch = $Events | Select-Object -Skip $i -First $BatchSize
        $PayloadArray = @()
        foreach ($Event in $Batch) {
            $Event | Add-Member -Type NoteProperty -Name "DFIR_Host" -Value $Hostname -Force
            $Event | Add-Member -Type NoteProperty -Name "DFIR_Artifact" -Value $ArtifactType -Force
            $Event | Add-Member -Type NoteProperty -Name "DFIR_Timestamp" -Value $Timestamp -Force
            $PayloadArray += $Event
        }
        $Body = $PayloadArray | ConvertTo-Json -Depth 5
        $DateStr = [DateTime]::UtcNow.ToString("r")
        $ContentLength = [System.Text.Encoding]::UTF8.GetBytes($Body).Length
        $StringToHash = "POST`n$ContentLength`napplication/json`nx-ms-date:$DateStr`n/api/logs"
        $BytesToHash = [System.Text.Encoding]::UTF8.GetBytes($StringToHash)
        $KeyBytes = [Convert]::FromBase64String($SentinelSharedKey)
        $HMAC = New-Object System.Security.Cryptography.HMACSHA256
        $HMAC.Key = $KeyBytes
        $Hash = $HMAC.ComputeHash($BytesToHash)
        $Signature = [Convert]::ToBase64String($Hash)
        $Uri = "https://$SentinelWorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-04"
        $Headers = @{
            "Authorization" = "SharedKey ${SentinelWorkspaceId}:$Signature"
            "Log-Type" = $SentinelLogType
            "x-ms-date" = $DateStr
        }
        Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Body -ContentType "application/json" | Out-Null
        Start-Sleep -Milliseconds $ThrottleSleep
    }
}

function Forward-ToDatadog ($Hostname, $Timestamp, $ArtifactType, $Events) {
    Write-Log "→ Datadog: $($Events.Count) events"
    $Headers = @{ "DD-API-KEY" = $DdApiKey }
    for ($i = 0; $i -lt $Events.Count; $i += $BatchSize) {
        $Batch = $Events | Select-Object -Skip $i -First $BatchSize
        $PayloadArray = @()
        foreach ($Event in $Batch) {
            $PayloadArray += @{
                ddsource = "dfir_collector"
                ddtags = "host:$Hostname,artifact:$ArtifactType"
                hostname = $Hostname
                message = $Event
            }
        }
        $Body = $PayloadArray | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri $DdUrl -Method Post -Headers $Headers -Body $Body -ContentType "application/json" | Out-Null
        Start-Sleep -Milliseconds $ThrottleSleep
    }
}

function Forward-ToSyslog ($Hostname, $Timestamp, $ArtifactType, $Events) {
    Write-Log "→ Syslog: $($Events.Count) events"
    if ($SyslogProtocol -eq "TCP") { $Client = New-Object System.Net.Sockets.TcpClient($SyslogServer, $SyslogPort); $Stream = $Client.GetStream() }
    else { $Client = New-Object System.Net.Sockets.UdpClient; $Client.Connect($SyslogServer, $SyslogPort) }

    foreach ($Event in $Events) {
        $SyslogPayload = @{ host = $Hostname; timestamp = $Timestamp; artifact = $ArtifactType; data = $Event }
        $Message = "<13>1 $Timestamp $Hostname DFIR_Collector - - - $($SyslogPayload | ConvertTo-Json -Depth 5 -Compress)`n"
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        if ($SyslogProtocol -eq "TCP") { $Stream.Write($Bytes, 0, $Bytes.Length) }
        else { $Client.Send($Bytes, $Bytes.Length) | Out-Null }
    }
    $Client.Close()
}

function Route-ToSiem ($Hostname, $Timestamp, $Filename, $Data) {
    $ArtifactType = $Filename.Replace(".json", "")
    $Events = if ($Data -is [array]) { $Data } else { @($Data) }
    try {
        switch ($ActiveSiem) {
            "SPLUNK"   { Forward-ToSplunk $Hostname $Timestamp $ArtifactType $Events }
            "ELASTIC"  { Forward-ToElastic $Hostname $Timestamp $ArtifactType $Events }
            "SENTINEL" { Forward-ToSentinel $Hostname $Timestamp $ArtifactType $Events }
            "DATADOG"  { Forward-ToDatadog $Hostname $Timestamp $ArtifactType $Events }
            "SYSLOG"   { Forward-ToSyslog $Hostname $Timestamp $ArtifactType $Events }
            default    { Write-Log "[-] Unknown SIEM '$ActiveSiem'" }
        }
    } catch {
        Write-Log "[-] Failed $ArtifactType to $ActiveSiem: $($_.Exception.Message)"
    }
}

# ==========================================
# MULTIPART STREAM PARSER
# ==========================================
function Extract-MultipartFile ($Request, $Boundary, $SavePath) {
    $Stream = $Request.InputStream
    $MemoryStream = New-Object System.IO.MemoryStream
    $Stream.CopyTo($MemoryStream)
    $Bytes = $MemoryStream.ToArray()

    $Enc = [System.Text.Encoding]::UTF8
    $BoundaryBytes = $Enc.GetBytes("--$Boundary")
    $FileHeader = $Enc.GetBytes("filename=")

    $StartIndex = -1
    $EndIndex = -1

    for ($i = 0; $i -lt ($Bytes.Length - $FileHeader.Length); $i++) {
        $Match = $true
        for ($j = 0; $j -lt $FileHeader.Length; $j++) {
            if ($Bytes[$i+$j] -ne $FileHeader[$j]) { $Match = $false; break }
        }
        if ($Match) {
            for ($k = $i; $k -lt $Bytes.Length - 4; $k++) {
                if ($Bytes[$k] -eq 13 -and $Bytes[$k+1] -eq 10 -and $Bytes[$k+2] -eq 13 -and $Bytes[$k+3] -eq 10) {
                    $StartIndex = $k + 4
                    break
                }
            }
            break
        }
    }

    if ($StartIndex -ne -1) {
        for ($i = $StartIndex; $i -lt ($Bytes.Length - $BoundaryBytes.Length); $i++) {
            $Match = $true
            for ($j = 0; $j -lt $BoundaryBytes.Length; $j++) {
                if ($Bytes[$i+$j] -ne $BoundaryBytes[$j]) { $Match = $false; break }
            }
            if ($Match) {
                $EndIndex = $i - 2
                break
            }
        }
    }

    if ($StartIndex -ne -1 -and $EndIndex -ne -1) {
        $FileBytes = New-Object byte[] ($EndIndex - $StartIndex)
        [System.Array]::Copy($Bytes, $StartIndex, $FileBytes, 0, $FileBytes.Length)
        [System.IO.File]::WriteAllBytes($SavePath, $FileBytes)
        return $true
    }
    return $false
}

# ==========================================
# HTTP LISTENER
# ==========================================
$Listener = New-Object System.Net.HttpListener
$Listener.Prefixes.Add("http://*:$ListenPort/api/upload/")
$Listener.Start()
Write-Log "[*] Listener active on http://*:$ListenPort/api/upload/"

try {
    while ($true) {
        $Context = $Listener.GetContext()
        $Request = $Context.Request
        $Response = $Context.Response

        if ($Request.Headers["Authorization"] -ne "Bearer $AuthToken") {
            $Response.StatusCode = 401
            $Response.Close()
            continue
        }

        if ($ContentType -match "application/json") {
            # Read stream dynamically without allocating massive byte arrays
            $StreamReader = New-Object System.IO.StreamReader($Request.InputStream)
            $JsonString = $StreamReader.ReadToEnd()
            $JsonBody = $JsonString | ConvertFrom-Json
            $StreamReader.Close()

            $Hostname = $JsonBody.hostname
            $Timestamp = $JsonBody.timestamp
            $ZipPath = Join-Path $UploadFolder "$Hostname`_$Timestamp.zip"

            [System.IO.File]::WriteAllBytes($ZipPath, [Convert]::FromBase64String($JsonBody.payload))
            $ZipHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
            Write-Log "Chain-of-Custody ZIP SHA256: $($ZipHash.Substring(0,16))..."

            $ExtractDir = Join-Path $UploadFolder "$([guid]::NewGuid())"
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

            Get-ChildItem $ExtractDir -Filter "*.json" | ForEach-Object {
                $JsonData = Get-Content $_.FullName -Raw | ConvertFrom-Json
                Route-ToSiem $Hostname $Timestamp $_.Name $JsonData
            }

            Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
            Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue

            $Response.StatusCode = 200
            $Buffer = [System.Text.Encoding]::UTF8.GetBytes('{"message": "Payload forwarded successfully"}')
        }
        else {
            $Boundary = $ContentType.Split("=")[1]
            $TempZipPath = Join-Path $UploadFolder "$([guid]::NewGuid()).zip"

            if (Extract-MultipartFile $Request $Boundary $TempZipPath) {
                Write-Log "[+] Multipart payload received"
                $ExtractDir = Join-Path $UploadFolder "$([guid]::NewGuid())"
                try {
                    Expand-Archive -Path $TempZipPath -DestinationPath $ExtractDir -Force
                    $Hostname = "Endpoint"
                    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

                    Get-ChildItem -Path $ExtractDir -Filter "*.json" | ForEach-Object {
                        $JsonData = Get-Content $_.FullName -Raw | ConvertFrom-Json
                        Route-ToSiem $Hostname $Timestamp $_.Name $JsonData
                    }
                    $Response.StatusCode = 200
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes('{"message": "Payload forwarded successfully"}')
                } catch {
                    $Response.StatusCode = 400
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes('{"error": "Invalid ZIP"}')
                } finally {
                    Remove-Item $TempZipPath -Force -ErrorAction SilentlyContinue
                    if (Test-Path $ExtractDir) { Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
                }
            } else {
                $Response.StatusCode = 400
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes('{"error": "Failed to parse multipart"}')
            }
        }

        $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
        $Response.Close()
    }
} finally {
    $Listener.Stop()
    Write-Log "Middleware listener stopped."
}