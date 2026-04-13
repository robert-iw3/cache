$Target = "SRV-WEB-01"

$HuntArgs = @(
    "-ScanProcesses",
    "-ScanFileless",
    "-ScanInjection",
    "-QuickMode",
    "-ReportPath", "C:\Windows\Temp",
    "-OutputFormat", "JSON",
    "-Quiet" # Highly recommended for WinRM to keep the network stream clean
)

Write-Host "Deploying EDR Toolkit to $Target via WinRM..."
Invoke-Command -ComputerName $Target -FilePath ".\Release\EDR_Toolkit_Deploy.ps1" -ArgumentList $HuntArgs