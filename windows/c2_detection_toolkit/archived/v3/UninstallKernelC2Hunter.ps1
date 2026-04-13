#Requires -RunAsAdministrator
logman stop "C2KernelTrace" -ets 2>&1 | Out-Null
logman delete "C2KernelTrace" -ets 2>&1 | Out-Null
pktmon stop 2>&1 | Out-Null
Write-Host "[v3.0] Kernel C2 Beacon Hunter fully uninstalled." -ForegroundColor Green