<#
.SYNOPSIS
    Pester 5 Tests for Drivers and Tasks
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "04_Drivers_And_Tasks.ps1")
}

Describe "Driver and Task Hunt Modules" {

    BeforeEach {
        $script:Findings = @()
        $Quiet = $true
    }

    It "Should detect a known vulnerable kernel driver (BYOVD)" {
        Mock Get-WmiObject {
            return @( [PSCustomObject]@{ Name = "RTCore64.sys"; DisplayName = "Micro-Star MSI Afterburner"; Path = "C:\Windows\System32\drivers\RTCore64.sys" } )
        }
        Mock Get-AuthenticodeSignature {
            return [PSCustomObject]@{ Status = "Valid" }
        }

        # Run without live API updates to test the hardcoded list
        $AutoUpdateDrivers = $false
        Invoke-DriverHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "Suspicious Kernel Driver" }
        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Match "RTCore64"
        $Alert.Severity | Should -Be "Critical"
    }

    It "Should detect a Scheduled Task executing PowerShell" {
        Mock Get-ScheduledTask {
            return @(
                [PSCustomObject]@{
                    TaskName = "PersistenceTask"
                    TaskPath = "\"
                    State = "Ready"
                    Actions = @( [PSCustomObject]@{ Execute = "powershell.exe"; Arguments = "-WindowStyle Hidden -c calc.exe" } )
                    Triggers = @( [PSCustomObject]@{ GetType = { return [PSCustomObject]@{ Name = "LogonTrigger" } } } )
                }
            )
        }

        Invoke-ScheduledTaskHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "Suspicious Scheduled Task" }
        $Alert.Details | Should -Match "powershell.exe"
    }
}