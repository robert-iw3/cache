<#
.SYNOPSIS
    Pester 5 Tests for Process & Injection Hunting
#>

# Load the source files into the test session
BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")
}

Describe "Invoke-ProcessHunt Module" {

    BeforeEach {
        # Reset the global findings array before every single test
        $script:Findings = @()
        # Suppress console output during tests to keep the output clean
        $Quiet = $true
    }

    It "Should detect a Hidden Process (Rootkit behavior: API mismatch)" {

        # MOCK: Standard API only sees 'explorer'
        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 100; ProcessName = "explorer" } )
        }

        # MOCK: WMI sees 'explorer' AND a hidden 'evil.exe'
        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 100; Name = "explorer.exe"; ParentProcessId = 4; CommandLine = "explorer.exe" },
                [PSCustomObject]@{ ProcessId = 666; Name = "evil.exe"; ParentProcessId = 100; CommandLine = "evil.exe -hide" }
            )
        }

        # Action
        Invoke-ProcessHunt

        # Assert
        $script:Findings.Count | Should -BeGreaterThan 0
        $Alert = $script:Findings | Where-Object { $_.Type -eq "Hidden Process" }

        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Match "PID: 666"
        $Alert.Severity | Should -Be "High"
    }

    It "Should detect Fileless Obfuscation (Encoded PowerShell)" {

        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 200; ProcessName = "powershell" } )
        }

        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 200; Name = "powershell.exe"; ParentProcessId = 100; CommandLine = "powershell.exe -enc ZWNobyAnbWFsd2FyZSc=" }
            )
        }

        Invoke-ProcessHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "Suspicious Command Line" }

        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Match "PID: 200"
        $Alert.Details | Should -Match "-enc"
    }

    It "Should ignore healthy, baseline OS processes" {

        # MOCK: A completely healthy, normal system state
        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 500; ProcessName = "svchost" } )
        }

        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 500; Name = "svchost.exe"; ParentProcessId = 100; CommandLine = "svchost.exe -k netsvcs" }
            )
        }

        Invoke-ProcessHunt

        # Assert that NO findings were generated
        $script:Findings.Count | Should -Be 0
    }
}