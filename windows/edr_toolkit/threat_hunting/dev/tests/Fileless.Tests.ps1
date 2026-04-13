<#
.SYNOPSIS
    Pester 5 Tests for Fileless & Registry Hunting
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")
}

Describe "Fileless and Registry Hunt Modules" {

    BeforeEach {
        $script:Findings = @()
        $Quiet = $true
    }

    It "Should detect a malicious LOLBin in a Registry Run Key" {
        # MOCK: Pretend the registry has a malicious payload
        Mock Get-ItemProperty {
            return [PSCustomObject]@{
                PSObject = [PSCustomObject]@{
                    Properties = @(
                        [PSCustomObject]@{ Name = "WindowsUpdater"; Value = "powershell.exe -nop -w hidden -enc ZWNobyAiaGFja2VkIg==" }
                    )
                }
            }
        } -ParameterFilter { $Path -match "Run" }

        # MOCK: Test-Path needs to return true so the script actually checks the key
        Mock Test-Path { return $true }

        Invoke-FilelessHunt

        $script:Findings.Count | Should -BeGreaterThan 0
        $Alert = $script:Findings | Where-Object { $_.Type -eq "Suspicious Registry Key" }
        $Alert.Details | Should -Match "powershell.exe"
    }

    It "Should detect an IFEO Debugger Hijack" {
        Mock Test-Path { return $true }
        Mock Get-ChildItem {
            return @( [PSCustomObject]@{ PSPath = "HKLM:\Fake\IFEO\sethc.exe"; PSChildName = "sethc.exe" } )
        }
        Mock Get-ItemProperty {
            return [PSCustomObject]@{ Debugger = "cmd.exe" }
        }

        Invoke-AdvancedRegistryHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "IFEO Debugger Hijack" }
        $Alert.Target | Should -Be "sethc.exe"
        $Alert.Details | Should -Match "cmd.exe"
    }

    It "Should detect a hijacked Windows Service executing out of Temp" {
        Mock Get-CimInstance {
            return @( [PSCustomObject]@{ Name = "EvilSvc"; PathName = "C:\Windows\Temp\payload.exe"; StartMode = "Auto" } )
        }

        Invoke-AdvancedRegistryHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "Suspicious Service" }
        $Alert.Details | Should -Match "\\Temp"
    }
}