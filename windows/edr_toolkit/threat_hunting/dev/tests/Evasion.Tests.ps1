<#
.SYNOPSIS
    Pester 5 Tests for ETW, AMSI, BITS, and COM Hijacking
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "03_BITS_COM_ETW_AMSI.ps1")
}

Describe "Defense Evasion & Tampering Modules" {

    BeforeEach {
        $script:Findings = @()
        $Quiet = $true
    }

    It "Should trigger a CRITICAL alert if AMSI Providers are wiped (Count = 0)" {
        Mock Test-Path { return $true }

        # MOCK: Return an empty array to simulate an attacker deleting the AMSI keys
        Mock Get-ChildItem { return @() } -ParameterFilter { $Path -match "AMSI\\Providers" }
        Mock Get-ItemProperty { return [PSCustomObject]@{ AmsiEnable = 1 } }

        Invoke-ETWAMSITamperHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "AMSI Tampering" }
        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Severity | Should -Be "Critical"
        $Alert.Details | Should -Match "0 providers"
    }

    It "Should detect a malicious BITS Transfer Job" {
        Mock Get-BitsTransfer {
            return @( [PSCustomObject]@{ DisplayName = "Updater"; FileList = [PSCustomObject]@{ Source = "http://evil.com/payload.exe" }; JobState = "Suspended" } )
        }

        Invoke-BITSHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "Suspicious BITS Job" }
        $Alert.Details | Should -Match "evil.com"
    }
}