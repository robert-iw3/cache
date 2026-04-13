<#
.SYNOPSIS
    Pester 5 Tests for File and ADS Hunting using the Pester TestDrive
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1")
}

Describe "File System and ADS Hunt Modules" {

    BeforeEach {
        $script:Findings = @()
        $Quiet = $true
    }

    It "Should detect a Timestomped executable (Modified Date older than Creation Date)" {

        # 1. Create a real temporary file inside Pester's isolated $TestDrive
        $TestFilePath = Join-Path $TestDrive "payload.exe"
        Set-Content -Path $TestFilePath -Value "MZ... Fake Executable Content"

        # 2. Artificially Timestomp the file (Set Creation to 2026, Modified to 2010)
        $FileInfo = [System.IO.FileInfo]::new($TestFilePath)
        $FileInfo.CreationTime = [datetime]"2026-01-01"
        $FileInfo.LastWriteTime = [datetime]"2010-01-01"

        # 3. Run the multithreaded FileHunt against the TestDrive ONLY
        Invoke-FileHunt -Path $TestDrive -Recurse:$true -QuickMode:$true

        # 4. Assert
        $Alert = $script:Findings | Where-Object { $_.Type -eq "Timestomped File" }

        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Be $TestFilePath
    }
}