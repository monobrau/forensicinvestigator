<#
.SYNOPSIS
    SAFE VERSION - Forensic system analysis tool with crash protection

.DESCRIPTION
    This is a safer version with timeout protection and better error handling
    to prevent PowerShell crashes. Use this if the regular version hangs or crashes.

.PARAMETER OutputPath
    Directory where reports will be saved

.PARAMETER VirusTotalApiKey
    VirusTotal API key for hash lookups

.PARAMETER EnableVirusTotal
    Switch to enable VirusTotal scanning

.PARAMETER ToolsPath
    Directory where Sysinternals tools will be downloaded

.PARAMETER SkipAutoruns
    Skip autorun analysis (use if autoruns causes crashes)

.PARAMETER SkipProcesses
    Skip process analysis

.PARAMETER TimeoutSeconds
    Timeout for autorunsc in seconds (default: 300)

.EXAMPLE
    .\Invoke-ForensicAnalysis-Safe.ps1

.EXAMPLE
    .\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -TimeoutSeconds 120
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ForensicReports",

    [Parameter(Mandatory=$false)]
    [string]$VirusTotalApiKey = "",

    [Parameter(Mandatory=$false)]
    [switch]$EnableVirusTotal,

    [Parameter(Mandatory=$false)]
    [string]$ToolsPath = ".\SysinternalsTools",

    [Parameter(Mandatory=$false)]
    [switch]$SkipAutoruns,

    [Parameter(Mandatory=$false)]
    [switch]$SkipProcesses,

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 300
)

# Import the main script functions but with timeout protection
$mainScriptUrl = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Invoke-ForensicAnalysis.ps1"

Write-Host "=== SAFE MODE Forensic Analysis ===" -ForegroundColor Cyan
Write-Host "Loading core functions with crash protection..." -ForegroundColor Yellow
Write-Host ""

# Download main script
try {
    $mainScript = Invoke-RestMethod -Uri $mainScriptUrl -UseBasicParsing -TimeoutSec 30

    # Execute in isolated scope to get functions
    . ([ScriptBlock]::Create($mainScript))

    Write-Host "[+] Core functions loaded successfully" -ForegroundColor Green

} catch {
    Write-Host "[!] Failed to load core script: $_" -ForegroundColor Red
    Write-Host "[!] Attempting to use local version..." -ForegroundColor Yellow

    if (Test-Path ".\Invoke-ForensicAnalysis.ps1") {
        . .\Invoke-ForensicAnalysis.ps1
    } else {
        Write-Host "[!] No local version found. Exiting." -ForegroundColor Red
        exit 1
    }
}

# Run with crash protection
try {
    Initialize-Environment
    Get-SysinternalsTools

    # Collect data with timeouts
    $autorunEntries = @()
    $serviceEntries = @()
    $networkEntries = @()
    $processEntries = @()

    if (!$SkipAutoruns) {
        Write-Host "`n[*] Running Autoruns analysis with timeout protection ($TimeoutSeconds seconds)..." -ForegroundColor Yellow

        $job = Start-Job -ScriptBlock {
            param($ToolsPath, $VTEnabled, $VTApiKey)

            $script:VTEnabled = $VTEnabled
            $script:VTApiKey = $VTApiKey

            # Run autoruns
            $arch = if ([Environment]::Is64BitOperatingSystem) { "autorunsc64.exe" } else { "autorunsc.exe" }
            $autorunsc = Join-Path $ToolsPath $arch

            if (Test-Path $autorunsc) {
                & $autorunsc -accepteula -a * -c -s -v '*' 2>&1
            }
        } -ArgumentList $ToolsPath, $script:VTEnabled, $script:VTApiKey

        $completed = Wait-Job $job -Timeout $TimeoutSeconds

        if ($completed) {
            Write-Host "[+] Autoruns completed successfully" -ForegroundColor Green
            $autorunEntries = Get-AutorunEntries
        } else {
            Write-Host "[!] Autoruns timed out after $TimeoutSeconds seconds - skipping" -ForegroundColor Yellow
            Stop-Job $job
            Remove-Job $job -Force
        }
    } else {
        Write-Host "[*] Skipping Autoruns analysis" -ForegroundColor Yellow
    }

    # Services (usually safe)
    Write-Host "`n[*] Analyzing Services..." -ForegroundColor Cyan
    try {
        $serviceEntries = Get-ServiceEntries
    } catch {
        Write-Host "[!] Service analysis failed: $_" -ForegroundColor Red
    }

    # Network (usually safe)
    Write-Host "`n[*] Analyzing Network Connections..." -ForegroundColor Cyan
    try {
        $networkEntries = Get-NetworkConnections
    } catch {
        Write-Host "[!] Network analysis failed: $_" -ForegroundColor Red
    }

    # Processes (can be slow)
    if (!$SkipProcesses) {
        Write-Host "`n[*] Analyzing Processes..." -ForegroundColor Cyan
        try {
            $processEntries = Get-RunningProcesses
        } catch {
            Write-Host "[!] Process analysis failed: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[*] Skipping Process analysis" -ForegroundColor Yellow
    }

    # Export
    Export-Results -AutorunEntries $autorunEntries -ServiceEntries $serviceEntries -NetworkEntries $networkEntries -ProcessEntries $processEntries

    # Summary
    Show-Summary -AutorunEntries $autorunEntries -ServiceEntries $serviceEntries -NetworkEntries $networkEntries -ProcessEntries $processEntries

    Write-Host "`n[+] Safe mode analysis completed successfully!" -ForegroundColor Green

} catch {
    Write-Host "`n[!] Error during analysis: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
