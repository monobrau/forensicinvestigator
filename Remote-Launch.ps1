<#
.SYNOPSIS
    Remote launcher for Forensic Investigation Tool (IEX and RMM compatible)

.DESCRIPTION
    This script can be executed remotely via IEX or RMM tools like ConnectWise.
    It downloads and executes the forensic analysis tool with customizable parameters.

.PARAMETER VirusTotalApiKey
    VirusTotal API key for malware scanning

.PARAMETER EnableVirusTotal
    Enable VirusTotal scanning

.PARAMETER OutputPath
    Custom output path for reports

.PARAMETER ToolsPath
    Custom path for Sysinternals tools

.PARAMETER UploadResults
    Upload results to specified URL (optional)

.PARAMETER UploadUrl
    URL to upload results to (requires -UploadResults)

.PARAMETER CleanupTools
    Delete Sysinternals tools after analysis completes

.PARAMETER ExportXLSX
    Export to Excel format (XLSX) instead of CSV. Requires Microsoft Excel to be installed.
    By default, exports to CSV format which works in all environments including ScreenConnect.

.PARAMETER CombinedWorkbook
    Export to a single Excel workbook with all worksheets (slower but consolidated).
    Only applies when -ExportXLSX is used.

.EXAMPLE
    # Direct execution
    .\Remote-Launch.ps1 -EnableVirusTotal -VirusTotalApiKey "your-key"

.EXAMPLE
    # Via IEX from GitHub (with proper encoding)
    $script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1" -UseBasicParsing; Invoke-Expression $script

.EXAMPLE
    # Via IEX with parameters (using scriptblock for parameter passing - with proper encoding)
    $script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1" -UseBasicParsing; & ([scriptblock]::Create($script)) -ExportXLSX

.EXAMPLE
    # Via IEX with environment variable (with proper encoding)
    $env:VT_API_KEY = "your-api-key"; $script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1" -UseBasicParsing; Invoke-Expression $script

.EXAMPLE
    # ConnectWise Command - One-liner (no parameters - defaults to CSV, with proper encoding)
    powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "$script = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1' -UseBasicParsing; Invoke-Expression $script"

.EXAMPLE
    # ConnectWise Command - With ExportXLSX parameter (with proper encoding)
    powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "$script = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1' -UseBasicParsing; & ([scriptblock]::Create($script)) -ExportXLSX"

.EXAMPLE
    # With tool cleanup (leaves no trace)
    .\Remote-Launch.ps1 -CleanupTools -EnableVirusTotal
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$VirusTotalApiKey = "",

    [Parameter(Mandatory=$false)]
    [switch]$EnableVirusTotal,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",

    [Parameter(Mandatory=$false)]
    [string]$ToolsPath = "",

    [Parameter(Mandatory=$false)]
    [switch]$UploadResults,

    [Parameter(Mandatory=$false)]
    [string]$UploadUrl = "",

    [Parameter(Mandatory=$false)]
    [switch]$CleanupTools,

    [Parameter(Mandatory=$false)]
    [switch]$ExportXLSX,

    [Parameter(Mandatory=$false)]
    [switch]$CombinedWorkbook,

    [Parameter(Mandatory=$false)]
    [string]$ScriptUrl = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Banner
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║     Forensic Investigation Tool - Remote Launcher        ║
║              Sysinternals + VirusTotal                    ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Log "Starting remote deployment..." "INFO"

# Collect system information
$hostname = $env:COMPUTERNAME
$username = $env:USERNAME
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
Write-Log "Target: $hostname (User: $username)" "INFO"
Write-Log "OS: $($osInfo.Caption) $($osInfo.Version)" "INFO"

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin) {
    Write-Log "WARNING: Not running as Administrator. Attempting elevation..." "WARN"

    # Try to elevate
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        if ([string]::IsNullOrWhiteSpace($scriptPath)) {
            # Script was run via IEX, re-download and elevate
            Write-Log "Re-launching with elevation via IEX..." "INFO"
            # Use proper encoding when re-downloading
            $elevateScript = "Start-Process powershell.exe -ArgumentList '-ExecutionPolicy Bypass -NoProfile -Command `"`$script = Invoke-RestMethod -Uri ''$ScriptUrl'' -UseBasicParsing; `$script | Out-File -FilePath ''`$env:TEMP\RemoteLaunch.ps1'' -Encoding UTF8 -Force; & ''`$env:TEMP\RemoteLaunch.ps1''`"' -Verb RunAs"
            Invoke-Expression $elevateScript
            exit
        } else {
            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
            exit
        }
    } catch {
        Write-Log "Elevation failed. Continuing without admin rights (limited functionality)." "WARN"
    }
}

# Set default paths if not specified
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = "$env:TEMP\ForensicReports"
}
if ([string]::IsNullOrWhiteSpace($ToolsPath)) {
    $ToolsPath = "$env:TEMP\SysinternalsTools"
}

Write-Log "Output Path: $OutputPath" "INFO"
Write-Log "Tools Path: $ToolsPath" "INFO"

# Check for API key in environment variable if not provided
if ([string]::IsNullOrWhiteSpace($VirusTotalApiKey)) {
    $VirusTotalApiKey = [System.Environment]::GetEnvironmentVariable("VT_API_KEY", "Process")
    if (![string]::IsNullOrWhiteSpace($VirusTotalApiKey)) {
        Write-Log "Using VirusTotal API key from environment variable" "INFO"
        $EnableVirusTotal = $true
    }
}

# Download main script
Write-Log "Downloading forensic analysis script from: $ScriptUrl" "INFO"
try {
    $mainScript = Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop
    Write-Log "Script downloaded successfully ($($mainScript.Length) bytes)" "SUCCESS"
} catch {
    Write-Log "Failed to download script: $_" "ERROR"
    Write-Log "Attempting alternate download method..." "WARN"

    try {
        $mainScript = (New-Object System.Net.WebClient).DownloadString($ScriptUrl)
        Write-Log "Downloaded via WebClient" "SUCCESS"
    } catch {
        Write-Log "All download methods failed. Exiting." "ERROR"
        exit 1
    }
}

# Save script to temp location
$tempScriptPath = Join-Path $env:TEMP "Invoke-ForensicAnalysis.ps1"
$mainScript | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
Write-Log "Script saved to: $tempScriptPath" "INFO"

# Build execution parameters
$params = @{
    OutputPath = $OutputPath
    ToolsPath = $ToolsPath
}

if ($EnableVirusTotal -and ![string]::IsNullOrWhiteSpace($VirusTotalApiKey)) {
    $params.EnableVirusTotal = $true
    $params.VirusTotalApiKey = $VirusTotalApiKey
    Write-Log "VirusTotal scanning: ENABLED" "SUCCESS"
} else {
    Write-Log "VirusTotal scanning: DISABLED" "WARN"
}

if ($CleanupTools) {
    $params.CleanupTools = $true
    Write-Log "Tool cleanup: ENABLED" "INFO"
}

if ($ExportXLSX) {
    $params.ExportXLSX = $true
    Write-Log "XLSX export: ENABLED" "INFO"
}

if ($CombinedWorkbook) {
    $params.CombinedWorkbook = $true
    Write-Log "Combined workbook: ENABLED" "INFO"
}

# Execute the forensic analysis
Write-Log "Starting forensic analysis..." "INFO"
Write-Host "`n"

try {
    & $tempScriptPath @params
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0 -or $null -eq $exitCode) {
        Write-Log "Forensic analysis completed successfully" "SUCCESS"
    } else {
        Write-Log "Forensic analysis completed with warnings (exit code: $exitCode)" "WARN"
    }
} catch {
    Write-Log "Error during forensic analysis: $_" "ERROR"
    exit 1
}

# Upload results if requested
if ($UploadResults -and ![string]::IsNullOrWhiteSpace($UploadUrl)) {
    Write-Log "Uploading results to: $UploadUrl" "INFO"

    try {
        # Find the most recent report
        $reports = Get-ChildItem -Path $OutputPath -Filter "*.xlsx" -ErrorAction SilentlyContinue
        if ($reports.Count -eq 0) {
            $reports = Get-ChildItem -Path $OutputPath -Filter "*.csv" -ErrorAction SilentlyContinue
        }

        $latestReport = $reports | Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if ($latestReport) {
            # ZIP the report
            $zipPath = "$env:TEMP\ForensicReport_${hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
            Compress-Archive -Path $OutputPath\* -DestinationPath $zipPath -Force

            Write-Log "Report compressed: $zipPath" "INFO"

            # Upload (example using multipart form data)
            $uploadHeaders = @{
                "X-Computer-Name" = $hostname
                "X-Username" = $username
                "X-Timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }

            Invoke-RestMethod -Uri $UploadUrl -Method Post -InFile $zipPath -Headers $uploadHeaders -ContentType "application/zip"
            Write-Log "Results uploaded successfully" "SUCCESS"

            # Cleanup
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "No reports found to upload" "WARN"
        }
    } catch {
        Write-Log "Upload failed: $_" "ERROR"
    }
}

# Cleanup temp script
Write-Log "Cleaning up temporary files..." "INFO"
Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue

# Summary
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║                  Execution Complete                       ║
╚═══════════════════════════════════════════════════════════╝

Report Location: $OutputPath

"@ -ForegroundColor Green

Write-Log "Remote execution completed" "SUCCESS"

# Return path to reports for RMM tools
return $OutputPath
