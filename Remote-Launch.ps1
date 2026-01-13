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

# Enable TLS 1.2 for older Windows versions (Windows Server 2012 R2 and earlier)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # If SecurityProtocolManager doesn't exist, use the older method
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

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
    # Use Invoke-WebRequest to check Content-Type and handle encoding properly
    $response = Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop
    
    # Get content as UTF-8 string
    if ($response.Content -is [byte[]]) {
        $mainScript = [System.Text.Encoding]::UTF8.GetString($response.Content)
    } else {
        $mainScript = $response.Content
    }
    
    # Check if we got HTML instead of the script (web filter interception)
    if ($mainScript -match '<html|<HTML|<!DOCTYPE|Securly|web filter|geolocation') {
        Write-Log "ERROR: GitHub appears to be blocked by a web filter" "ERROR"
        Write-Log "Received HTML page instead of PowerShell script" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "SOLUTION: Download the script manually from GitHub:" "ERROR"
        Write-Log "  1. Open: https://github.com/monobrau/forensicinvestigator/blob/main/Invoke-ForensicAnalysis.ps1" "ERROR"
        Write-Log "  2. Click 'Raw' button (top right)" "ERROR"
        Write-Log "  3. Save the file as Invoke-ForensicAnalysis.ps1" "ERROR"
        Write-Log "  4. Run: .\Invoke-ForensicAnalysis.ps1 -OutputPath 'C:\SecurityReports'" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "Alternative: Use VPN or contact network admin to whitelist raw.githubusercontent.com" "ERROR"
        exit 1
    }
    
    # Verify it's PowerShell code
    if ($mainScript -notmatch '\.SYNOPSIS|function |param\(|\[CmdletBinding\]') {
        Write-Log "ERROR: Downloaded content doesn't appear to be a PowerShell script" "ERROR"
        Write-Log "It may be an HTML page. Make sure you clicked 'Raw' button on GitHub" "ERROR"
        Write-Log "First 200 characters: $($mainScript.Substring(0, [Math]::Min(200, $mainScript.Length)))" "ERROR"
        exit 1
    }
    
    Write-Log "Script downloaded successfully ($($mainScript.Length) bytes)" "SUCCESS"
} catch {
    $errorMsg = $_.Exception.Message
    
    # Check for SSL/TLS errors
    if ($errorMsg -match 'SSL/TLS|TLS|secure channel|Could not create') {
        Write-Log "ERROR: SSL/TLS connection failed (common on Windows Server 2012 R2)" "ERROR"
        Write-Log "This usually means TLS 1.2 is not enabled" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "SOLUTION - Manual Download:" "ERROR"
        Write-Log "  1. Open: https://github.com/monobrau/forensicinvestigator/blob/main/Invoke-ForensicAnalysis.ps1" "ERROR"
        Write-Log "  2. Click 'Raw' button (top right) - IMPORTANT: Must use Raw button!" "ERROR"
        Write-Log "  3. Right-click the page → Save As → Save as Invoke-ForensicAnalysis.ps1" "ERROR"
        Write-Log "  4. Run: .\Invoke-ForensicAnalysis.ps1 -OutputPath 'C:\SecurityReports'" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "Alternative: Enable TLS 1.2 in PowerShell:" "ERROR"
        Write-Log "  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" "ERROR"
        exit 1
    }
    
    Write-Log "Failed to download script: $errorMsg" "ERROR"
    Write-Log "Attempting alternate download method..." "WARN"

    try {
        # Fallback: Use WebClient with User-Agent
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        $webClient.Encoding = [System.Text.Encoding]::UTF8
        $mainScript = $webClient.DownloadString($ScriptUrl)
        $webClient.Dispose()
        
        # Verify it's PowerShell code
        if ($mainScript -match '<html|<HTML|<!DOCTYPE|Securly|web filter') {
            throw "Received HTML page instead of PowerShell script. Web filter may be blocking GitHub."
        }
        
        # Verify it's actually PowerShell
        if ($mainScript -notmatch '\.SYNOPSIS|function |param\(|\[CmdletBinding\]') {
            throw "Downloaded content doesn't appear to be a PowerShell script"
        }
        
        Write-Log "Downloaded via WebClient" "SUCCESS"
    } catch {
        Write-Log "All download methods failed. Exiting." "ERROR"
        Write-Log "" "ERROR"
        Write-Log "ERROR DETAILS: $($_.Exception.Message)" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "POSSIBLE CAUSES:" "ERROR"
        Write-Log "  - SSL/TLS error (Windows Server 2012 R2 needs TLS 1.2 enabled)" "ERROR"
        Write-Log "  - Web filter blocking GitHub (common in schools/organizations)" "ERROR"
        Write-Log "  - Network connectivity issues" "ERROR"
        Write-Log "  - Invalid URL or repository not accessible" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "SOLUTION - Manual Download:" "ERROR"
        Write-Log "  1. Open: https://github.com/monobrau/forensicinvestigator/blob/main/Invoke-ForensicAnalysis.ps1" "ERROR"
        Write-Log "  2. Click 'Raw' button (top right) - CRITICAL: Must use Raw button!" "ERROR"
        Write-Log "  3. Right-click → Save As → Save as Invoke-ForensicAnalysis.ps1" "ERROR"
        Write-Log "  4. Run: .\Invoke-ForensicAnalysis.ps1 -OutputPath 'C:\SecurityReports'" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "Alternative solutions:" "ERROR"
        Write-Log "  - Enable TLS 1.2: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" "ERROR"
        Write-Log "  - Use VPN to bypass web filters" "ERROR"
        Write-Log "  - Contact network admin to whitelist raw.githubusercontent.com" "ERROR"
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
