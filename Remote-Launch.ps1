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

.PARAMETER ScriptUrl
    URL to download Invoke-ForensicAnalysis.ps1 from. Defaults to GitHub main branch.
    Use this parameter if GitHub is blocked and you have an alternative hosting location.

.PARAMETER LocalScriptPath
    Local file path to Invoke-ForensicAnalysis.ps1. If provided, this takes precedence over ScriptUrl.
    Use this when running from a local file or network share instead of downloading from the web.

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

.EXAMPLE
    # Using local script file (when GitHub is blocked)
    .\Remote-Launch.ps1 -LocalScriptPath "\\server\share\Invoke-ForensicAnalysis.ps1"

.EXAMPLE
    # Using alternative hosting URL
    .\Remote-Launch.ps1 -ScriptUrl "https://your-cdn.com/scripts/Invoke-ForensicAnalysis.ps1"
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
    [string]$ScriptUrl = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1",
    
    [Parameter(Mandatory=$false)]
    [string]$LocalScriptPath = ""
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

# Function to try multiple GitHub alternative domains
function Get-ScriptFromGitHub {
    param(
        [string]$OriginalUrl,
        [string]$OutputPath
    )
    
    # Extract user/repo/branch/file from GitHub URL
    if ($OriginalUrl -match 'raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)') {
        $user = $matches[1]
        $repo = $matches[2]
        $branch = $matches[3]
        $file = $matches[4]
        
        # Alternative GitHub domains/CDNs to try (skip original, try it last)
        $alternatives = @(
            # jsDelivr CDN (free, production-ready) - try first
            "https://cdn.jsdelivr.net/gh/$user/$repo@$branch/$file",
            # StaticDelivr CDN (production CDN)
            "https://cdn.staticdelivr.com/gh/$user/$repo/$branch/$file",
            # Githack (caching proxy)
            "https://raw.githack.com/$user/$repo/$branch/$file",
            # Rawgit (caching proxy)
            "https://rawgit.net/$user/$repo/$branch/$file",
            # Original GitHub - try last
            "https://raw.githubusercontent.com/$user/$repo/$branch/$file"
        )
        
        foreach ($altUrl in $alternatives) {
            try {
                Write-Log "Trying: $altUrl" "INFO"
                # Use Invoke-WebRequest to check Content-Type and handle encoding properly
                $response = Invoke-WebRequest -Uri $altUrl -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
                
                # Check Content-Type header first - if HTML, skip immediately
                $contentType = $response.Headers['Content-Type']
                if ($contentType -and $contentType -match 'text/html') {
                    Write-Log "Received HTML Content-Type from: $altUrl" "WARN"
                    continue
                }
                
                # Get content as UTF-8 string
                if ($response.Content -is [byte[]]) {
                    $script = [System.Text.Encoding]::UTF8.GetString($response.Content)
                } else {
                    $script = $response.Content
                }
                
                # Only check for HTML if Content-Type wasn't clear
                if (-not $contentType -or $contentType -notmatch 'text/plain|application/octet-stream|text/x-powershell') {
                    # Check first 500 chars for HTML patterns (more lenient)
                    $checkLength = [Math]::Min(500, $script.Length)
                    if ($checkLength -gt 0) {
                        $first500 = $script.Substring(0, $checkLength)
                        if ($first500 -match '<html|<HTML|<!DOCTYPE') {
                            Write-Log "Received HTML page instead of script from: $altUrl" "WARN"
                            continue
                        }
                    }
                }
                
                # Verify it's PowerShell code (check first 1000 chars)
                $checkLength = [Math]::Min(1000, $script.Length)
                if ($checkLength -gt 0) {
                    $first1000 = $script.Substring(0, $checkLength)
                    if ($first1000 -notmatch '\.SYNOPSIS|function |param\(|\[CmdletBinding\]|#Requires|\.DESCRIPTION') {
                        Write-Log "Content doesn't appear to be PowerShell script from: $altUrl" "WARN"
                        continue
                    }
                } else {
                    Write-Log "Script content is empty from: $altUrl" "WARN"
                    continue
                }
                
                Write-Log "Successfully downloaded from: $altUrl ($($script.Length) bytes)" "SUCCESS"
                $script | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
                return $true
            } catch {
                Write-Log "Failed: $altUrl - $($_.Exception.Message)" "WARN"
                continue
            }
        }
    }
    
    return $false
}

# Download main script
$tempScriptPath = Join-Path $env:TEMP "Invoke-ForensicAnalysis.ps1"

# Check if local script path is provided and exists
if (![string]::IsNullOrWhiteSpace($LocalScriptPath) -and (Test-Path $LocalScriptPath)) {
    Write-Log "Using local script file: $LocalScriptPath" "INFO"
    Copy-Item $LocalScriptPath -Destination $tempScriptPath -Force -ErrorAction Stop
    Write-Log "Script copied successfully" "SUCCESS"
} elseif (![string]::IsNullOrWhiteSpace($ScriptUrl)) {
    Write-Log "Downloading forensic analysis script from: $ScriptUrl" "INFO"
    
    # Check if it's a GitHub URL - try alternatives automatically
    if ($ScriptUrl -match 'githubusercontent\.com|github\.com') {
        Write-Log "GitHub URL detected - trying alternative domains..." "INFO"
        $success = Get-ScriptFromGitHub -OriginalUrl $ScriptUrl -OutputPath $tempScriptPath
        
        if ($success) {
            Write-Log "Script downloaded successfully via alternative domain" "SUCCESS"
        } else {
            # All alternatives including original GitHub URL failed - suggest using local script
            Write-Log "All alternative domains failed (including original GitHub URL)" "ERROR"
            Write-Log "" "ERROR"
            Write-Log "SOLUTION: Use -LocalScriptPath parameter or download manually:" "ERROR"
            Write-Log "  1. Open: https://github.com/monobrau/forensicinvestigator/blob/main/Invoke-ForensicAnalysis.ps1" "ERROR"
            Write-Log "  2. Click 'Raw' button (top right)" "ERROR"
            Write-Log "  3. Save the file as Invoke-ForensicAnalysis.ps1" "ERROR"
            Write-Log "  4. Run: .\Remote-Launch.ps1 -LocalScriptPath '.\Invoke-ForensicAnalysis.ps1'" "ERROR"
            exit 1
        }
    } else {
        # Non-GitHub URL - try direct download
        try {
            $mainScript = Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop
            Write-Log "Script downloaded successfully ($($mainScript.Length) bytes)" "SUCCESS"
            $mainScript | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
        } catch {
            Write-Log "Failed to download script: $_" "ERROR"
            Write-Log "Attempting alternate download method..." "WARN"

            try {
                $mainScript = (New-Object System.Net.WebClient).DownloadString($ScriptUrl)
                Write-Log "Downloaded via WebClient" "SUCCESS"
                $mainScript | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
            } catch {
                Write-Log "All download methods failed. Exiting." "ERROR"
                Write-Log "TIP: Use -LocalScriptPath parameter with a local file path" "WARN"
                exit 1
            }
        }
    }
} else {
    Write-Log "No script source provided. Use -ScriptUrl or -LocalScriptPath parameter." "ERROR"
    exit 1
}

Write-Log "Script ready at: $tempScriptPath" "INFO"

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
