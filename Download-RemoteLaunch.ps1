<#
.SYNOPSIS
    Safe downloader for Remote-Launch.ps1 with proper UTF-8 encoding

.DESCRIPTION
    Downloads Remote-Launch.ps1 from GitHub with proper UTF-8 encoding to avoid parsing errors.
    This wrapper ensures the script downloads correctly even when GitHub serves it with encoding issues.

.EXAMPLE
    .\Download-RemoteLaunch.ps1
    Downloads and executes Remote-Launch.ps1 with default parameters

.EXAMPLE
    .\Download-RemoteLaunch.ps1 -OutputPath "C:\SecurityReports"
    Downloads and executes with custom output path
#>

param(
    [string]$OutputPath = "",
    [string]$VirusTotalApiKey = "",
    [switch]$EnableVirusTotal,
    [switch]$ExportXLSX,
    [switch]$CombinedWorkbook,
    [switch]$CleanupTools
)

$ErrorActionPreference = "Stop"

try {
    Write-Host "Downloading Remote-Launch.ps1 with proper encoding..." -ForegroundColor Cyan
    
    # Download with explicit UTF-8 handling
    $url = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1"
    
    # Method 1: Try Invoke-RestMethod with explicit encoding
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        $scriptContent = [System.Text.Encoding]::UTF8.GetString($response.Content)
    } catch {
        # Fallback: Use WebClient with UTF-8
        $webClient = New-Object System.Net.WebClient
        $webClient.Encoding = [System.Text.Encoding]::UTF8
        $scriptContent = $webClient.DownloadString($url)
        $webClient.Dispose()
    }
    
    # Save to temp file with explicit UTF-8 encoding
    $tempFile = Join-Path $env:TEMP "Remote-Launch.ps1"
    [System.IO.File]::WriteAllText($tempFile, $scriptContent, [System.Text.Encoding]::UTF8)
    
    Write-Host "Downloaded successfully. Executing..." -ForegroundColor Green
    
    # Build parameters
    $params = @{}
    if ($OutputPath) { $params.OutputPath = $OutputPath }
    if ($VirusTotalApiKey) { $params.VirusTotalApiKey = $VirusTotalApiKey }
    if ($EnableVirusTotal) { $params.EnableVirusTotal = $true }
    if ($ExportXLSX) { $params.ExportXLSX = $true }
    if ($CombinedWorkbook) { $params.CombinedWorkbook = $true }
    if ($CleanupTools) { $params.CleanupTools = $true }
    
    # Execute the downloaded script
    & $tempFile @params
    
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
