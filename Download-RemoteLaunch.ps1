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
    
    # Method 1: Try Invoke-WebRequest with User-Agent to bypass web filters
    try {
        $headers = @{
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        $response = Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -ErrorAction Stop
        
        # Check if we got HTML instead of the script (web filter interception)
        if ($response.Content -match '<html|<HTML|<!DOCTYPE') {
            throw "Web filter intercepted request - received HTML instead of script"
        }
        
        # Get content as UTF-8 string
        if ($response.Content -is [byte[]]) {
            $scriptContent = [System.Text.Encoding]::UTF8.GetString($response.Content)
        } else {
            $scriptContent = $response.Content
        }
    } catch {
        # Fallback: Use WebClient with UTF-8 and User-Agent
        Write-Host "Primary download failed, trying fallback method..." -ForegroundColor Yellow
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        $webClient.Encoding = [System.Text.Encoding]::UTF8
        $scriptContent = $webClient.DownloadString($url)
        $webClient.Dispose()
        
        # Verify it's PowerShell code, not HTML
        if ($scriptContent -match '<html|<HTML|<!DOCTYPE') {
            throw "Web filter is blocking GitHub. Received HTML page instead of PowerShell script."
        }
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
