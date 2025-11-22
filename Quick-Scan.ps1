<#
.SYNOPSIS
    Quick Forensic Analysis - Services and Network Only

.DESCRIPTION
    Fast, stable version that analyzes only Services and Network connections.
    Skips autoruns and processes to avoid crashes and long execution times.

.PARAMETER OutputPath
    Directory where reports will be saved

.PARAMETER VirusTotalApiKey
    VirusTotal API key for hash lookups

.PARAMETER EnableVirusTotal
    Switch to enable VirusTotal scanning

.PARAMETER ToolsPath
    Directory where Sysinternals tools will be downloaded

.EXAMPLE
    iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Quick-Scan.ps1")
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
    [string]$ToolsPath = ".\SysinternalsTools"
)

Write-Host "`n=== Quick Forensic Scan (Services + Network Only) ===" -ForegroundColor Cyan
Write-Host "This fast scan analyzes services and network connections only.`n" -ForegroundColor Yellow

# Global configuration
$script:VTApiKey = $VirusTotalApiKey
$script:VTEnabled = $EnableVirusTotal -and ![string]::IsNullOrWhiteSpace($VirusTotalApiKey)
$script:VTCache = @{}
$script:VTRateLimit = 4
$script:VTRequestCount = 0
$script:VTLastRequestTime = Get-Date

function Write-ColoredMessage {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

# Create directories
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# VT Functions
function Get-FileHashQuick {
    param([string]$FilePath)
    if (!(Test-Path $FilePath)) { return $null }
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        return $null
    }
}

function Get-VirusTotalReport {
    param([string]$Hash)
    if (!$script:VTEnabled -or [string]::IsNullOrWhiteSpace($Hash)) { return $null }
    if ($script:VTCache.ContainsKey($Hash)) { return $script:VTCache[$Hash] }

    $timeSinceLastRequest = (Get-Date) - $script:VTLastRequestTime
    if ($script:VTRequestCount -ge $script:VTRateLimit -and $timeSinceLastRequest.TotalSeconds -lt 60) {
        $sleepTime = 60 - $timeSinceLastRequest.TotalSeconds + 1
        Write-Host "[*] Rate limit reached, waiting $([math]::Round($sleepTime)) seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds $sleepTime
        $script:VTRequestCount = 0
    }

    try {
        $headers = @{ 'x-apikey' = $script:VTApiKey }
        $url = "https://www.virustotal.com/api/v3/files/$Hash"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop

        $script:VTRequestCount++
        $script:VTLastRequestTime = Get-Date

        $result = @{
            Malicious = $response.data.attributes.last_analysis_stats.malicious
            Suspicious = $response.data.attributes.last_analysis_stats.suspicious
            Undetected = $response.data.attributes.last_analysis_stats.undetected
            Harmless = $response.data.attributes.last_analysis_stats.harmless
        }
        $script:VTCache[$Hash] = $result
        return $result
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            $result = @{ Malicious = 0; Suspicious = 0; Undetected = 0; Harmless = 0 }
            $script:VTCache[$Hash] = $result
            return $result
        }
        return $null
    }
}

function Get-RiskLevel {
    param([string]$Signature, [object]$VTReport)
    $riskScore = 0

    if ([string]::IsNullOrWhiteSpace($Signature) -or $Signature -eq "(Not verified)" -or $Signature -eq "n/a") {
        $riskScore += 10
    } elseif ($Signature -like "*Unknown*") {
        $riskScore += 5
    }

    if ($VTReport) {
        $malicious = [int]$VTReport.Malicious
        if ($malicious -ge 5) { $riskScore += 20 }
        elseif ($malicious -ge 1) { $riskScore += 10 }
        if ([int]$VTReport.Suspicious -ge 3) { $riskScore += 5 }
    }

    if ($riskScore -ge 15) { return "High" }
    elseif ($riskScore -ge 5) { return "Medium" }
    else { return "Low" }
}

# Services Analysis
Write-ColoredMessage "`n=== Analyzing Services ===" -Color Cyan
$serviceEntries = @()

try {
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName }
    $totalServices = $services.Count
    $currentService = 0

    foreach ($service in $services) {
        $currentService++
        Write-Progress -Activity "Analyzing Services" -Status "Processing $currentService of $totalServices" -PercentComplete (($currentService / $totalServices) * 100)

        $pathName = $service.PathName
        $exePath = $pathName
        if ($pathName -match '^"([^"]+)"') { $exePath = $matches[1] }
        elseif ($pathName -match '^([^\s]+\.exe)') { $exePath = $matches[1] }

        $hash = $null
        $vtReport = $null
        $signature = "Unknown"

        if (Test-Path $exePath -ErrorAction SilentlyContinue) {
            $hash = Get-FileHashQuick -FilePath $exePath
            if ($hash -and $script:VTEnabled) {
                $vtReport = Get-VirusTotalReport -Hash $hash
            }
            try {
                $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                if ($sig -and $sig.SignerCertificate) {
                    $signature = $sig.SignerCertificate.Subject
                }
            } catch { }
        }

        $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

        $serviceEntries += [PSCustomObject]@{
            Type = "Service"
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            State = $service.State
            StartMode = $service.StartMode
            PathName = $pathName
            ExecutablePath = $exePath
            Publisher = $signature
            SHA256 = $hash
            VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "N/A" }
            VT_Suspicious = if ($vtReport) { $vtReport.Suspicious } else { "N/A" }
            VT_Detections = if ($vtReport) { "$($vtReport.Malicious)/$($vtReport.Malicious + $vtReport.Suspicious + $vtReport.Undetected + $vtReport.Harmless)" } else { "N/A" }
            RiskLevel = $riskLevel
        }
    }
    Write-Progress -Activity "Analyzing Services" -Completed
    Write-ColoredMessage "[+] Found $($serviceEntries.Count) services" -Color Green
} catch {
    Write-ColoredMessage "[!] Error: $_" -Color Red
}

# Network Analysis
Write-ColoredMessage "`n=== Analyzing Network Connections ===" -Color Cyan
$networkEntries = @()

try {
    $connections = Get-NetTCPConnection -State Listen,Established -ErrorAction Stop
    $totalConns = $connections.Count
    $currentConn = 0

    foreach ($conn in $connections) {
        $currentConn++
        Write-Progress -Activity "Analyzing Network" -Status "Processing $currentConn of $totalConns" -PercentComplete (($currentConn / $totalConns) * 100)

        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $exePath = $null
        $hash = $null
        $vtReport = $null
        $signature = "Unknown"

        if ($process) {
            try {
                $exePath = $process.Path
                if ($exePath -and (Test-Path $exePath)) {
                    $hash = Get-FileHashQuick -FilePath $exePath
                    if ($hash -and $script:VTEnabled) {
                        $vtReport = Get-VirusTotalReport -Hash $hash
                    }
                    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) {
                        $signature = $sig.SignerCertificate.Subject
                    }
                }
            } catch { }
        }

        $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

        $networkEntries += [PSCustomObject]@{
            Type = "Network"
            Protocol = "TCP"
            LocalAddress = $conn.LocalAddress
            LocalPort = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            State = $conn.State
            ProcessId = $conn.OwningProcess
            ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
            ExecutablePath = $exePath
            Publisher = $signature
            SHA256 = $hash
            VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "N/A" }
            VT_Suspicious = if ($vtReport) { $vtReport.Suspicious } else { "N/A" }
            VT_Detections = if ($vtReport) { "$($vtReport.Malicious)/$($vtReport.Malicious + $vtReport.Suspicious + $vtReport.Undetected + $vtReport.Harmless)" } else { "N/A" }
            RiskLevel = $riskLevel
        }
    }
    Write-Progress -Activity "Analyzing Network" -Completed
    Write-ColoredMessage "[+] Found $($networkEntries.Count) connections" -Color Green
} catch {
    Write-ColoredMessage "[!] Error: $_" -Color Red
}

# Export
Write-ColoredMessage "`n=== Exporting Results ===" -Color Cyan
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME

$serviceCsv = Join-Path $OutputPath "${hostname}_Services_${timestamp}.csv"
$networkCsv = Join-Path $OutputPath "${hostname}_Network_${timestamp}.csv"

if ($serviceEntries.Count -gt 0) {
    $serviceEntries | Export-Csv -Path $serviceCsv -NoTypeInformation
    Write-ColoredMessage "[+] Services: $serviceCsv" -Color Green
}

if ($networkEntries.Count -gt 0) {
    $networkEntries | Export-Csv -Path $networkCsv -NoTypeInformation
    Write-ColoredMessage "[+] Network: $networkCsv" -Color Green
}

# Summary
$allEntries = @()
$allEntries += $serviceEntries
$allEntries += $networkEntries

$highRisk = ($allEntries | Where-Object { $_.RiskLevel -eq "High" }).Count
$mediumRisk = ($allEntries | Where-Object { $_.RiskLevel -eq "Medium" }).Count
$lowRisk = ($allEntries | Where-Object { $_.RiskLevel -eq "Low" }).Count

Write-ColoredMessage "`n=== Quick Scan Summary ===" -Color Cyan
Write-Host "Total Items: $($allEntries.Count)"
Write-ColoredMessage "  High Risk:    $highRisk" -Color Red
Write-ColoredMessage "  Medium Risk:  $mediumRisk" -Color Yellow
Write-ColoredMessage "  Low Risk:     $lowRisk" -Color Green
Write-Host "`nServices: $($serviceEntries.Count)"
Write-Host "Network:  $($networkEntries.Count)"

if ($highRisk -gt 0) {
    Write-ColoredMessage "`n[!] WARNING: Found $highRisk high-risk items!" -Color Red
}

Write-ColoredMessage "`n=== Quick Scan Complete ===" -Color Green
Write-ColoredMessage "Reports saved to: $OutputPath" -Color Cyan
