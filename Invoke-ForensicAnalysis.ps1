<#
.SYNOPSIS
    Forensic system analysis tool using Sysinternals utilities with VirusTotal integration.

.DESCRIPTION
    Downloads and runs Sysinternals tools to perform comprehensive system analysis.
    Exports findings to color-coded Excel (if available) or CSV with optional VirusTotal hash checking.

.PARAMETER OutputPath
    Directory where reports will be saved. Defaults to .\ForensicReports

.PARAMETER VirusTotalApiKey
    VirusTotal API key for hash lookups. If not provided, VT scanning will be skipped.

.PARAMETER EnableVirusTotal
    Switch to enable VirusTotal scanning (requires API key)

.PARAMETER ToolsPath
    Directory where Sysinternals tools will be downloaded. Defaults to .\SysinternalsTools

.PARAMETER CleanupTools
    Switch to delete Sysinternals tools folder after analysis completes

.PARAMETER CombinedWorkbook
    Switch to export to a single Excel workbook with all worksheets (slower but consolidated).
    By default, exports to separate Excel files for faster performance.

.EXAMPLE
    .\Invoke-ForensicAnalysis.ps1 -EnableVirusTotal -VirusTotalApiKey "your-api-key"

.EXAMPLE
    .\Invoke-ForensicAnalysis.ps1 -OutputPath "C:\Reports"

.EXAMPLE
    .\Invoke-ForensicAnalysis.ps1 -CleanupTools

.EXAMPLE
    .\Invoke-ForensicAnalysis.ps1 -CombinedWorkbook
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
    [switch]$CleanupTools,

    [Parameter(Mandatory=$false)]
    [switch]$CombinedWorkbook
)

#Requires -RunAsAdministrator

# Script version - for verification
$script:Version = "2.1.2-RemovedDebugMessages-20250123"

# Global configuration
$script:VTApiKey = $VirusTotalApiKey
$script:VTEnabled = $EnableVirusTotal -and ![string]::IsNullOrWhiteSpace($VirusTotalApiKey)
$script:VTCache = @{}
$script:VTRateLimit = 4  # Free API: 4 requests per minute
$script:VTRequestCount = 0
$script:VTLastRequestTime = Get-Date

# Color coding thresholds
$script:ColorScheme = @{
    HighRisk = @{
        Color = 'Red'
        Criteria = 'No signature OR VT detections >= 5'
    }
    MediumRisk = @{
        Color = 'Yellow'
        Criteria = 'Unknown publisher OR VT detections 1-4'
    }
    LowRisk = @{
        Color = 'Green'
        Criteria = 'Verified signature AND VT detections = 0'
    }
}

# Required Sysinternals tools
$script:RequiredTools = @{
    'autorunsc.exe' = 'https://live.sysinternals.com/autorunsc.exe'
    'autorunsc64.exe' = 'https://live.sysinternals.com/autorunsc64.exe'
    'PsService.exe' = 'https://live.sysinternals.com/PsService.exe'
    'PsService64.exe' = 'https://live.sysinternals.com/PsService64.exe'
    'tcpview.exe' = 'https://live.sysinternals.com/Tcpview.exe'
    'tcpvcon.exe' = 'https://live.sysinternals.com/tcpvcon.exe'
    'sigcheck.exe' = 'https://live.sysinternals.com/sigcheck.exe'
    'sigcheck64.exe' = 'https://live.sysinternals.com/sigcheck64.exe'
    'handle.exe' = 'https://live.sysinternals.com/handle.exe'
    'handle64.exe' = 'https://live.sysinternals.com/handle64.exe'
    'listdlls.exe' = 'https://live.sysinternals.com/Listdlls.exe'
    'listdlls64.exe' = 'https://live.sysinternals.com/Listdlls64.exe'
    'psinfo.exe' = 'https://live.sysinternals.com/psinfo.exe'
    'psinfo64.exe' = 'https://live.sysinternals.com/psinfo64.exe'
}

function Write-ColoredMessage {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

function Initialize-Environment {
    Write-ColoredMessage "`n=== Forensic Investigation Tool ===" -Color Cyan
    Write-ColoredMessage "Version: $script:Version" -Color Gray
    Write-ColoredMessage "Initializing environment...`n" -Color Cyan

    # Create directories
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-ColoredMessage "[+] Created output directory: $OutputPath" -Color Green
    }

    if (!(Test-Path $ToolsPath)) {
        New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null
        Write-ColoredMessage "[+] Created tools directory: $ToolsPath" -Color Green
    }

    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$isAdmin) {
        Write-ColoredMessage "[!] Warning: Not running as Administrator. Some tools may not work properly." -Color Yellow
    }

    # Check VT status
    if ($script:VTEnabled) {
        Write-ColoredMessage "[+] VirusTotal scanning: ENABLED" -Color Green
    } else {
        Write-ColoredMessage "[-] VirusTotal scanning: DISABLED" -Color Yellow
    }

    Write-Host ""
}

function Get-SysinternalsTools {
    Write-ColoredMessage "`n=== Downloading Sysinternals Tools ===" -Color Cyan

    $arch = if ([Environment]::Is64BitOperatingSystem) { "64" } else { "" }
    $toolsToDownload = @()

    # Select architecture-appropriate tools
    foreach ($tool in $script:RequiredTools.Keys) {
        if ($arch -eq "64" -and $tool -like "*64.exe") {
            $toolsToDownload += $tool
        } elseif ($arch -eq "" -and $tool -notlike "*64.exe") {
            $toolsToDownload += $tool
        }
    }

    $downloadCount = 0
    foreach ($tool in $toolsToDownload) {
        $toolPath = Join-Path $ToolsPath $tool
        $url = $script:RequiredTools[$tool]

        if (!(Test-Path $toolPath)) {
            try {
                Write-Host "[*] Downloading $tool..." -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $toolPath -UseBasicParsing -ErrorAction Stop
                Write-ColoredMessage " OK" -Color Green
                $downloadCount++
            } catch {
                Write-ColoredMessage " FAILED" -Color Red
                Write-ColoredMessage "    Error: $_" -Color Red
            }
        } else {
            Write-ColoredMessage "[*] $tool already exists, skipping" -Color Gray
        }
    }

    Write-ColoredMessage "`n[+] Downloaded $downloadCount new tools" -Color Green
}

function Get-VirusTotalReport {
    param(
        [string]$Hash
    )

    if (!$script:VTEnabled -or [string]::IsNullOrWhiteSpace($Hash)) {
        return $null
    }

    # Check cache first
    if ($script:VTCache.ContainsKey($Hash)) {
        return $script:VTCache[$Hash]
    }

    # Rate limiting
    $timeSinceLastRequest = (Get-Date) - $script:VTLastRequestTime
    if ($script:VTRequestCount -ge $script:VTRateLimit -and $timeSinceLastRequest.TotalSeconds -lt 60) {
        $sleepTime = 60 - $timeSinceLastRequest.TotalSeconds + 1
        Write-Host "[*] Rate limit reached, waiting $([math]::Round($sleepTime)) seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds $sleepTime
        $script:VTRequestCount = 0
    }

    try {
        $headers = @{
            'x-apikey' = $script:VTApiKey
        }

        $url = "https://www.virustotal.com/api/v3/files/$Hash"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop

        $script:VTRequestCount++
        $script:VTLastRequestTime = Get-Date

        $result = @{
            Malicious = $response.data.attributes.last_analysis_stats.malicious
            Suspicious = $response.data.attributes.last_analysis_stats.suspicious
            Undetected = $response.data.attributes.last_analysis_stats.undetected
            Harmless = $response.data.attributes.last_analysis_stats.harmless
            LastAnalysis = $response.data.attributes.last_analysis_date
        }

        $script:VTCache[$Hash] = $result
        return $result

    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            # File not found in VT database
            $result = @{
                Malicious = 0
                Suspicious = 0
                Undetected = 0
                Harmless = 0
                LastAnalysis = "Not found"
            }
            $script:VTCache[$Hash] = $result
            return $result
        }
        Write-Host "[!] VT API Error for hash $Hash : $_" -ForegroundColor Red
        return $null
    }
}

function Get-FileHashQuick {
    param([string]$FilePath)

    if (!(Test-Path $FilePath)) {
        return $null
    }

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        return $null
    }
}

function Get-RiskLevel {
    param(
        [string]$Signature,
        [object]$VTReport
    )

    $riskLevel = "Unknown"
    $riskScore = 0

    # Check signature
    if ([string]::IsNullOrWhiteSpace($Signature) -or $Signature -eq "(Not verified)" -or $Signature -eq "n/a") {
        $riskScore += 10
    } elseif ($Signature -like "*Unknown*" -or $Signature -like "*Cannot*") {
        $riskScore += 5
    }

    # Check VT report
    if ($VTReport) {
        $malicious = [int]$VTReport.Malicious
        $suspicious = [int]$VTReport.Suspicious

        if ($malicious -ge 5) {
            $riskScore += 20
        } elseif ($malicious -ge 1) {
            $riskScore += 10
        }

        if ($suspicious -ge 3) {
            $riskScore += 5
        }
    }

    # Determine risk level
    if ($riskScore -ge 15) {
        return "High"
    } elseif ($riskScore -ge 5) {
        return "Medium"
    } else {
        return "Low"
    }
}

function Get-AutorunEntries {
    Write-ColoredMessage "`n=== Analyzing Autorun Entries ===" -Color Cyan

    $arch = if ([Environment]::Is64BitOperatingSystem) { "autorunsc64.exe" } else { "autorunsc.exe" }
    $autorunsc = Join-Path $ToolsPath $arch

    if (!(Test-Path $autorunsc)) {
        Write-ColoredMessage "[!] Autorunsc not found!" -Color Red
        return @()
    }

    Write-Host "[*] Running Autorunsc with real-time monitoring..."
    Write-Host "[*] Monitoring CPU usage every 5 seconds (Ctrl+C to cancel)..." -ForegroundColor Yellow

    try {
        # Accept EULA automatically with -accepteula
        # Removed -h (hash calculated later) and -v (signature verification - slow/network dependent)

        # Create temp file for autorunsc output (handles UTF-16 encoding properly)
        $tempCsvPath = Join-Path $env:TEMP "autorunsc_output_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

        # Use cmd.exe with native redirection to preserve autorunsc's UTF-16 output
        # This avoids PowerShell's encoding conversion issues
        $cmdLine = "cmd.exe /c `"`"$autorunsc`" -accepteula -a * -c -s > `"$tempCsvPath`"`""

        # Start the process in background
        $startTime = Get-Date
        $processInfo = Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c `"`"$autorunsc`" -accepteula -a * -c -s > `"$tempCsvPath`"`"" `
            -NoNewWindow `
            -PassThru

        Write-Host "[*] Autorunsc process started (PID: $($processInfo.Id))" -ForegroundColor Green

        # Monitor the process
        $lastCpu = 0

        while (!$processInfo.HasExited) {
            Start-Sleep -Seconds 5

            try {
                # Find autorunsc process (child of cmd.exe)
                $proc = Get-Process -Name "autorunsc*" -ErrorAction SilentlyContinue
                if ($proc) {
                    $runtime = (Get-Date) - $startTime
                    $cpuTime = [math]::Round($proc.CPU, 2)
                    $cpuDelta = $cpuTime - $lastCpu
                    $memoryMB = [math]::Round($proc.WS / 1MB, 2)

                    # Determine status based on CPU delta
                    $status = if ($cpuDelta -gt 0.1) { "WORKING" } else { "IDLE?" }
                    $color = if ($cpuDelta -gt 0.1) { "Green" } else { "Yellow" }

                    Write-Host "`r[$(Get-Date -Format 'HH:mm:ss')] Runtime: $([math]::Round($runtime.TotalMinutes,1))min | CPU: ${cpuTime}s (Δ+${cpuDelta}s) | Memory: ${memoryMB}MB | Status: $status" -ForegroundColor $color -NoNewline

                    $lastCpu = $cpuTime
                }
            } catch {
                # Process may have just exited
            }
        }

        Write-Host "" # New line after monitoring

        # Wait for process to complete
        $processInfo.WaitForExit()

        $totalTime = (Get-Date) - $startTime
        Write-ColoredMessage "[+] Autorunsc completed in $([math]::Round($totalTime.TotalMinutes,1)) minutes (Exit code: $($processInfo.ExitCode))" -Color Green

        $entries = @()

        # Read the CSV file with proper encoding
        if (!(Test-Path $tempCsvPath)) {
            Write-ColoredMessage "[!] Autorunsc output file not found: $tempCsvPath" -Color Red
            return @()
        }

        # Read as UTF-16 LE (which is what autorunsc outputs with -c flag)
        $lines = Get-Content -Path $tempCsvPath -Encoding Unicode | Where-Object { ![string]::IsNullOrWhiteSpace($_) }

        if ($lines.Count -lt 2) {
            Write-ColoredMessage "[!] No output from Autorunsc (only $($lines.Count) lines)" -Color Yellow
            Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
            return @()
        }

        # Parse CSV output
        try {
            $csv = $lines | ConvertFrom-Csv
        } catch {
            Write-ColoredMessage "[!] Failed to parse CSV: $_" -Color Red
            return @()
        }

        $totalEntries = $csv.Count
        $currentEntry = 0

        # Helper function to safely get property value
        function Get-CsvProperty {
            param($obj, [string[]]$names)
            foreach ($name in $names) {
                $prop = $obj.PSObject.Properties[$name]
                if ($prop) {
                    return $prop.Value
                }
            }
            return $null
        }

        foreach ($entry in $csv) {
            $currentEntry++
            Write-Progress -Activity "Analyzing Autorun Entries" -Status "Processing $currentEntry of $totalEntries" -PercentComplete (($currentEntry / $totalEntries) * 100)

            # Try different possible column names (autorunsc format varies)
            $imagePath = Get-CsvProperty $entry @('Image Path', 'ImagePath', 'Path')
            $entryLocation = Get-CsvProperty $entry @('Entry Location', 'EntryLocation', 'Location')
            $entryName = Get-CsvProperty $entry @('Entry', 'Name', 'Item')
            $description = Get-CsvProperty $entry @('Description', 'Desc')
            $enabled = Get-CsvProperty $entry @('Enabled')
            $category = Get-CsvProperty $entry @('Category')
            $profile = Get-CsvProperty $entry @('Profile')

            # Try Signer first (most common), then Company, then Publisher
            $signer = Get-CsvProperty $entry @('Signer', 'Publisher')
            $company = Get-CsvProperty $entry @('Company', 'Manufacturer')
            # Use Signer if available, otherwise Company
            $publisher = if (![string]::IsNullOrWhiteSpace($signer)) { $signer } else { $company }

            $version = Get-CsvProperty $entry @('Version')
            $launchString = Get-CsvProperty $entry @('Launch String', 'LaunchString', 'Command')
            $timestamp = Get-CsvProperty $entry @('Time', 'Timestamp')

            $hash = $null
            $vtReport = $null

            # Get file hash if path exists
            if (![string]::IsNullOrWhiteSpace($imagePath) -and (Test-Path $imagePath -ErrorAction SilentlyContinue)) {
                $hash = Get-FileHashQuick -FilePath $imagePath

                if ($hash -and $script:VTEnabled) {
                    $vtReport = Get-VirusTotalReport -Hash $hash
                }
            }

            # Determine signature/publisher for risk assessment
            $signature = if (![string]::IsNullOrWhiteSpace($publisher)) { $publisher } else { "(Not verified)" }
            $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

            # Safely format VT detections (handle potential non-integer values)
            $vtDetections = "N/A"
            if ($vtReport) {
                try {
                    $mal = [int]$vtReport.Malicious
                    $sus = [int]$vtReport.Suspicious
                    $undet = [int]$vtReport.Undetected
                    $harm = [int]$vtReport.Harmless
                    $total = $mal + $sus + $undet + $harm
                    $vtDetections = "$mal/$total"
                } catch {
                    $vtDetections = "Error"
                }
            }

            $entries += [PSCustomObject]@{
                Type = "Autorun"
                Timestamp = if ($timestamp) { $timestamp.ToString() } else { "" }
                Category = if ($category) { $category.ToString() } else { "" }
                Profile = if ($profile) { $profile.ToString() } else { "" }
                Enabled = if ($enabled) { $enabled.ToString() } else { "" }
                EntryLocation = if ($entryLocation) { $entryLocation.ToString() } else { "" }
                Entry = if ($entryName) { $entryName.ToString() } else { "" }
                Description = if ($description) { $description.ToString() } else { "" }
                Signer = if ($signer) { $signer.ToString() } else { "" }
                Company = if ($company) { $company.ToString() } else { "" }
                ImagePath = if ($imagePath) { $imagePath.ToString() } else { "" }
                Version = if ($version) { $version.ToString() } else { "" }
                LaunchString = if ($launchString) { $launchString.ToString() } else { "" }
                SHA256 = if ($hash) { $hash } else { "" }
                VT_Malicious = if ($vtReport) { [string]$vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { [string]$vtReport.Suspicious } else { "N/A" }
                VT_Detections = $vtDetections
                RiskLevel = $riskLevel
            }
        }

        Write-Progress -Activity "Analyzing Autorun Entries" -Completed
        Write-ColoredMessage "[+] Found $($entries.Count) autorun entries" -Color Green

        # Clean up temp file
        if (Test-Path $tempCsvPath) {
            Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
        }

        return $entries

    } catch {
        Write-ColoredMessage "[!] Error running Autorunsc: $_" -Color Red
        # Clean up temp file on error
        if (Test-Path variable:tempCsvPath) {
            Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
        }
        return @()
    }
}

function Get-ServiceEntries {
    Write-ColoredMessage "`n=== Analyzing Services ===" -Color Cyan

    Write-Host "[*] Enumerating services..."

    try {
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName }
        $entries = @()

        $totalServices = $services.Count
        $currentService = 0

        foreach ($service in $services) {
            $currentService++
            Write-Progress -Activity "Analyzing Services" -Status "Processing $currentService of $totalServices" -PercentComplete (($currentService / $totalServices) * 100)

            # Extract executable path from PathName (may include arguments)
            $pathName = $service.PathName
            $exePath = $pathName

            # Handle quoted paths
            if ($pathName -match '^"([^"]+)"') {
                $exePath = $matches[1]
            } elseif ($pathName -match '^([^\s]+\.exe)') {
                $exePath = $matches[1]
            }

            $hash = $null
            $vtReport = $null
            $signature = "Unknown"

            if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                $hash = Get-FileHashQuick -FilePath $exePath

                if ($hash -and $script:VTEnabled) {
                    $vtReport = Get-VirusTotalReport -Hash $hash
                }

                # Get signature info
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) {
                        $signature = $sig.SignerCertificate.Subject
                    }
                } catch {
                    $signature = "(Not verified)"
                }
            }

            $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

            # Safely format VT detections
            $vtDetections = "N/A"
            if ($vtReport) {
                try {
                    $mal = [int]$vtReport.Malicious
                    $sus = [int]$vtReport.Suspicious
                    $undet = [int]$vtReport.Undetected
                    $harm = [int]$vtReport.Harmless
                    $total = $mal + $sus + $undet + $harm
                    $vtDetections = "$mal/$total"
                } catch {
                    $vtDetections = "Error"
                }
            }

            $entries += [PSCustomObject]@{
                Type = "Service"
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                State = $service.State
                StartMode = $service.StartMode
                PathName = $pathName
                ExecutablePath = $exePath
                Publisher = $signature
                SHA256 = $hash
                VT_Malicious = if ($vtReport) { [string]$vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { [string]$vtReport.Suspicious } else { "N/A" }
                VT_Detections = $vtDetections
                RiskLevel = $riskLevel
            }
        }

        Write-Progress -Activity "Analyzing Services" -Completed
        Write-ColoredMessage "[+] Found $($entries.Count) services" -Color Green
        return $entries

    } catch {
        Write-ColoredMessage "[!] Error enumerating services: $_" -Color Red
        return @()
    }
}

function Get-NetworkConnections {
    Write-ColoredMessage "`n=== Analyzing Network Connections ===" -Color Cyan

    Write-Host "[*] Gathering network connections..."

    try {
        $connections = Get-NetTCPConnection -State Listen,Established -ErrorAction Stop
        $entries = @()

        $totalConns = $connections.Count
        $currentConn = 0

        foreach ($conn in $connections) {
            $currentConn++
            Write-Progress -Activity "Analyzing Network Connections" -Status "Processing $currentConn of $totalConns" -PercentComplete (($currentConn / $totalConns) * 100)

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
                } catch {
                    # Process may have exited
                }
            }

            $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

            # Safely format VT detections
            $vtDetections = "N/A"
            if ($vtReport) {
                try {
                    $mal = [int]$vtReport.Malicious
                    $sus = [int]$vtReport.Suspicious
                    $undet = [int]$vtReport.Undetected
                    $harm = [int]$vtReport.Harmless
                    $total = $mal + $sus + $undet + $harm
                    $vtDetections = "$mal/$total"
                } catch {
                    $vtDetections = "Error"
                }
            }

            $entries += [PSCustomObject]@{
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
                VT_Malicious = if ($vtReport) { [string]$vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { [string]$vtReport.Suspicious } else { "N/A" }
                VT_Detections = $vtDetections
                RiskLevel = $riskLevel
            }
        }

        Write-Progress -Activity "Analyzing Network Connections" -Completed
        Write-ColoredMessage "[+] Found $($entries.Count) network connections" -Color Green
        return $entries

    } catch {
        Write-ColoredMessage "[!] Error gathering network connections: $_" -Color Red
        return @()
    }
}

function Get-RunningProcesses {
    Write-ColoredMessage "`n=== Analyzing Running Processes ===" -Color Cyan

    Write-Host "[*] Enumerating processes..."

    try {
        $processes = Get-Process | Where-Object { $_.Path }
        $entries = @()

        $totalProcs = $processes.Count
        $currentProc = 0

        foreach ($process in $processes) {
            $currentProc++
            Write-Progress -Activity "Analyzing Processes" -Status "Processing $currentProc of $totalProcs" -PercentComplete (($currentProc / $totalProcs) * 100)

            $exePath = $process.Path
            $hash = $null
            $vtReport = $null
            $signature = "Unknown"

            if ($exePath -and (Test-Path $exePath)) {
                $hash = Get-FileHashQuick -FilePath $exePath

                if ($hash -and $script:VTEnabled) {
                    $vtReport = Get-VirusTotalReport -Hash $hash
                }

                try {
                    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) {
                        $signature = $sig.SignerCertificate.Subject
                    }
                } catch {
                    $signature = "(Not verified)"
                }
            }

            $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

            # Safely format VT detections
            $vtDetections = "N/A"
            if ($vtReport) {
                try {
                    $mal = [int]$vtReport.Malicious
                    $sus = [int]$vtReport.Suspicious
                    $undet = [int]$vtReport.Undetected
                    $harm = [int]$vtReport.Harmless
                    $total = $mal + $sus + $undet + $harm
                    $vtDetections = "$mal/$total"
                } catch {
                    $vtDetections = "Error"
                }
            }

            $entries += [PSCustomObject]@{
                Type = "Process"
                ProcessName = $process.ProcessName
                ProcessId = $process.Id
                ExecutablePath = $exePath
                Company = $process.Company
                Description = $process.Description
                Publisher = $signature
                SHA256 = $hash
                VT_Malicious = if ($vtReport) { [string]$vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { [string]$vtReport.Suspicious } else { "N/A" }
                VT_Detections = $vtDetections
                RiskLevel = $riskLevel
            }
        }

        Write-Progress -Activity "Analyzing Processes" -Completed
        Write-ColoredMessage "[+] Found $($entries.Count) running processes" -Color Green
        return $entries

    } catch {
        Write-ColoredMessage "[!] Error enumerating processes: $_" -Color Red
        return @()
    }
}

function Export-ToExcel {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$WorksheetName
    )

    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false

        if (Test-Path $FilePath) {
            $workbook = $excel.Workbooks.Open($FilePath)
        } else {
            $workbook = $excel.Workbooks.Add()
        }

        # Check if worksheet exists
        $worksheet = $workbook.Worksheets | Where-Object { $_.Name -eq $WorksheetName }
        if (!$worksheet) {
            $worksheet = $workbook.Worksheets.Add()
            $worksheet.Name = $WorksheetName
        } else {
            $worksheet.Cells.Clear()
        }

        # Convert data to CSV format first (safer and more reliable)
        $csvData = $Data | ConvertTo-Csv -NoTypeInformation

        # Parse CSV to get clean string data
        $csvLines = $csvData
        $headers = $csvLines[0] -split ',' | ForEach-Object { $_.Trim('"') }

        # Write headers
        for ($col = 0; $col -lt $headers.Count; $col++) {
            $worksheet.Cells.Item(1, $col + 1) = $headers[$col]
        }

        # Format header row
        $headerRow = $worksheet.Rows.Item(1)
        $headerRow.Font.Bold = $true
        $headerRow.Interior.ColorIndex = 15  # Gray

        # Write data rows
        for ($row = 1; $row -lt $csvLines.Count; $row++) {
            $line = $csvLines[$row]
            # Simple CSV parsing - split by comma but respect quotes
            $values = @()
            $currentValue = ""
            $inQuotes = $false

            for ($i = 0; $i -lt $line.Length; $i++) {
                $char = $line[$i]
                if ($char -eq '"') {
                    $inQuotes = -not $inQuotes
                } elseif ($char -eq ',' -and -not $inQuotes) {
                    $values += $currentValue.Trim('"')
                    $currentValue = ""
                } else {
                    $currentValue += $char
                }
            }
            $values += $currentValue.Trim('"')

            # Write row
            for ($col = 0; $col -lt $values.Count; $col++) {
                $worksheet.Cells.Item($row + 1, $col + 1) = $values[$col]
            }

            # Apply color coding based on RiskLevel
            $riskLevel = $Data[$row - 1].RiskLevel
            $excelRow = $row + 1

            switch ($riskLevel) {
                "High" {
                    $rowRange = $worksheet.Rows.Item($excelRow)
                    $rowRange.Interior.Color = 255  # Red
                    $rowRange.Font.Color = 16777215  # White
                }
                "Medium" {
                    $rowRange = $worksheet.Rows.Item($excelRow)
                    $rowRange.Interior.Color = 65535  # Yellow
                    $rowRange.Font.Color = 0  # Black
                }
                "Low" {
                    $rowRange = $worksheet.Rows.Item($excelRow)
                    $rowRange.Interior.Color = 5287936  # Green
                    $rowRange.Font.Color = 16777215  # White
                }
            }
        }

        # Auto-fit columns
        $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null

        # Save and close
        # Excel file format constant: 51 = xlWorkbookDefault (.xlsx)
        $workbook.SaveAs($FilePath, 51)
        $workbook.Close($false)  # $false = don't save again
        $excel.Quit()

        # Clean up COM objects
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return $true

    } catch {
        Write-ColoredMessage "[!] Excel export error: $_" -Color Red
        if ($workbook) {
            try { $workbook.Close($false) } catch {}
        }
        if ($excel) {
            try { $excel.Quit() } catch {}
        }
        return $false
    }
}

function Export-Results {
    param(
        [object[]]$AutorunEntries,
        [object[]]$ServiceEntries,
        [object[]]$NetworkEntries,
        [object[]]$ProcessEntries
    )

    Write-ColoredMessage "`n=== Exporting Results ===" -Color Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME

    # Check if Excel is available
    $excelAvailable = $false
    try {
        $testExcel = New-Object -ComObject Excel.Application -ErrorAction Stop
        $testExcel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($testExcel) | Out-Null
        $excelAvailable = $true
        if ($CombinedWorkbook) {
            Write-ColoredMessage "[+] Microsoft Excel detected - will export to single combined XLSX workbook (slower)" -Color Green
        } else {
            Write-ColoredMessage "[+] Microsoft Excel detected - will export to separate XLSX files (faster)" -Color Green
        }
    } catch {
        Write-ColoredMessage "[!] Microsoft Excel not available - will export to CSV" -Color Yellow
    }

    if ($excelAvailable -and $CombinedWorkbook) {
        # Export to Excel with color coding - SINGLE WORKBOOK
        # Ensure absolute path for Excel
        $absoluteOutputPath = (Resolve-Path -Path $OutputPath).Path
        $excelPath = Join-Path $absoluteOutputPath "${hostname}_ForensicAnalysis_${timestamp}.xlsx"

        try {
            # Create Excel instance ONCE
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $excel.DisplayAlerts = $false

            # Create workbook ONCE
            $workbook = $excel.Workbooks.Add()

            # Helper function to add worksheet with data - REFACTORED for reliability
            $addWorksheet = {
                param($wb, $data, $sheetName)

                if ($data.Count -eq 0) { return }

                Write-Host "[*] Adding $sheetName worksheet..."

                # Add new worksheet
                $worksheet = $wb.Worksheets.Add()
                $worksheet.Name = $sheetName

                # Convert data to CSV format first (safer than direct Excel manipulation)
                $csvData = $data | ConvertTo-Csv -NoTypeInformation

                # Parse CSV to get clean string data
                $csvLines = $csvData
                $headers = $csvLines[0] -split ',' | ForEach-Object { $_.Trim('"') }

                # Write headers
                for ($col = 0; $col -lt $headers.Count; $col++) {
                    $worksheet.Cells.Item(1, $col + 1) = $headers[$col]
                }

                # Format header row
                $headerRow = $worksheet.Rows.Item(1)
                $headerRow.Font.Bold = $true
                $headerRow.Interior.ColorIndex = 15  # Gray

                # Write data rows
                for ($row = 1; $row -lt $csvLines.Count; $row++) {
                    $line = $csvLines[$row]
                    # Simple CSV parsing - split by comma but respect quotes
                    $values = @()
                    $currentValue = ""
                    $inQuotes = $false

                    for ($i = 0; $i -lt $line.Length; $i++) {
                        $char = $line[$i]
                        if ($char -eq '"') {
                            $inQuotes = -not $inQuotes
                        } elseif ($char -eq ',' -and -not $inQuotes) {
                            $values += $currentValue.Trim('"')
                            $currentValue = ""
                        } else {
                            $currentValue += $char
                        }
                    }
                    $values += $currentValue.Trim('"')

                    # Write row
                    for ($col = 0; $col -lt $values.Count; $col++) {
                        $worksheet.Cells.Item($row + 1, $col + 1) = $values[$col]
                    }

                    # Apply color coding based on RiskLevel (column varies by sheet)
                    $riskLevel = $data[$row - 1].RiskLevel
                    $excelRow = $row + 1

                    switch ($riskLevel) {
                        "High" {
                            $rowRange = $worksheet.Rows.Item($excelRow)
                            $rowRange.Interior.Color = 255  # Red
                            $rowRange.Font.Color = 16777215  # White
                        }
                        "Medium" {
                            $rowRange = $worksheet.Rows.Item($excelRow)
                            $rowRange.Interior.Color = 65535  # Yellow
                            $rowRange.Font.Color = 0  # Black
                        }
                        "Low" {
                            $rowRange = $worksheet.Rows.Item($excelRow)
                            $rowRange.Interior.Color = 5287936  # Green
                            $rowRange.Font.Color = 16777215  # White
                        }
                    }
                }

                # Auto-fit columns
                $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
            }

            # Add all worksheets
            if ($AutorunEntries.Count -gt 0) {
                & $addWorksheet $workbook $AutorunEntries "Autoruns"
            }
            if ($ServiceEntries.Count -gt 0) {
                & $addWorksheet $workbook $ServiceEntries "Services"
            }
            if ($NetworkEntries.Count -gt 0) {
                & $addWorksheet $workbook $NetworkEntries "Network"
            }
            if ($ProcessEntries.Count -gt 0) {
                & $addWorksheet $workbook $ProcessEntries "Processes"
            }

            # Delete the default blank worksheets
            $excel.DisplayAlerts = $false
            foreach ($sheet in $workbook.Worksheets) {
                if ($sheet.Name -like "Sheet*" -and $sheet.UsedRange.Cells.Count -eq 1) {
                    try {
                        $sheet.Delete()
                    } catch {
                        # Ignore if we can't delete (might be the last sheet)
                    }
                }
            }

            # Save workbook
            Write-Host "[*] Saving workbook..."
            # Excel file format constant: 51 = xlWorkbookDefault (.xlsx)
            $workbook.SaveAs($excelPath, 51)
            $workbook.Close($false)
            $excel.Quit()

            # Clean up COM objects
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Write-ColoredMessage "`n[+] Excel report saved: $excelPath" -Color Green
            return $excelPath

        } catch {
            Write-ColoredMessage "[!] Excel export failed: $_" -Color Red
            Write-ColoredMessage "[!] Falling back to CSV export" -Color Yellow

            # Cleanup on error
            if ($workbook) {
                try { $workbook.Close($false) } catch {}
            }
            if ($excel) {
                try { $excel.Quit() } catch {}
            }

            $excelAvailable = $false
        }
    }

    if ($excelAvailable -and !$CombinedWorkbook) {
        # Export to separate Excel files (faster than combined workbook)
        $excelPaths = @()

        # Resolve absolute path once
        $absoluteOutputPath = (Resolve-Path -Path $OutputPath).Path

        try {
            if ($AutorunEntries.Count -gt 0) {
                $excelPath = Join-Path $absoluteOutputPath "${hostname}_Autoruns_${timestamp}.xlsx"
                if (Export-ToExcel -Data $AutorunEntries -FilePath $excelPath -WorksheetName "Autoruns") {
                    Write-ColoredMessage "[+] Autoruns Excel saved: $excelPath" -Color Green
                    $excelPaths += $excelPath
                }
            }

            if ($ServiceEntries.Count -gt 0) {
                $excelPath = Join-Path $absoluteOutputPath "${hostname}_Services_${timestamp}.xlsx"
                if (Export-ToExcel -Data $ServiceEntries -FilePath $excelPath -WorksheetName "Services") {
                    Write-ColoredMessage "[+] Services Excel saved: $excelPath" -Color Green
                    $excelPaths += $excelPath
                }
            }

            if ($NetworkEntries.Count -gt 0) {
                $excelPath = Join-Path $absoluteOutputPath "${hostname}_Network_${timestamp}.xlsx"
                if (Export-ToExcel -Data $NetworkEntries -FilePath $excelPath -WorksheetName "Network") {
                    Write-ColoredMessage "[+] Network Excel saved: $excelPath" -Color Green
                    $excelPaths += $excelPath
                }
            }

            if ($ProcessEntries.Count -gt 0) {
                $excelPath = Join-Path $absoluteOutputPath "${hostname}_Processes_${timestamp}.xlsx"
                if (Export-ToExcel -Data $ProcessEntries -FilePath $excelPath -WorksheetName "Processes") {
                    Write-ColoredMessage "[+] Processes Excel saved: $excelPath" -Color Green
                    $excelPaths += $excelPath
                }
            }

            if ($excelPaths.Count -gt 0) {
                Write-ColoredMessage "`n[+] Exported $($excelPaths.Count) Excel files with color coding" -Color Green
                return $excelPaths -join ", "
            }
        } catch {
            Write-ColoredMessage "[!] Separate Excel export failed: $_" -Color Red
            Write-ColoredMessage "[!] Falling back to CSV export" -Color Yellow
            $excelAvailable = $false
        }
    }

    if (!$excelAvailable) {
        # Export to CSV
        $csvPaths = @()

        if ($AutorunEntries.Count -gt 0) {
            $csvPath = Join-Path $OutputPath "${hostname}_Autoruns_${timestamp}.csv"
            $AutorunEntries | Export-Csv -Path $csvPath -NoTypeInformation
            Write-ColoredMessage "[+] Autoruns CSV saved: $csvPath" -Color Green
            $csvPaths += $csvPath
        }

        if ($ServiceEntries.Count -gt 0) {
            $csvPath = Join-Path $OutputPath "${hostname}_Services_${timestamp}.csv"
            $ServiceEntries | Export-Csv -Path $csvPath -NoTypeInformation
            Write-ColoredMessage "[+] Services CSV saved: $csvPath" -Color Green
            $csvPaths += $csvPath
        }

        if ($NetworkEntries.Count -gt 0) {
            $csvPath = Join-Path $OutputPath "${hostname}_Network_${timestamp}.csv"
            $NetworkEntries | Export-Csv -Path $csvPath -NoTypeInformation
            Write-ColoredMessage "[+] Network CSV saved: $csvPath" -Color Green
            $csvPaths += $csvPath
        }

        if ($ProcessEntries.Count -gt 0) {
            $csvPath = Join-Path $OutputPath "${hostname}_Processes_${timestamp}.csv"
            $ProcessEntries | Export-Csv -Path $csvPath -NoTypeInformation
            Write-ColoredMessage "[+] Processes CSV saved: $csvPath" -Color Green
            $csvPaths += $csvPath
        }

        Write-ColoredMessage "`n[!] Note: CSV files do not include color coding. Use Excel for color-coded risk levels." -Color Yellow
        return $csvPaths -join ", "
    }
}

function Show-Summary {
    param(
        [object[]]$AutorunEntries,
        [object[]]$ServiceEntries,
        [object[]]$NetworkEntries,
        [object[]]$ProcessEntries
    )

    $allEntries = @()
    $allEntries += $AutorunEntries
    $allEntries += $ServiceEntries
    $allEntries += $NetworkEntries
    $allEntries += $ProcessEntries

    $highRisk = ($allEntries | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRisk = ($allEntries | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowRisk = ($allEntries | Where-Object { $_.RiskLevel -eq "Low" }).Count

    Write-ColoredMessage "`n=== Analysis Summary ===" -Color Cyan
    Write-Host "Total Items Analyzed: $($allEntries.Count)"
    Write-ColoredMessage "  High Risk (Red):    $highRisk" -Color Red
    Write-ColoredMessage "  Medium Risk (Yellow): $mediumRisk" -Color Yellow
    Write-ColoredMessage "  Low Risk (Green):   $lowRisk" -Color Green

    Write-Host "`nBreakdown by Category:"
    Write-Host "  Autoruns:   $($AutorunEntries.Count)"
    Write-Host "  Services:   $($ServiceEntries.Count)"
    Write-Host "  Network:    $($NetworkEntries.Count)"
    Write-Host "  Processes:  $($ProcessEntries.Count)"

    if ($script:VTEnabled) {
        $vtScanned = ($allEntries | Where-Object { $_.VT_Detections -ne "N/A" }).Count
        Write-Host "`nVirusTotal Scans: $vtScanned items"
    }

    if ($highRisk -gt 0) {
        Write-ColoredMessage "`n[!] WARNING: Found $highRisk high-risk items requiring immediate attention!" -Color Red
    }
}

# Main execution
try {
    $ErrorActionPreference = "Stop"

    Initialize-Environment
    Get-SysinternalsTools

    # Prompt for VT API key if enabled but not provided
    if ($EnableVirusTotal -and [string]::IsNullOrWhiteSpace($script:VTApiKey)) {
        $script:VTApiKey = Read-Host "Enter your VirusTotal API key"
        $script:VTEnabled = ![string]::IsNullOrWhiteSpace($script:VTApiKey)
    }

    # Run analyses
    $autorunEntries = Get-AutorunEntries
    $serviceEntries = Get-ServiceEntries
    $networkEntries = Get-NetworkConnections
    $processEntries = Get-RunningProcesses

    # Export results
    $reportPath = Export-Results -AutorunEntries $autorunEntries -ServiceEntries $serviceEntries -NetworkEntries $networkEntries -ProcessEntries $processEntries

    # Show summary
    Show-Summary -AutorunEntries $autorunEntries -ServiceEntries $serviceEntries -NetworkEntries $networkEntries -ProcessEntries $processEntries

    Write-ColoredMessage "`n=== Forensic Analysis Complete ===" -Color Cyan
    Write-ColoredMessage "Report(s): $reportPath" -Color Green

    # Cleanup Sysinternals tools if requested
    if ($CleanupTools) {
        Write-ColoredMessage "`n[*] Cleaning up Sysinternals tools..." -Color Yellow
        if (Test-Path $ToolsPath) {
            try {
                Remove-Item -Path $ToolsPath -Recurse -Force -ErrorAction Stop
                Write-ColoredMessage "[+] Sysinternals tools deleted successfully" -Color Green
            } catch {
                Write-ColoredMessage "[!] Warning: Failed to delete tools directory: $_" -Color Yellow
            }
        } else {
            Write-ColoredMessage "[*] Tools directory not found, nothing to clean up" -Color Gray
        }
    }

} catch {
    Write-ColoredMessage "`n[!] Fatal Error: $_" -Color Red
    Write-ColoredMessage $_.ScriptStackTrace -Color Red

    # Cleanup tools even on error if requested
    if ($CleanupTools -and (Test-Path $ToolsPath)) {
        Write-ColoredMessage "`n[*] Cleaning up Sysinternals tools (error cleanup)..." -Color Yellow
        try {
            Remove-Item -Path $ToolsPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-ColoredMessage "[+] Sysinternals tools deleted" -Color Green
        } catch {
            # Silent failure on error cleanup
        }
    }

    exit 1
}
