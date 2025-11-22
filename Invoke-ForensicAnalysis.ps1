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

.EXAMPLE
    .\Invoke-ForensicAnalysis.ps1 -EnableVirusTotal -VirusTotalApiKey "your-api-key"

.EXAMPLE
    .\Invoke-ForensicAnalysis.ps1 -OutputPath "C:\Reports"
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

#Requires -RunAsAdministrator

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

    Write-Host "[*] Running Autorunsc (this may take a few minutes)..."

    try {
        # Accept EULA automatically with -accepteula
        # Removed -h (hash calculated later) and -v (signature verification - slow/network dependent)
        $output = & $autorunsc -accepteula -a * -c -s 2>&1 | Out-String

        $entries = @()
        $lines = $output -split "`n" | Where-Object { $_ -match '\S' }

        if ($lines.Count -lt 2) {
            Write-ColoredMessage "[!] No output from Autorunsc" -Color Yellow
            return @()
        }

        # Parse CSV output
        $csv = $lines | ConvertFrom-Csv

        $totalEntries = $csv.Count
        $currentEntry = 0

        foreach ($entry in $csv) {
            $currentEntry++
            Write-Progress -Activity "Analyzing Autorun Entries" -Status "Processing $currentEntry of $totalEntries" -PercentComplete (($currentEntry / $totalEntries) * 100)

            $imagePath = $entry.'Image Path'
            $hash = $null
            $vtReport = $null

            # Get file hash if path exists
            if (![string]::IsNullOrWhiteSpace($imagePath) -and (Test-Path $imagePath -ErrorAction SilentlyContinue)) {
                $hash = Get-FileHashQuick -FilePath $imagePath

                if ($hash -and $script:VTEnabled) {
                    $vtReport = Get-VirusTotalReport -Hash $hash
                }
            }

            $signature = if ($entry.Publisher) { $entry.Publisher } else { "(Not verified)" }
            $riskLevel = Get-RiskLevel -Signature $signature -VTReport $vtReport

            $entries += [PSCustomObject]@{
                Type = "Autorun"
                EntryLocation = $entry.'Entry Location'
                Entry = $entry.Entry
                Description = $entry.Description
                Publisher = $signature
                ImagePath = $imagePath
                Version = $entry.Version
                LaunchString = $entry.'Launch String'
                SHA256 = $hash
                VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { $vtReport.Suspicious } else { "N/A" }
                VT_Detections = if ($vtReport) { "$($vtReport.Malicious)/$($vtReport.Malicious + $vtReport.Suspicious + $vtReport.Undetected + $vtReport.Harmless)" } else { "N/A" }
                RiskLevel = $riskLevel
                Timestamp = $entry.Time
            }
        }

        Write-Progress -Activity "Analyzing Autorun Entries" -Completed
        Write-ColoredMessage "[+] Found $($entries.Count) autorun entries" -Color Green
        return $entries

    } catch {
        Write-ColoredMessage "[!] Error running Autorunsc: $_" -Color Red
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
                VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { $vtReport.Suspicious } else { "N/A" }
                VT_Detections = if ($vtReport) { "$($vtReport.Malicious)/$($vtReport.Malicious + $vtReport.Suspicious + $vtReport.Undetected + $vtReport.Harmless)" } else { "N/A" }
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
                VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { $vtReport.Suspicious } else { "N/A" }
                VT_Detections = if ($vtReport) { "$($vtReport.Malicious)/$($vtReport.Malicious + $vtReport.Suspicious + $vtReport.Undetected + $vtReport.Harmless)" } else { "N/A" }
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

            $entries += [PSCustomObject]@{
                Type = "Process"
                ProcessName = $process.ProcessName
                ProcessId = $process.Id
                ExecutablePath = $exePath
                Company = $process.Company
                Description = $process.Description
                Publisher = $signature
                SHA256 = $hash
                VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "N/A" }
                VT_Suspicious = if ($vtReport) { $vtReport.Suspicious } else { "N/A" }
                VT_Detections = if ($vtReport) { "$($vtReport.Malicious)/$($vtReport.Malicious + $vtReport.Suspicious + $vtReport.Undetected + $vtReport.Harmless)" } else { "N/A" }
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

        # Get column headers
        $properties = $Data[0].PSObject.Properties.Name

        # Write headers
        for ($i = 0; $i -lt $properties.Count; $i++) {
            $worksheet.Cells.Item(1, $i + 1) = $properties[$i]
            $worksheet.Cells.Item(1, $i + 1).Font.Bold = $true
            $worksheet.Cells.Item(1, $i + 1).Interior.ColorIndex = 15  # Gray
        }

        # Write data and apply color coding
        $row = 2
        foreach ($item in $Data) {
            for ($i = 0; $i -lt $properties.Count; $i++) {
                $value = $item.($properties[$i])
                $worksheet.Cells.Item($row, $i + 1) = if ($value) { $value.ToString() } else { "" }
            }

            # Apply color coding based on RiskLevel
            $riskLevel = $item.RiskLevel
            switch ($riskLevel) {
                "High" {
                    $worksheet.Rows.Item($row).Interior.Color = 255  # Red (BGR format)
                    $worksheet.Rows.Item($row).Font.Color = 16777215  # White
                }
                "Medium" {
                    $worksheet.Rows.Item($row).Interior.Color = 65535  # Yellow (BGR format)
                    $worksheet.Rows.Item($row).Font.Color = 0  # Black
                }
                "Low" {
                    $worksheet.Rows.Item($row).Interior.Color = 5287936  # Green (BGR format)
                    $worksheet.Rows.Item($row).Font.Color = 16777215  # White
                }
            }

            $row++
        }

        # Auto-fit columns
        $usedRange = $worksheet.UsedRange
        $usedRange.EntireColumn.AutoFit() | Out-Null

        # Save and close
        $workbook.SaveAs($FilePath)
        $workbook.Close()
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
        $excel = New-Object -ComObject Excel.Application -ErrorAction Stop
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        $excelAvailable = $true
        Write-ColoredMessage "[+] Microsoft Excel detected - will export to XLSX with color coding" -Color Green
    } catch {
        Write-ColoredMessage "[!] Microsoft Excel not available - will export to CSV" -Color Yellow
    }

    if ($excelAvailable) {
        # Export to Excel with color coding
        $excelPath = Join-Path $OutputPath "${hostname}_ForensicAnalysis_${timestamp}.xlsx"

        $success = $true
        if ($AutorunEntries.Count -gt 0) {
            Write-Host "[*] Exporting Autoruns to Excel..."
            $success = Export-ToExcel -Data $AutorunEntries -FilePath $excelPath -WorksheetName "Autoruns"
        }

        if ($success -and $ServiceEntries.Count -gt 0) {
            Write-Host "[*] Exporting Services to Excel..."
            $success = Export-ToExcel -Data $ServiceEntries -FilePath $excelPath -WorksheetName "Services"
        }

        if ($success -and $NetworkEntries.Count -gt 0) {
            Write-Host "[*] Exporting Network Connections to Excel..."
            $success = Export-ToExcel -Data $NetworkEntries -FilePath $excelPath -WorksheetName "Network"
        }

        if ($success -and $ProcessEntries.Count -gt 0) {
            Write-Host "[*] Exporting Processes to Excel..."
            $success = Export-ToExcel -Data $ProcessEntries -FilePath $excelPath -WorksheetName "Processes"
        }

        if ($success) {
            Write-ColoredMessage "`n[+] Excel report saved: $excelPath" -Color Green
            return $excelPath
        } else {
            Write-ColoredMessage "[!] Excel export failed, falling back to CSV" -Color Yellow
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

} catch {
    Write-ColoredMessage "`n[!] Fatal Error: $_" -Color Red
    Write-ColoredMessage $_.ScriptStackTrace -Color Red
    exit 1
}
