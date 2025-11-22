# Example Usage Scripts for Forensic Investigator
# Copy and modify these examples for your specific needs

# ============================================
# Example 1: Basic Analysis (No VirusTotal)
# ============================================
# Quick system analysis without VirusTotal scanning
# Results saved to default location: .\ForensicReports

.\Invoke-ForensicAnalysis.ps1


# ============================================
# Example 2: Full Analysis with VirusTotal
# ============================================
# Comprehensive analysis with malware detection
# Replace YOUR_API_KEY with your actual VirusTotal API key

.\Invoke-ForensicAnalysis.ps1 `
    -EnableVirusTotal `
    -VirusTotalApiKey "YOUR_API_KEY"


# ============================================
# Example 3: Custom Output Location
# ============================================
# Save reports to a specific directory
# Useful for organizing multiple investigations

.\Invoke-ForensicAnalysis.ps1 `
    -OutputPath "C:\Investigations\Case-2024-001\Reports" `
    -ToolsPath "C:\Investigations\Tools"


# ============================================
# Example 4: Complete Investigation Setup
# ============================================
# Full investigation with custom paths and VirusTotal

$ApiKey = "your-virustotal-api-key-here"
$CaseName = "Incident-2024-001"
$CaseDir = "C:\Investigations\$CaseName"

# Create case directory structure
New-Item -ItemType Directory -Path "$CaseDir\Reports" -Force | Out-Null
New-Item -ItemType Directory -Path "$CaseDir\Tools" -Force | Out-Null

# Run analysis
.\Invoke-ForensicAnalysis.ps1 `
    -EnableVirusTotal `
    -VirusTotalApiKey $ApiKey `
    -OutputPath "$CaseDir\Reports" `
    -ToolsPath "$CaseDir\Tools"

Write-Host "Investigation complete! Results saved to: $CaseDir\Reports"


# ============================================
# Example 5: Batch Analysis (Multiple Systems)
# ============================================
# Analyze multiple systems remotely (requires PowerShell Remoting)

$Systems = @("WORKSTATION-01", "WORKSTATION-02", "SERVER-01")
$ApiKey = "your-api-key"
$OutputBase = "C:\Investigations\MultiSystem"

foreach ($System in $Systems) {
    Write-Host "Analyzing $System..." -ForegroundColor Cyan

    Invoke-Command -ComputerName $System -FilePath ".\Invoke-ForensicAnalysis.ps1" -ArgumentList @{
        OutputPath = "$OutputBase\$System\Reports"
        ToolsPath = "$OutputBase\$System\Tools"
        EnableVirusTotal = $true
        VirusTotalApiKey = $ApiKey
    }

    Write-Host "Completed: $System" -ForegroundColor Green
}


# ============================================
# Example 6: Scheduled Analysis
# ============================================
# Set up a scheduled task for regular monitoring

$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument @"
-NoProfile -ExecutionPolicy Bypass -File "C:\Tools\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\MonitoringReports"
"@

$Trigger = New-ScheduledTaskTrigger -Daily -At 2am

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Daily-Forensic-Scan" -Action $Action -Trigger $Trigger -Principal $Principal


# ============================================
# Example 7: Quick Triage (Fast Analysis)
# ============================================
# For rapid incident response, analyze only high-risk items
# This runs the full analysis but you can filter results afterward

.\Invoke-ForensicAnalysis.ps1 -OutputPath ".\Triage"

# Then filter for high-risk items only
$Report = Import-Csv ".\Triage\*_Autoruns_*.csv"
$HighRisk = $Report | Where-Object { $_.RiskLevel -eq "High" }
$HighRisk | Export-Csv ".\Triage\HighRisk-Only.csv" -NoTypeInformation

Write-Host "Found $($HighRisk.Count) high-risk items"


# ============================================
# Example 8: Using Environment Variables
# ============================================
# Store API key in environment variable for security

# Set environment variable (do this once):
# [System.Environment]::SetEnvironmentVariable("VT_API_KEY", "your-key", "User")

# Then use it in the script:
$ApiKey = [System.Environment]::GetEnvironmentVariable("VT_API_KEY", "User")

if ($ApiKey) {
    .\Invoke-ForensicAnalysis.ps1 -EnableVirusTotal -VirusTotalApiKey $ApiKey
} else {
    Write-Host "VirusTotal API key not found in environment variables" -ForegroundColor Yellow
    .\Invoke-ForensicAnalysis.ps1
}


# ============================================
# Example 9: Analysis with Error Logging
# ============================================
# Capture all output and errors to a log file

$LogFile = ".\forensic-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

.\Invoke-ForensicAnalysis.ps1 `
    -EnableVirusTotal `
    -VirusTotalApiKey "your-key" `
    -Verbose *>&1 | Tee-Object -FilePath $LogFile

Write-Host "Log saved to: $LogFile"


# ============================================
# Example 10: Post-Analysis Review
# ============================================
# After analysis, review high-risk findings

# Find the most recent Excel report
$LatestReport = Get-ChildItem ".\ForensicReports\*.xlsx" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($LatestReport) {
    # Open in Excel for review
    Start-Process excel.exe -ArgumentList $LatestReport.FullName

    Write-Host "Opening report: $($LatestReport.Name)" -ForegroundColor Green
    Write-Host "Review items highlighted in RED for immediate investigation" -ForegroundColor Red
} else {
    Write-Host "No Excel reports found. Check CSV files in .\ForensicReports\" -ForegroundColor Yellow
}
