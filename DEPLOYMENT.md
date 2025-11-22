# Remote Deployment Guide

This guide covers deploying the Forensic Investigation Tool remotely via IEX (Invoke-Expression) and RMM platforms like ConnectWise, Datto RMM, NinjaRMM, and Kaseya.

## Table of Contents

- [IEX Deployment](#iex-deployment)
- [ConnectWise Automate](#connectwise-automate)
- [ConnectWise Command (ScreenConnect)](#connectwise-command-screenconnect)
- [Datto RMM](#datto-rmm)
- [NinjaRMM](#ninjarmm)
- [Other RMM Platforms](#other-rmm-platforms)
- [Security Considerations](#security-considerations)

---

## IEX Deployment

### Method 1: Direct IEX from URL

**Prerequisites:**
- Script hosted on accessible web server (GitHub, Azure Blob, etc.)
- PowerShell ExecutionPolicy allows remote scripts

**Basic Execution:**
```powershell
# Without VirusTotal
iex (irm "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1")

# With VirusTotal (API key in environment variable)
$env:VT_API_KEY = "your-api-key-here"
iex (irm "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1")
```

**One-liner with all parameters:**
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "$env:VT_API_KEY='your-key'; iex (irm 'https://your-url/Remote-Launch.ps1')"
```

### Method 2: IEX with Parameter Injection

```powershell
# Download and execute with custom parameters
$params = @{
    EnableVirusTotal = $true
    VirusTotalApiKey = "your-api-key"
    OutputPath = "C:\TechReports"
}

iex "& { $(irm 'https://your-url/Remote-Launch.ps1') } @params"
```

### Method 3: Two-Stage Deployment

```powershell
# Stage 1: Download
Invoke-WebRequest -Uri "https://your-url/Remote-Launch.ps1" -OutFile "$env:TEMP\launch.ps1"

# Stage 2: Execute
& "$env:TEMP\launch.ps1" -EnableVirusTotal -VirusTotalApiKey "your-key"

# Cleanup
Remove-Item "$env:TEMP\launch.ps1" -Force
```

---

## ConnectWise Automate

### Script Template

Create a new script in ConnectWise Automate:

**Script Name:** Forensic Investigation - Full Scan
**Script Type:** PowerShell
**Run As:** System

**Script Body:**
```powershell
# ConnectWise Automate - Forensic Investigation Script
# Required Variables: @VT_API_KEY@ (optional)

$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Configuration
$ScriptUrl = "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1"
$OutputPath = "C:\Windows\Temp\LTSvc\Forensics"
$VTApiKey = "@VT_API_KEY@"  # Set in Automate variables

# Log function for Automate
function Write-AutomateLog {
    param([string]$Message)
    Write-Host "[AUTOMATE] $Message"
}

Write-AutomateLog "Starting Forensic Investigation"
Write-AutomateLog "Computer: $env:COMPUTERNAME"

# Download and execute
try {
    $script = Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing
    $tempScript = "$env:TEMP\forensic-launch.ps1"
    $script | Out-File -FilePath $tempScript -Encoding UTF8 -Force

    # Execute with parameters
    $params = @{
        OutputPath = $OutputPath
        ToolsPath = "C:\Windows\Temp\LTSvc\Tools"
    }

    if (![string]::IsNullOrWhiteSpace($VTApiKey) -and $VTApiKey -ne "@VT_API_KEY@") {
        $params.EnableVirusTotal = $true
        $params.VirusTotalApiKey = $VTApiKey
        Write-AutomateLog "VirusTotal scanning enabled"
    }

    & $tempScript @params

    Write-AutomateLog "Investigation completed"
    Write-AutomateLog "Results: $OutputPath"

    # Upload results to Automate (optional)
    # Use Get-ChildItem and Upload-LTFile if available
    $reports = Get-ChildItem -Path $OutputPath -Filter "*.xlsx" -ErrorAction SilentlyContinue
    if ($reports) {
        Write-AutomateLog "Found $($reports.Count) report(s)"
        # Upload logic here
    }

} catch {
    Write-AutomateLog "ERROR: $_"
    exit 1
}

# Cleanup
Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
exit 0
```

### Variables to Set in Automate

1. Navigate to **System > Manage > Global Variables**
2. Add Variable:
   - **Name:** `VT_API_KEY`
   - **Value:** Your VirusTotal API key
   - **Type:** Secured (encrypted)

### Deployment Options

**Option 1: On-Demand via Right-Click**
- Assign script to computer or location
- Right-click computer → Scripts → Run Now

**Option 2: Scheduled Deployment**
- Create a monitor
- Schedule: Weekly (e.g., Sunday 2 AM)
- Action: Run script "Forensic Investigation - Full Scan"

**Option 3: Alert Response**
- Create alert for specific events
- Response: Execute forensic scan
- Useful for incident response

---

## ConnectWise Command (ScreenConnect)

### Method 1: Commands Tab

1. Open ConnectWise Command session
2. Go to **Commands** tab
3. Select **PowerShell**
4. Paste command:

```powershell
# Quick scan (no VT)
iex (irm "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1")

# With VirusTotal
$env:VT_API_KEY = "your-api-key"
iex (irm "https://your-url/Remote-Launch.ps1")
```

### Method 2: Extension Command

Create a reusable command extension:

**Extension Name:** Forensic Investigation Scan

**Command:**
```powershell
#timeout=3600000
#maxlength=5242880

param(
    [string]$VTApiKey = ""
)

$launchUrl = "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1"

try {
    if (![string]::IsNullOrWhiteSpace($VTApiKey)) {
        $env:VT_API_KEY = $VTApiKey
    }

    iex (Invoke-RestMethod -Uri $launchUrl -UseBasicParsing)

    # Show results location
    $results = Get-ChildItem "$env:TEMP\ForensicReports" -ErrorAction SilentlyContinue
    if ($results) {
        Write-Host "`nResults available at: $($results[0].DirectoryName)"
        Write-Host "Files: $($results.Count)"
    }
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
```

**Usage:**
- Select target machine(s)
- Run extension
- Optionally provide VT API key when prompted

### Method 3: Backstage Command

For organization-wide deployment:

1. Go to **Admin** → **Extensions** → **Backstage**
2. Create new PowerShell command
3. Add to toolbar for quick access

---

## Datto RMM

### Component Setup

**Component Name:** Forensic Investigation Tool
**Component Type:** PowerShell Script

```powershell
# Datto RMM Component
# Environment Variables: VT_API_KEY (site or account variable)

$ScriptUrl = $env:script_url
if ([string]::IsNullOrWhiteSpace($ScriptUrl)) {
    $ScriptUrl = "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1"
}

$VTKey = $env:VT_API_KEY
$OutputPath = "C:\ProgramData\CentraStage\Forensics"

# Download and execute
$script = Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing
$tempScript = "$env:TEMP\datto-forensic.ps1"
$script | Out-File -FilePath $tempScript -Encoding UTF8

$params = @{
    OutputPath = $OutputPath
}

if (![string]::IsNullOrWhiteSpace($VTKey)) {
    $params.EnableVirusTotal = $true
    $params.VirusTotalApiKey = $VTKey
}

& $tempScript @params

# Set Datto UDF with report path
# Set-DrmmSiteCustomField -Name "LastForensicScan" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
```

### Quick Job Deployment

1. **Jobs** → **Quick Job**
2. Select **Component**: Forensic Investigation Tool
3. Select target devices
4. Run immediately or schedule

---

## NinjaRMM

### Script Template

**Script Name:** Forensic-Investigation-Scan
**Category:** Security
**Script Type:** PowerShell

```powershell
# NinjaRMM Script
# Script Variable: vtApiKey (optional, Role Variable)

$ScriptUrl = "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1"
$OutputPath = "C:\ProgramData\NinjaRMMAgent\Forensics"

# Get VT API key from Ninja custom field or script variable
$VTKey = Ninja-Property-Get vtApiKey

try {
    $script = Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing
    $tempScript = "$env:TEMP\ninja-forensic.ps1"
    $script | Out-File -FilePath $tempScript -Encoding UTF8

    $params = @{
        OutputPath = $OutputPath
    }

    if (![string]::IsNullOrWhiteSpace($VTKey)) {
        $params.EnableVirusTotal = $true
        $params.VirusTotalApiKey = $VTKey
    }

    & $tempScript @params

    # Update custom field with completion status
    Ninja-Property-Set lastForensicScan (Get-Date -Format "yyyy-MM-dd")

    Write-Host "SUCCESS: Forensic scan completed"
    exit 0

} catch {
    Write-Host "FAILED: $_"
    exit 1
} finally {
    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
}
```

### Deployment

1. **Administration** → **Scripts**
2. Create new script with above content
3. Deploy via:
   - **Manual Run**: Select devices → Run Script
   - **Scheduled Task**: Create automation policy
   - **Condition**: Trigger on specific events

---

## Other RMM Platforms

### Kaseya VSA

```powershell
# Kaseya Agent Procedure
executeShellCommand('powershell.exe -ExecutionPolicy Bypass -Command "iex (irm ''https://your-url/Remote-Launch.ps1'')"')
```

### Syncro

```powershell
# Syncro Script
$OutputPath = "C:\ProgramData\Syncro\Forensics"
iex (irm "https://your-url/Remote-Launch.ps1")
```

### Atera

```powershell
# Atera IT Automation Script
# Add as IT Automation Profile
iex (irm "https://your-url/Remote-Launch.ps1")
```

### N-able N-central

```powershell
# N-central AMP Script
& {
    $env:VT_API_KEY = "%VT_API_KEY%"  # N-central parameter
    iex (irm "https://your-url/Remote-Launch.ps1")
}
```

---

## Security Considerations

### 1. Script Hosting Security

**Recommended Hosting:**
- Private GitHub repository (with authentication)
- Azure Blob Storage (with SAS tokens)
- Internal web server (HTTPS only)

**Avoid:**
- Public repositories without version control
- HTTP (unencrypted) hosting
- Unversioned URLs

### 2. API Key Management

**Best Practices:**
- Never hardcode API keys in scripts
- Use RMM platform's encrypted variables
- Rotate keys regularly
- Use separate keys per MSP/client

**Storage Options:**
- RMM encrypted variables
- Azure Key Vault
- Environment variables (for testing only)

### 3. Execution Policy

Always specify execution policy in RMM commands:
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "..."
```

### 4. Logging and Auditing

**Track:**
- Which systems were scanned
- When scans occurred
- Who initiated scans
- Results/findings

**Implementation:**
```powershell
# Add to Remote-Launch.ps1 or wrapper
$logEntry = @{
    Timestamp = Get-Date
    Computer = $env:COMPUTERNAME
    User = $env:USERNAME
    Initiator = "RMM-System"
} | ConvertTo-Json

# Send to logging endpoint
Invoke-RestMethod -Uri "https://your-logging-api/endpoint" -Method Post -Body $logEntry
```

### 5. Network Requirements

**Outbound Access Required:**
- `live.sysinternals.com` (443) - Download tools
- `www.virustotal.com` (443) - API calls (if enabled)
- Your script hosting location (443)

**Firewall Rules:**
Allow PowerShell/RMM agents to access these endpoints.

### 6. Clean Up

Always clean up after execution:
```powershell
# Remove downloaded tools (optional - keep for reuse)
Remove-Item $ToolsPath -Recurse -Force -ErrorAction SilentlyContinue

# Remove reports after upload (if uploading to central location)
Remove-Item $OutputPath -Recurse -Force -ErrorAction SilentlyContinue
```

---

## Troubleshooting

### IEX fails with "Cannot download"

**Solution:**
```powershell
# Test connectivity
Test-NetConnection -ComputerName raw.githubusercontent.com -Port 443

# Alternative download method
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$webClient = New-Object System.Net.WebClient
$script = $webClient.DownloadString("https://your-url/script.ps1")
```

### Execution Policy Errors

**Solution:**
```powershell
# Force bypass
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex (irm 'url')"

# Or set permanently (not recommended)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

### RMM Timeout

**Solution:**
- Increase timeout in RMM platform
- Disable VirusTotal for faster execution
- Use background jobs for long-running scans

```powershell
# Run as background job
Start-Job -ScriptBlock { iex (irm "https://your-url/Remote-Launch.ps1") }
```

### Missing Administrator Rights

**Solution:**
- Configure RMM to run scripts as SYSTEM
- Use elevation in Remote-Launch.ps1 (included)

---

## Best Practices

1. **Test First**: Run on test systems before mass deployment
2. **Schedule Wisely**: Run during maintenance windows or off-hours
3. **Monitor Results**: Set up alerts for high-risk findings
4. **Document**: Keep records of scans performed
5. **Update Regularly**: Keep scripts updated from repository
6. **Version Control**: Use tagged releases for production
7. **Incremental Rollout**: Deploy to small groups first

---

## Support

For issues with remote deployment:
1. Check RMM platform logs
2. Verify network connectivity to script hosting
3. Test script locally on target system first
4. Review Windows Event Logs (PowerShell logs)

---

## Quick Reference Card

| Platform | Command Location | Timeout Setting | Variables/Parameters |
|----------|-----------------|-----------------|---------------------|
| **ConnectWise Automate** | Scripts → PowerShell | Script settings | Global variables |
| **CW Command** | Commands → PowerShell | `#timeout=` directive | Extension parameters |
| **Datto RMM** | Components → PowerShell | Component config | Site/account variables |
| **NinjaRMM** | Scripts | 15 min default | Script variables, custom fields |
| **Kaseya VSA** | Agent Procedures | Procedure settings | Parameter prompts |
| **Syncro** | Scripts & Alerts | Platform default | Script parameters |
| **Atera** | IT Automation | Profile settings | Global parameters |
