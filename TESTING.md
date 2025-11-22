# Testing Guide

Quick commands to test the Forensic Investigation Tool locally and remotely.

## Local Testing

### Test Main Script Directly

```powershell
# Navigate to the repository directory
cd C:\path\to\forensicinvestigator

# Basic test (no VirusTotal)
.\Invoke-ForensicAnalysis.ps1

# With VirusTotal
.\Invoke-ForensicAnalysis.ps1 -EnableVirusTotal -VirusTotalApiKey "your-api-key"

# Custom output location for testing
.\Invoke-ForensicAnalysis.ps1 -OutputPath "$env:USERPROFILE\Desktop\TestReports"
```

### Test Remote Launcher Locally

```powershell
# Test the remote launcher script
.\Remote-Launch.ps1

# With VirusTotal via environment variable
$env:VT_API_KEY = "your-api-key"
.\Remote-Launch.ps1 -EnableVirusTotal

# Specify the main script URL (for local testing, point to local file)
.\Remote-Launch.ps1 -ScriptUrl "file:///$PWD/Invoke-ForensicAnalysis.ps1"
```

## Remote Testing

Once you've pushed your repository to GitHub (or another hosting service), you can test remote execution.

### Step 1: Get Your Raw Script URL

Your GitHub raw URLs:
```
# Main branch (once merged):
https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1

# Current development branch:
https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Remote-Launch.ps1
```

### Step 2: Test Remote Execution

**Basic IEX Test (no VirusTotal):**
```powershell
# Using current branch
iex (irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Remote-Launch.ps1")

# Or once merged to main:
iex (irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Remote-Launch.ps1")
```

**With VirusTotal API Key:**
```powershell
$env:VT_API_KEY = "your-virustotal-api-key"
iex (irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Remote-Launch.ps1")
```

**One-liner for RMM platforms:**
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "$env:VT_API_KEY='your-key'; iex (irm 'https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Remote-Launch.ps1')"
```

### Step 3: Test ConnectWise Command

1. Open ConnectWise Command session to your test machine
2. Go to **Commands** → **PowerShell**
3. Run:

```powershell
# Current branch
iex (irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Remote-Launch.ps1")
```

## Alternative: Test via Local Web Server

If you want to test remote execution without pushing to GitHub:

### Option 1: Python HTTP Server

```powershell
# In the repository directory
cd C:\path\to\forensicinvestigator

# Start a simple web server (Python 3)
python -m http.server 8080

# In another PowerShell window, test:
iex (irm "http://localhost:8080/Remote-Launch.ps1")
```

### Option 2: PowerShell HTTP Server

```powershell
# Create a simple HTTP server in PowerShell
$http = [System.Net.HttpListener]::new()
$http.Prefixes.Add("http://localhost:8080/")
$http.Start()

Write-Host "Server started at http://localhost:8080/"
Write-Host "Press Ctrl+C to stop"

while ($http.IsListening) {
    $context = $http.GetContext()
    $request = $context.Request
    $response = $context.Response

    if ($request.Url.LocalPath -eq "/Remote-Launch.ps1") {
        $content = Get-Content ".\Remote-Launch.ps1" -Raw
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
    }

    $response.Close()
}

$http.Stop()
```

Then test with:
```powershell
iex (irm "http://localhost:8080/Remote-Launch.ps1")
```

## Quick Test Commands for Your Current Setup

Ready-to-use commands for your repository:

### Local Test
```powershell
# Clone your repo (if testing on another machine)
git clone https://github.com/monobrau/forensicinvestigator.git
cd forensicinvestigator

# Switch to the branch
git checkout claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf

# Run local test
.\Invoke-ForensicAnalysis.ps1 -OutputPath "$env:TEMP\ForensicTest"
```

### Remote Test (GitHub)
```powershell
# Your actual URLs
$url = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/claude/sysinternals-download-analyzer-01EbqkwEvJpPcVmcyF6NSXRf/Remote-Launch.ps1"

# Test without VirusTotal
iex (irm $url)

# Test with VirusTotal
$env:VT_API_KEY = "your-api-key"
iex (irm $url)
```

## Verifying Results

After running the test, check:

1. **Output Directory**:
   ```powershell
   # Check for generated reports
   Get-ChildItem "$env:TEMP\ForensicReports" -Recurse
   ```

2. **Open Excel Report** (if Excel is installed):
   ```powershell
   $report = Get-ChildItem "$env:TEMP\ForensicReports\*.xlsx" | Select-Object -First 1
   Start-Process excel.exe -ArgumentList $report.FullName
   ```

3. **Review CSV Reports** (if no Excel):
   ```powershell
   Get-ChildItem "$env:TEMP\ForensicReports\*.csv" | ForEach-Object {
       Import-Csv $_.FullName | Where-Object { $_.RiskLevel -eq "High" }
   }
   ```

## Troubleshooting Test Failures

### "Cannot download script"
```powershell
# Test connectivity
Test-NetConnection -ComputerName raw.githubusercontent.com -Port 443

# Try alternate method
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$webClient = New-Object System.Net.WebClient
$script = $webClient.DownloadString("YOUR_URL")
Invoke-Expression $script
```

### "Execution Policy" errors
```powershell
# Check current policy
Get-ExecutionPolicy

# Bypass for testing
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Or run with bypass flag
powershell.exe -ExecutionPolicy Bypass -File ".\Invoke-ForensicAnalysis.ps1"
```

### "Not running as Administrator"
```powershell
# Check if admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as Admin: $isAdmin"

# Re-launch as admin
Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PWD\Invoke-ForensicAnalysis.ps1`"" -Verb RunAs
```

## Clean Up After Testing

```powershell
# Remove test reports
Remove-Item "$env:TEMP\ForensicReports" -Recurse -Force -ErrorAction SilentlyContinue

# Remove downloaded tools
Remove-Item "$env:TEMP\SysinternalsTools" -Recurse -Force -ErrorAction SilentlyContinue

# Clear environment variables
Remove-Item Env:\VT_API_KEY -ErrorAction SilentlyContinue
```
