# Troubleshooting PowerShell Crashes

If the forensic analysis script is crashing PowerShell, use this guide to diagnose and fix the issue.

## Quick Fix: Use Safe Mode

If the regular script crashes, use the safe mode version:

```powershell
# Remote execution (safe mode)
iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis-Safe.ps1")

# Or skip problematic components
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -TimeoutSeconds 120
```

## Diagnostic Steps

### Step 1: Run Component Test

```powershell
# Download and run the diagnostic script
iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Quick-Test.ps1")
```

This will test each component separately and tell you which one is causing problems.

### Step 2: Identify the Problem

Common crash causes:

| Component | Symptom | Solution |
|-----------|---------|----------|
| **Autorunsc** | PowerShell hangs/freezes | Use `-SkipAutoruns` or reduce timeout |
| **Excel COM** | Crash during export | Excel will auto-fallback to CSV |
| **Process Enumeration** | Slow or crash | Use `-SkipProcesses` |
| **Memory** | Out of memory errors | Disable VirusTotal or reduce scope |

### Step 3: Use Workarounds

**If Autorunsc hangs:**
```powershell
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns
```

**If Process enumeration is slow:**
```powershell
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipProcesses
```

**If everything is slow:**
```powershell
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -SkipProcesses -TimeoutSeconds 60
```

## Common Issues and Fixes

### Issue 1: Autorunsc Hangs Indefinitely

**Symptoms:**
- PowerShell shows "Running Autorunsc (this may take a few minutes)..." but never completes
- CPU usage is high
- Process is consuming lots of memory

**Root Cause:**
- Autorunsc with `-a *` (all locations) can take 10-30 minutes on some systems
- Systems with many startup items or corruption can cause hangs

**Solutions:**

**Option A: Use timeout protection**
```powershell
.\Invoke-ForensicAnalysis-Safe.ps1 -TimeoutSeconds 180
```

**Option B: Skip autoruns entirely**
```powershell
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns
```

**Option C: Run autorunsc manually with limited scope**
```powershell
# Only check boot entries and logon items (faster)
.\SysinternalsTools\autorunsc64.exe -accepteula -a bl -c > autoruns.csv
```

### Issue 2: Excel COM Crashes

**Symptoms:**
- Error message about Excel
- PowerShell crashes when trying to export
- COM object errors

**Root Cause:**
- Excel COM objects can be finicky
- Improper cleanup can crash PowerShell
- Excel process left running in background

**Solutions:**

**Option A: Kill Excel processes first**
```powershell
Get-Process excel -ErrorAction SilentlyContinue | Stop-Process -Force
.\Invoke-ForensicAnalysis.ps1
```

**Option B: Script automatically falls back to CSV**
- If Excel export fails, the script will automatically use CSV
- No action needed - just check the output directory

**Option C: Force CSV export**
Modify the script to skip Excel entirely (edit line 697):
```powershell
$excelAvailable = $false  # Force CSV mode
```

### Issue 3: Out of Memory

**Symptoms:**
- PowerShell crashes with no error
- System becomes slow
- "Out of memory" error

**Root Cause:**
- Too many items being analyzed at once
- VirusTotal caching consuming memory
- Large datasets from autorunsc

**Solutions:**

**Option A: Disable VirusTotal**
```powershell
.\Invoke-ForensicAnalysis.ps1  # Don't use -EnableVirusTotal
```

**Option B: Increase PowerShell memory limit**
```powershell
# Before running the script
$env:PSModulePath = ""
[System.GC]::Collect()
```

**Option C: Process in smaller batches**
Skip heavy components:
```powershell
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -SkipProcesses
```

### Issue 4: WMI/CIM Errors

**Symptoms:**
- "RPC server unavailable"
- "Access denied" errors
- Service enumeration fails

**Root Cause:**
- Not running as Administrator
- WMI service issues
- Firewall blocking WMI

**Solutions:**

**Option A: Run as Administrator**
```powershell
# Right-click PowerShell → Run as Administrator
```

**Option B: Restart WMI service**
```powershell
Restart-Service Winmgmt -Force
```

**Option C: Use alternative methods**
The safe mode script will skip failed components automatically.

### Issue 5: Network/Firewall Issues (Remote Execution)

**Symptoms:**
- "Cannot download script"
- Timeout errors
- 404 errors

**Root Cause:**
- Firewall blocking raw.githubusercontent.com
- Corporate proxy
- Network connectivity issues

**Solutions:**

**Option A: Download manually first**
```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -OutFile "forensic.ps1"

# Run locally
.\forensic.ps1
```

**Option B: Use proxy**
```powershell
$proxy = "http://your-proxy:8080"
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
iex (irm "https://...")
```

**Option C: Clone repository**
```powershell
git clone https://github.com/YOUR_USERNAME/forensicinvestigator.git
cd forensicinvestigator
.\Invoke-ForensicAnalysis.ps1
```

## Advanced Troubleshooting

### Enable Debug Logging

```powershell
# Add to top of script
$VerbosePreference = "Continue"
$DebugPreference = "Continue"

# Run with transcript
Start-Transcript -Path "$env:TEMP\forensic-debug.log"
.\Invoke-ForensicAnalysis.ps1
Stop-Transcript
```

### Check PowerShell Event Logs

```powershell
# View recent PowerShell errors
Get-EventLog -LogName "Windows PowerShell" -EntryType Error -Newest 10
```

### Monitor Resource Usage

```powershell
# In another PowerShell window
while ($true) {
    $proc = Get-Process powershell | Sort-Object CPU -Descending | Select-Object -First 1
    Write-Host "$([DateTime]::Now) - CPU: $($proc.CPU) - Memory: $([math]::Round($proc.WS/1MB))MB"
    Start-Sleep -Seconds 5
}
```

### Run Individual Components

```powershell
# Test just services
Get-WmiObject -Class Win32_Service | Select-Object Name, State, PathName | Export-Csv services.csv

# Test just network
Get-NetTCPConnection | Export-Csv network.csv

# Test just processes
Get-Process | Where-Object {$_.Path} | Select-Object Name, Path, Company | Export-Csv processes.csv
```

## Component-Specific Parameters

### Safe Mode Parameters

```powershell
# Skip autoruns (fastest)
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns

# Skip processes
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipProcesses

# Custom timeout for autoruns (seconds)
.\Invoke-ForensicAnalysis-Safe.ps1 -TimeoutSeconds 120

# Skip both autoruns and processes
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -SkipProcesses

# Minimal analysis (services and network only)
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -SkipProcesses -OutputPath "$env:TEMP\QuickScan"
```

## Getting Help

If you're still experiencing crashes:

1. **Run the diagnostic test:**
   ```powershell
   .\Quick-Test.ps1
   ```

2. **Save the output:**
   ```powershell
   .\Quick-Test.ps1 | Tee-Object -FilePath diagnostic.log
   ```

3. **Report the issue:**
   - Include the diagnostic.log output
   - Specify your Windows version
   - Include PowerShell version: `$PSVersionTable.PSVersion`
   - Include any error messages

## Known Limitations

- **Autorunsc** can take 10-30 minutes on systems with many startup items
- **Excel export** requires Excel to be installed and not in use
- **VirusTotal** free tier is limited to 4 requests/minute
- **WMI queries** require Administrator privileges for full results
- **Some processes** may be protected and not enumerable

## Quick Reference

| Problem | Command |
|---------|---------|
| Crashes immediately | `.\Quick-Test.ps1` |
| Hangs on autoruns | `.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns` |
| Out of memory | `.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -SkipProcesses` |
| Excel crashes | Script auto-falls back to CSV |
| Too slow | `.\Invoke-ForensicAnalysis-Safe.ps1 -TimeoutSeconds 60 -SkipProcesses` |
| Can't download | `git clone` then run locally |
