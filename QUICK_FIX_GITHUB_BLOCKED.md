# Quick Fix: GitHub Blocked

If `raw.githubusercontent.com` is blocked, the scripts **automatically try alternative GitHub domains**!

## ✅ Automatic Fallback (No Action Needed!)

The scripts now automatically try these alternative domains when GitHub is blocked:
1. `cdn.jsdelivr.net/gh/` (jsDelivr CDN)
2. `cdn.staticdelivr.com/gh/` (StaticDelivr CDN)
3. `raw.githack.com` (Githack proxy)
4. `rawgit.net` (Rawgit proxy)

**Just use your normal GitHub URL** - alternatives are tried automatically!

```powershell
# Works automatically - tries alternatives if GitHub is blocked
.\Remote-Launch.ps1 -ScriptUrl "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
```

## Manual Solutions

If automatic fallback doesn't work, use one of these solutions:

## ✅ Solution 1: Use Local Script File (Easiest)

**Step 1:** Copy `Invoke-ForensicAnalysis.ps1` to the target machine (USB, network share, etc.)

**Step 2:** Run with local path:
```powershell
# Using Remote-Launch.ps1
.\Remote-Launch.ps1 -LocalScriptPath "C:\Scripts\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"

# Using Send-ForensicReport.ps1
.\Send-ForensicReport.ps1 -LocalScriptPath "C:\Scripts\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

**ScreenConnect Command:**
```powershell
#!ps
Copy-Item "\\server\share\scripts\Invoke-ForensicAnalysis.ps1" "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

## ✅ Solution 2: Use Alternative GitHub Domain Manually

If automatic fallback doesn't work, manually specify an alternative:

```powershell
# jsDelivr CDN (recommended)
.\Remote-Launch.ps1 -ScriptUrl "https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"

# StaticDelivr CDN
.\Remote-Launch.ps1 -ScriptUrl "https://cdn.staticdelivr.com/gh/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"

# Githack
.\Remote-Launch.ps1 -ScriptUrl "https://raw.githack.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

**ScreenConnect Command:**
```powershell
#!ps
irm "https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

## ✅ Solution 3: Use Alternative Hosting URL

If you have scripts hosted elsewhere (internal server, GitLab, etc.):

```powershell
# Using Remote-Launch.ps1
.\Remote-Launch.ps1 -ScriptUrl "https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"

# Using Send-ForensicReport.ps1  
.\Send-ForensicReport.ps1 -ScriptUrl "https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

**ScreenConnect Command:**
```powershell
#!ps
irm "https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

## ✅ Solution 4: Network Share

```powershell
# Direct execution from network share
& "\\server\share\scripts\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

## 📚 Full Documentation

See **[ALTERNATIVE_HOSTING.md](ALTERNATIVE_HOSTING.md)** for:
- Detailed setup instructions
- Self-hosting guides (IIS, Python, Node.js, PowerShell)
- Alternative CDN options (GitLab, Bitbucket, etc.)
- Base64 encoding method
- Troubleshooting tips

## What Changed?

All scripts now support:
- ✅ **Automatic alternative domain fallback** - tries 5 different GitHub CDNs automatically!
- ✅ `-LocalScriptPath` parameter (use local files)
- ✅ `-ScriptUrl` parameter (use alternative hosting)
- ✅ Better error handling for blocked URLs
- ✅ Multiple fallback mechanisms

**No more dependency on GitHub - works even when `raw.githubusercontent.com` is blocked!**
