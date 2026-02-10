# GitHub Alternative Domains

When `raw.githubusercontent.com` is blocked, the scripts automatically try these alternative domains/CDNs.

## Automatic Fallback Order

When you use a GitHub URL, the scripts try these alternatives **automatically**:

1. ✅ **raw.githubusercontent.com** (Original GitHub)
   - `https://raw.githubusercontent.com/user/repo/branch/file`

2. ✅ **cdn.jsdelivr.net** (jsDelivr CDN - Recommended)
   - Format: `https://cdn.jsdelivr.net/gh/user/repo@branch/file`
   - Free, production-ready CDN
   - Example: `https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1`

3. ✅ **cdn.staticdelivr.com** (StaticDelivr CDN)
   - Format: `https://cdn.staticdelivr.com/gh/user/repo/branch/file`
   - Production CDN with permanent caching
   - Example: `https://cdn.staticdelivr.com/gh/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1`

4. ✅ **raw.githack.com** (Githack Proxy)
   - Format: `https://raw.githack.com/user/repo/branch/file`
   - Caching proxy for GitHub raw content
   - Example: `https://raw.githack.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1`

5. ✅ **rawgit.net** (Rawgit Proxy)
   - Format: `https://rawgit.net/user/repo/branch/file`
   - Caching proxy for GitHub raw content
   - Example: `https://rawgit.net/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1`

## Usage

### Automatic (Recommended)

Just use your normal GitHub URL - alternatives are tried automatically:

```powershell
# Scripts automatically try all alternatives if GitHub is blocked
.\Remote-Launch.ps1 -ScriptUrl "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
```

### Manual Selection

If you want to specify a particular alternative domain:

```powershell
# jsDelivr CDN (recommended for production)
.\Remote-Launch.ps1 -ScriptUrl "https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1"

# StaticDelivr CDN
.\Remote-Launch.ps1 -ScriptUrl "https://cdn.staticdelivr.com/gh/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"

# Githack
.\Remote-Launch.ps1 -ScriptUrl "https://raw.githack.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
```

### ScreenConnect Commands

**Using jsDelivr CDN:**
```powershell
#!ps
irm "https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

**Using StaticDelivr CDN:**
```powershell
#!ps
irm "https://cdn.staticdelivr.com/gh/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

## URL Format Conversion

### From GitHub URL to jsDelivr:
```
GitHub:    https://raw.githubusercontent.com/USER/REPO/BRANCH/FILE
jsDelivr:  https://cdn.jsdelivr.net/gh/USER/REPO@BRANCH/FILE
```

### From GitHub URL to StaticDelivr:
```
GitHub:        https://raw.githubusercontent.com/USER/REPO/BRANCH/FILE
StaticDelivr: https://cdn.staticdelivr.com/gh/USER/REPO/BRANCH/FILE
```

### From GitHub URL to Githack:
```
GitHub:   https://raw.githubusercontent.com/USER/REPO/BRANCH/FILE
Githack:  https://raw.githack.com/USER/REPO/BRANCH/FILE
```

## Which Alternative to Use?

- **jsDelivr** - Best for production, free, reliable CDN
- **StaticDelivr** - Best for permanent caching, production CDN
- **Githack** - Good fallback option, caching proxy
- **Rawgit** - Good fallback option, caching proxy

## Testing Connectivity

Test which domains are accessible:

```powershell
# Test GitHub
Test-NetConnection -ComputerName raw.githubusercontent.com -Port 443

# Test jsDelivr
Test-NetConnection -ComputerName cdn.jsdelivr.net -Port 443

# Test StaticDelivr
Test-NetConnection -ComputerName cdn.staticdelivr.com -Port 443

# Test Githack
Test-NetConnection -ComputerName raw.githack.com -Port 443
```

## Notes

- All alternatives serve the **exact same content** from GitHub
- Alternatives are **automatically tried** - no configuration needed
- If all alternatives fail, scripts fall back to `-LocalScriptPath` option
- These alternatives work even when GitHub is completely blocked
