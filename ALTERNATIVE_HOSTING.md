# Alternative Hosting Solutions for Blocked GitHub Access

If `raw.githubusercontent.com` is blocked in your environment, you have several options to deploy and run the Forensic Investigator tool.

## Quick Solutions

### Option 0: Automatic Alternative Domain Fallback (NEW! ✅)

**The scripts now automatically try alternative GitHub domains if `raw.githubusercontent.com` is blocked!**

When you use a GitHub URL, the scripts will automatically try these alternatives in order:
1. `raw.githubusercontent.com` (original)
2. `cdn.jsdelivr.net/gh/` (jsDelivr CDN - free, production-ready)
3. `cdn.staticdelivr.com/gh/` (StaticDelivr CDN - production CDN)
4. `raw.githack.com` (Githack caching proxy)
5. `rawgit.net` (Rawgit caching proxy)

**No changes needed** - just use your normal GitHub URL and the script will automatically try alternatives if the primary domain is blocked!

**Example:**
```powershell
# Just use your normal GitHub URL - alternatives are tried automatically
.\Remote-Launch.ps1 -ScriptUrl "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
```

**Manual Alternative URLs:**
If you want to specify an alternative domain manually:
```powershell
# jsDelivr CDN
.\Remote-Launch.ps1 -ScriptUrl "https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1"

# StaticDelivr CDN
.\Remote-Launch.ps1 -ScriptUrl "https://cdn.staticdelivr.com/gh/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"

# Githack
.\Remote-Launch.ps1 -ScriptUrl "https://raw.githack.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
```

### Option 1: Use Local Script Path (Recommended for Blocked Networks)

If you can transfer the script files to the target machine via USB, network share, or file transfer tool:

```powershell
# Using Remote-Launch.ps1 with local script
.\Remote-Launch.ps1 -LocalScriptPath "C:\Scripts\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"

# Using Send-ForensicReport.ps1 with local script
.\Send-ForensicReport.ps1 -LocalScriptPath "C:\Scripts\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

**ScreenConnect Command:**
```powershell
#!ps
$scriptPath = "\\server\share\scripts\Invoke-ForensicAnalysis.ps1"; Copy-Item $scriptPath "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

### Option 2: Self-Host on Internal Web Server

Host the scripts on your internal web server, file share, or CDN.

#### Step 1: Upload Scripts to Your Server

Copy these files to your web server:
- `Invoke-ForensicAnalysis.ps1`
- `Remote-Launch.ps1` (optional)
- `Send-ForensicReport.ps1` (optional)

#### Step 2: Update Script URLs

**Using Remote-Launch.ps1:**
```powershell
.\Remote-Launch.ps1 -ScriptUrl "https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

**Using Send-ForensicReport.ps1:**
```powershell
.\Send-ForensicReport.ps1 -ScriptUrl "https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

**ScreenConnect Command:**
```powershell
#!ps
irm "https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

### Option 3: Use Network Share

Store scripts on a network share accessible to target machines:

```powershell
# Direct execution from network share
& "\\server\share\scripts\Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"

# Or copy to local temp first
Copy-Item "\\server\share\scripts\Invoke-ForensicAnalysis.ps1" "$env:TEMP\FA.ps1"
& "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

**ScreenConnect Command:**
```powershell
#!ps
Copy-Item "\\server\share\scripts\Invoke-ForensicAnalysis.ps1" "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

### Option 4: Use Alternative CDN/Hosting Services

#### GitHub Alternative Domains (Automatically Tried)

The scripts automatically try these GitHub alternative domains/CDNs:

1. **jsDelivr CDN** (Recommended)
   - Format: `https://cdn.jsdelivr.net/gh/user/repo@branch/file`
   - Free, production-ready CDN
   - Example: `https://cdn.jsdelivr.net/gh/monobrau/forensicinvestigator@main/Invoke-ForensicAnalysis.ps1`

2. **StaticDelivr CDN**
   - Format: `https://cdn.staticdelivr.com/gh/user/repo/branch/file`
   - Production CDN with permanent caching
   - Example: `https://cdn.staticdelivr.com/gh/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1`

3. **Githack**
   - Format: `https://raw.githack.com/user/repo/branch/file`
   - Caching proxy for GitHub raw content
   - Example: `https://raw.githack.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1`

4. **Rawgit**
   - Format: `https://rawgit.net/user/repo/branch/file`
   - Caching proxy for GitHub raw content
   - Example: `https://rawgit.net/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1`

**Note:** These are automatically tried when using GitHub URLs - no manual configuration needed!

#### Other Git Hosting Services

If GitHub and its alternatives are blocked, use other Git hosting:

- **GitLab**: `https://gitlab.com/yourusername/forensicinvestigator/-/raw/main/Invoke-ForensicAnalysis.ps1`
- **Bitbucket**: `https://bitbucket.org/yourusername/forensicinvestigator/raw/main/Invoke-ForensicAnalysis.ps1`
- **Gitea/Gogs**: `https://your-gitea-instance.com/yourusername/forensicinvestigator/raw/branch/main/Invoke-ForensicAnalysis.ps1`
- **Azure DevOps**: `https://dev.azure.com/yourorg/project/_git/repo?path=/Invoke-ForensicAnalysis.ps1`
- **AWS S3**: `https://your-bucket.s3.amazonaws.com/scripts/Invoke-ForensicAnalysis.ps1`
- **Google Cloud Storage**: `https://storage.googleapis.com/your-bucket/scripts/Invoke-ForensicAnalysis.ps1`

**Example using GitLab:**
```powershell
#!ps
irm "https://gitlab.com/yourusername/forensicinvestigator/-/raw/main/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

### Option 5: Base64 Encoded Script (One-Liner)

For very restricted environments, you can embed the script as a base64-encoded string:

```powershell
# Encode script to base64 (run on a machine with access)
$scriptContent = Get-Content "Invoke-ForensicAnalysis.ps1" -Raw
$base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($scriptContent))
Write-Host $base64

# Decode and execute on target machine
$base64 = "PASTE_BASE64_STRING_HERE"
$scriptContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
$scriptContent | Out-File "$env:TEMP\FA.ps1" -Encoding UTF8
& "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

**Note:** This method has size limitations and may not work for very large scripts.

## Setting Up Self-Hosting

### Using IIS (Windows Server)

1. **Create a directory** on your IIS server (e.g., `C:\inetpub\wwwroot\scripts`)
2. **Copy scripts** to this directory
3. **Configure IIS** to serve `.ps1` files:
   - Open IIS Manager
   - Select your site or create a new one
   - Add MIME type: Extension `.ps1`, MIME type `text/plain`
   - Or configure handler mapping for PowerShell scripts
4. **Set permissions** so scripts are readable but not executable
5. **Test access**: `https://your-server.com/scripts/Invoke-ForensicAnalysis.ps1`

### Using Simple HTTP Server (Python)

If you have Python installed:

```bash
# Navigate to directory containing scripts
cd C:\Scripts

# Start HTTP server (Python 3)
python -m http.server 8000

# Access scripts via:
# http://your-ip:8000/Invoke-ForensicAnalysis.ps1
```

### Using Node.js HTTP Server

```bash
# Install http-server globally
npm install -g http-server

# Navigate to directory containing scripts
cd C:\Scripts

# Start server
http-server -p 8000

# Access scripts via:
# http://your-ip:8000/Invoke-ForensicAnalysis.ps1
```

### Using PowerShell HTTP Server

Create a simple PowerShell HTTP server:

```powershell
# Simple-PowerShellServer.ps1
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:8000/")
$listener.Start()

Write-Host "Server started on http://localhost:8000/"
Write-Host "Press Ctrl+C to stop"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    
    $localPath = $request.Url.LocalPath.TrimStart('/')
    $filePath = Join-Path $PSScriptRoot $localPath
    
    if (Test-Path $filePath) {
        $content = Get-Content $filePath -Raw
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
        $response.ContentType = "text/plain"
        $response.ContentLength64 = $buffer.Length
        $response.StatusCode = 200
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
    } else {
        $response.StatusCode = 404
    }
    
    $response.Close()
}
```

## Troubleshooting Blocked GitHub Access

### Test Connectivity

```powershell
# Test if GitHub is accessible
Test-NetConnection -ComputerName raw.githubusercontent.com -Port 443

# Test alternative host
Test-NetConnection -ComputerName your-server.com -Port 443
```

### Check Proxy Settings

If your environment uses a proxy:

```powershell
# Set proxy for PowerShell
$proxy = "http://proxy-server:port"
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# Or use proxy parameter
Invoke-RestMethod -Uri $ScriptUrl -Proxy $proxy -ProxyCredential $cred
```

### Bypass Certificate Validation (Not Recommended)

Only use this for testing in isolated environments:

```powershell
# Disable certificate validation (INSECURE - for testing only)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## Recommended Approach for Enterprise Environments

1. **Set up internal web server** or file share
2. **Host scripts** on internal infrastructure
3. **Update ScreenConnect commands** to use internal URLs
4. **Document** the internal URLs for your team
5. **Version control** scripts internally (GitLab, Azure DevOps, etc.)

## Security Considerations

- **HTTPS**: Always use HTTPS for script hosting when possible
- **Authentication**: Consider adding authentication to your script hosting
- **Signature Verification**: Verify script integrity using checksums or digital signatures
- **Network Isolation**: Keep script hosting on internal networks when possible
- **Access Control**: Limit access to script hosting locations

## Example: Complete Self-Hosted Deployment

```powershell
# 1. Upload scripts to your server: https://scripts.yourcompany.com/

# 2. Update ScreenConnect command:
#!ps
$scriptUrl = "https://scripts.yourcompany.com/Invoke-ForensicAnalysis.ps1"
irm $scriptUrl -OutFile "$env:TEMP\FA.ps1"
& "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports" -ForceCSV

# 3. Or use Remote-Launch.ps1:
#!ps
irm "https://scripts.yourcompany.com/Remote-Launch.ps1" -OutFile "$env:TEMP\RL.ps1"
& "$env:TEMP\RL.ps1" -ScriptUrl "https://scripts.yourcompany.com/Invoke-ForensicAnalysis.ps1" -OutputPath "C:\SecurityReports"
```

## Summary

When GitHub is blocked:
1. ✅ **Best**: Use `-LocalScriptPath` with files transferred via USB/network share
2. ✅ **Good**: Self-host on internal web server or file share
3. ✅ **Alternative**: Use alternative Git hosting (GitLab, Bitbucket, etc.)
4. ⚠️ **Last Resort**: Base64 encoding (has size limitations)

All scripts now support the `-LocalScriptPath` and `-ScriptUrl` parameters for maximum flexibility.
