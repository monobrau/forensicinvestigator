# Forensic Investigator

A comprehensive PowerShell-based forensic analysis tool that leverages Sysinternals utilities to perform deep system analysis with optional VirusTotal integration and color-coded reporting.

## Features

- **Automated Sysinternals Download**: Automatically downloads required Sysinternals tools (architecture-aware)
- **Comprehensive System Analysis**:
  - Autorun entries (startup programs, scheduled tasks, services, drivers, etc.)
  - Windows Services (running and stopped)
  - Network connections (TCP listening and established)
  - Running processes
- **VirusTotal Integration**: Optional hash-based malware detection for all executables
- **Smart Export**:
  - XLSX format with color-coded risk levels (if Excel is installed)
  - CSV fallback (if Excel is not available)
- **Risk Assessment**: Three-tier color coding system
  - **Red (High Risk)**: Unsigned executables OR VirusTotal detections ≥ 5
  - **Yellow (Medium Risk)**: Unknown publisher OR VirusTotal detections 1-4
  - **Green (Low Risk)**: Verified signature AND VirusTotal detections = 0

## Requirements

- **Operating System**: Windows (PowerShell 5.1 or later)
- **Privileges**: Administrator rights required for full analysis
- **Optional**: Microsoft Excel (for XLSX export with color coding)
- **Optional**: VirusTotal API key (for malware scanning)

## Installation

1. Clone or download this repository
2. No installation required - it's a standalone PowerShell script

## Usage

### Basic Usage (No VirusTotal)

```powershell
.\Invoke-ForensicAnalysis.ps1
```

This will:
- Download Sysinternals tools to `.\SysinternalsTools`
- Analyze the system
- Export results to `.\ForensicReports`

### With VirusTotal Scanning

```powershell
.\Invoke-ForensicAnalysis.ps1 -EnableVirusTotal -VirusTotalApiKey "your-api-key-here"
```

### Custom Output Directory

```powershell
.\Invoke-ForensicAnalysis.ps1 -OutputPath "C:\Investigation\Reports"
```

### Custom Tools Directory

```powershell
.\Invoke-ForensicAnalysis.ps1 -ToolsPath "C:\Tools\Sysinternals"
```

### Full Example

```powershell
.\Invoke-ForensicAnalysis.ps1 `
    -EnableVirusTotal `
    -VirusTotalApiKey "abc123def456..." `
    -OutputPath "C:\Investigation\Reports" `
    -ToolsPath "C:\Investigation\Tools"
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `OutputPath` | String | No | `.\ForensicReports` | Directory for saving reports |
| `VirusTotalApiKey` | String | No | `""` | VirusTotal API key for hash lookups |
| `EnableVirusTotal` | Switch | No | `$false` | Enable VirusTotal scanning |
| `ToolsPath` | String | No | `.\SysinternalsTools` | Directory for Sysinternals tools |

## Remote Deployment

The tool supports remote deployment via IEX (Invoke-Expression) and RMM platforms like ConnectWise, Datto, and NinjaRMM.

### Quick Remote Execution

**Via IEX (replace URL with your hosted script):**
```powershell
# Basic execution
iex (irm "https://raw.githubusercontent.com/yourusername/forensicinvestigator/main/Remote-Launch.ps1")

# With VirusTotal API key
$env:VT_API_KEY = "your-api-key"
iex (irm "https://your-url/Remote-Launch.ps1")
```

**One-liner for RMM platforms:**
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "$env:VT_API_KEY='your-key'; iex (irm 'https://your-url/Remote-Launch.ps1')"
```

### ConnectWise ScreenConnect Commands

ConnectWise ScreenConnect provides multiple ways to execute PowerShell scripts remotely. Choose the method that best fits your needs.

#### Step-by-Step Instructions

1. **Connect to the target machine** in ScreenConnect
2. Click the **Commands** button (or press F5)
3. Paste one of the commands below (ScreenConnect will auto-detect the `#!ps` prefix)
4. Press **Enter** or click **Run**

#### Getting Your Script URL

Replace `YOUR_USERNAME/forensicinvestigator` with your actual GitHub repository path:

- **GitHub (Public Repo)**: `https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1`
- **GitHub (Private Repo)**: Use a GitHub Personal Access Token
- **Self-Hosted**: `https://yourdomain.com/path/to/Remote-Launch.ps1`
- **Local Network**: `http://192.168.1.100/Remote-Launch.ps1`

#### Command Options

**Option 1: Basic Scan (No VirusTotal)**
```powershell
#!ps
iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1")
```
- Fast execution (2-5 minutes)
- No malware scanning
- Creates Excel or CSV reports

**Option 2: With VirusTotal Scanning**
```powershell
#!ps
$env:VT_API_KEY = "your-virustotal-api-key-here"; iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1")
```
- Scans all executables for malware
- Takes 30-60+ minutes (API rate limited)
- Requires free VirusTotal API key

**Option 3: Using PowerShell Direct Call**
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex (irm 'https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1')"
```
- Alternative method without `#!ps` prefix
- Explicitly calls PowerShell executable
- Bypasses execution policy restrictions

**Option 4: With VirusTotal (PowerShell 7)**
```powershell
pwsh.exe -ExecutionPolicy Bypass -NoProfile -Command "$env:VT_API_KEY='your-api-key'; iex (irm 'https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1')"
```
- Uses PowerShell 7 (if installed)
- Includes VirusTotal API key
- Faster performance on modern systems

#### ScreenConnect Command Templates

For **one-time execution**, copy and paste into the ScreenConnect command box:

```powershell
# Template 1: Basic (fastest) - Using #!ps prefix
#!ps
iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1")
```

```powershell
# Template 2: With VirusTotal - Using #!ps prefix
#!ps
$env:VT_API_KEY = "YOUR_VT_API_KEY"; iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1")
```

```powershell
# Template 3: Using direct PowerShell call
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex (irm 'https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1')"
```

For **saving as a ScreenConnect Command** (reusable):

1. In ScreenConnect, go to **Admin** → **Command Toolbox**
2. Click **Add Command**
3. Name it: `Forensic Scan - Basic`
4. Command Type: **PowerShell** (or leave as Command)
5. Paste one of these:

**Using #!ps prefix:**
```powershell
#!ps
iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1")
```

**Using direct call:**
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex (irm 'https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1')"
```

6. Save and run from the Commands menu anytime

#### Retrieving Reports

After execution completes, reports are saved to:
- **Default Location**: `C:\Users\[Username]\AppData\Local\Temp\ForensicReports\`
- **Custom Location**: Path specified with `-OutputPath`

To retrieve reports via ScreenConnect:
1. Open **File Manager** in the session
2. Navigate to the report directory
3. Download the `.xlsx` or `.csv` files
4. Or use ScreenConnect's **Transfer Files** feature

#### Troubleshooting ScreenConnect Commands

**Error: "Execution Policy Restricted"**

Try using the direct PowerShell call method:
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex (irm 'https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1')"
```

Or with `#!ps` prefix:
```powershell
#!ps
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; iex (irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1")
```

**Error: "Cannot download script"**
- Check internet connectivity on target machine
- Verify URL is correct and accessible
- Try using IP address instead of hostname
- Check firewall/proxy settings

**Error: "Not running as Administrator"**
- The script will auto-elevate if possible
- Ensure ScreenConnect session has admin rights
- Or manually run ScreenConnect as admin

**Error: "#!ps not recognized"**
- Try using the direct PowerShell call method instead:
  ```
  powershell.exe -ExecutionPolicy Bypass -Command "iex (irm 'URL')"
  ```
- Or use `pwsh.exe` for PowerShell 7

**Command appears to hang**
- This is normal for VirusTotal scans (can take 30-60 minutes)
- Check CPU usage - if active, it's still running
- Without VT, should complete in 2-5 minutes

### ConnectWise Automate

Create a PowerShell script with:
```powershell
$ScriptUrl = "https://your-url/Remote-Launch.ps1"
$VTApiKey = "@VT_API_KEY@"  # Automate variable

$script = Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing
$tempScript = "$env:TEMP\forensic.ps1"
$script | Out-File -FilePath $tempScript -Encoding UTF8

& $tempScript -EnableVirusTotal -VirusTotalApiKey $VTApiKey

Remove-Item $tempScript -Force
```

### Other RMM Platforms

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for detailed instructions for:
- **Datto RMM**
- **NinjaRMM**
- **Kaseya VSA**
- **Syncro**
- **Atera**
- **N-able N-central**

The deployment guide includes:
- Platform-specific script templates
- Variable/parameter configuration
- Scheduling and automation setup
- Security best practices
- Troubleshooting tips

## Getting a VirusTotal API Key

1. Create a free account at [VirusTotal](https://www.virustotal.com/)
2. Navigate to your profile settings
3. Copy your API key
4. **Note**: Free API keys are limited to 4 requests per minute

## Output Format

### Excel (XLSX) Output

When Microsoft Excel is installed, the tool generates a single Excel workbook with multiple worksheets:

- **Autoruns**: All autostart entries
- **Services**: Windows services
- **Network**: Active network connections
- **Processes**: Running processes

Each worksheet includes:
- Color-coded rows based on risk level
- File hashes (SHA256)
- VirusTotal detection results (if enabled)
- Publisher/signature information
- Detailed metadata

### CSV Output

When Excel is not available, separate CSV files are created:

- `{HOSTNAME}_Autoruns_{TIMESTAMP}.csv`
- `{HOSTNAME}_Services_{TIMESTAMP}.csv`
- `{HOSTNAME}_Network_{TIMESTAMP}.csv`
- `{HOSTNAME}_Processes_{TIMESTAMP}.csv`

**Note**: CSV files include all data but cannot display color coding.

## What Gets Analyzed

### Autorun Entries
- Logon items
- Services
- Drivers
- Scheduled tasks
- Browser helper objects
- Winlogon entries
- Explorer addons
- And many more autostart locations

### Services
- All Windows services (running and stopped)
- Service executable paths
- Start modes
- Digital signatures
- VirusTotal scans (if enabled)

### Network Connections
- TCP connections (listening and established)
- Associated processes
- Remote addresses and ports
- Process signatures
- VirusTotal scans (if enabled)

### Running Processes
- All running processes with executable paths
- Process metadata
- Digital signatures
- VirusTotal scans (if enabled)

## Risk Level Determination

The tool automatically calculates risk levels based on:

1. **Digital Signature**:
   - No signature or unverified: +10 risk points
   - Unknown publisher: +5 risk points

2. **VirusTotal Detections** (if enabled):
   - ≥5 malicious detections: +20 risk points
   - 1-4 malicious detections: +10 risk points
   - ≥3 suspicious detections: +5 risk points

3. **Final Risk Level**:
   - **High**: ≥15 points (Red)
   - **Medium**: 5-14 points (Yellow)
   - **Low**: 0-4 points (Green)

## Performance Considerations

- **Without VirusTotal**: Analysis typically takes 2-5 minutes
- **With VirusTotal**: Can take 30-60+ minutes depending on:
  - Number of unique executables found
  - VirusTotal API rate limits (free: 4 requests/minute)
  - Network latency

The script automatically handles rate limiting and caches results to avoid duplicate API calls.

## Sysinternals Tools Downloaded

The script automatically downloads the following tools (architecture-appropriate):

- **autorunsc.exe**: Enumerates autostart entries
- **PsService.exe**: Service enumeration (backup method)
- **tcpview.exe / tcpvcon.exe**: Network connections
- **sigcheck.exe**: Digital signature verification
- **handle.exe**: Open file handles
- **listdlls.exe**: Loaded DLLs
- **psinfo.exe**: System information

All tools are downloaded from `https://live.sysinternals.com/` and accept EULAs automatically.

## Security Considerations

1. **Administrator Rights**: Required for complete system visibility
2. **API Key Security**: Never commit your VirusTotal API key to version control
3. **Network Usage**: VirusTotal scanning requires internet connectivity
4. **Privacy**: Hash values are sent to VirusTotal (not the files themselves)

## Troubleshooting

### "Not running as Administrator"
Run PowerShell as Administrator for full functionality.

### "Excel not available"
The tool will automatically fall back to CSV export. Install Microsoft Excel for color-coded XLSX reports.

### VirusTotal Rate Limiting
Free API keys are limited to 4 requests per minute. The script automatically throttles requests. Consider waiting or using a premium API key for faster analysis.

### Execution Policy Error
If you get an execution policy error, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Sysinternals Download Failures
Ensure you have internet connectivity and can access `https://live.sysinternals.com/`

## Example Output Summary

```
=== Analysis Summary ===
Total Items Analyzed: 487
  High Risk (Red):    12
  Medium Risk (Yellow): 34
  Low Risk (Green):   441

Breakdown by Category:
  Autoruns:   156
  Services:   182
  Network:    23
  Processes:  126

VirusTotal Scans: 287 items

[!] WARNING: Found 12 high-risk items requiring immediate attention!
```

## Use Cases

- **Incident Response**: Quickly identify suspicious autostart locations and processes
- **Malware Hunting**: Find unsigned or malicious executables
- **Compliance Auditing**: Document all autostart entries and services
- **System Baseline**: Create a snapshot of system configuration
- **Forensic Analysis**: Investigate compromised systems

## License

This tool is provided as-is for forensic investigation and security research purposes.

Sysinternals tools are property of Microsoft Corporation and subject to their license terms.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Disclaimer

This tool is intended for authorized security testing and forensic investigation only. Always ensure you have proper authorization before running forensic tools on any system.
