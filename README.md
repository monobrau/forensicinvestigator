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
  - CSV format by default (works in all environments including ScreenConnect)
  - XLSX format with color-coded risk levels (use -ExportXLSX flag, requires Excel)
- **Risk Assessment**: Three-tier color coding system
  - **Red (High Risk)**: Unsigned executables OR VirusTotal detections ≥ 5
  - **Yellow (Medium Risk)**: Unknown publisher OR VirusTotal detections 1-4
  - **Green (Low Risk)**: Verified signature AND VirusTotal detections = 0

## Requirements

- **Operating System**: Windows (PowerShell 5.1 or later)
- **Privileges**: Administrator rights required for full analysis
- **Optional**: Microsoft Excel (for XLSX export with color coding, use -ExportXLSX flag)
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
| `CleanupTools` | Switch | No | `$false` | Delete Sysinternals tools after analysis |
| `ExportXLSX` | Switch | No | `$false` | Export to Excel format (XLSX) instead of CSV. Requires Excel installed. |
| `CombinedWorkbook` | Switch | No | `$false` | Export to single Excel workbook (slower). Only applies with -ExportXLSX. |

## Remote Deployment

The tool supports remote deployment via ScreenConnect and direct PowerShell execution.

### Tested & Verified Methods

#### Direct Download & Execute (✅ Tested)

Download the main script directly and run with custom parameters:

```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

**Benefits:**
- No encoding issues
- Direct access to all parameters
- Works in ScreenConnect and regular PowerShell
- Custom output paths supported

**All Parameters Available:**
```powershell
-OutputPath "C:\SecurityReports"        # Custom output location
-ToolsPath "C:\Tools"                   # Custom tools location
-EnableVirusTotal                       # Enable malware scanning
-VirusTotalApiKey "your-key"           # VT API key
-CleanupTools                          # Delete tools after scan
-ExportXLSX                            # Export to Excel format (requires Excel)
-CombinedWorkbook                      # Single Excel file (slower, requires -ExportXLSX)
```

#### Run Directly from GitHub (No Disk Storage) ✅

Execute the script directly from GitHub without saving it to disk:

```powershell
# Basic execution (default parameters)
iex (irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1")
```

**With Parameters (Recommended):**
```powershell
# Using scriptblock for parameter passing (defaults to CSV)
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"))) -OutputPath "C:\SecurityReports"
```

**With Multiple Parameters:**
```powershell
# CSV output (default) with cleanup
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"))) -OutputPath "C:\SecurityReports" -CleanupTools
```

**With VirusTotal:**
```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"))) -OutputPath "C:\SecurityReports" -EnableVirusTotal -VirusTotalApiKey "your-api-key"
```

**Benefits:**
- ✅ No script file saved to disk (runs entirely from memory)
- ✅ Useful for security-sensitive environments
- ✅ Leaves no PowerShell script artifacts
- ✅ Still downloads Sysinternals tools (required for execution)
- ✅ Reports are still written to disk (that's the output)

**Note:** The script itself runs from memory, but it still needs to download Sysinternals tools and write reports to disk. Only the PowerShell script file itself is not saved.

### ConnectWise ScreenConnect Commands (✅ Tested)

ConnectWise ScreenConnect provides multiple ways to execute PowerShell scripts remotely. Choose the method that best fits your needs.

#### Step-by-Step Instructions

1. **Connect to the target machine** in ScreenConnect
2. Click the **Commands** button (or press F5)
3. Paste one of the tested commands below (ScreenConnect will auto-detect the `#!ps` prefix)
4. Press **Enter** or click **Run**

**Note:** Replace `YOUR_USERNAME` in the URLs below with your GitHub username (or use the full URL to your hosted script location).

#### Recommended Commands (Tested ✅)

**Option 1: Basic Scan with Custom Output Path**
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```
- ✅ Verified working in ScreenConnect
- Fast execution (2-5 minutes)
- Saves to easy-to-find location
- No encoding issues

**Option 2: Default Output Location**
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1"
```
- Saves to `C:\Windows\Temp\ForensicReports\` (when running as SYSTEM)
- Otherwise saves to `C:\Users\[Username]\AppData\Local\Temp\ForensicReports\`

**Option 3: Combined Workbook (Single Excel File)**
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -ExportXLSX -CombinedWorkbook -OutputPath "C:\SecurityReports"
```
- Creates one Excel file with all worksheets
- Slower than separate files
- Easier to manage and transfer

**Option 4: With VirusTotal Scanning**
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -EnableVirusTotal -VirusTotalApiKey "your-api-key" -OutputPath "C:\SecurityReports"
```
- Scans all executables for malware
- Takes 30-60+ minutes (API rate limited)
- Requires free VirusTotal API key

**Option 5: Export to Excel (XLSX) Format**
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -ExportXLSX -OutputPath "C:\SecurityReports"
```
- Exports to Excel format with color-coded risk levels
- Requires Microsoft Excel to be installed
- Note: CSV is the default format (works in ScreenConnect without Excel)

#### Saving as Reusable ScreenConnect Command

1. In ScreenConnect, go to **Admin** → **Command Toolbox**
2. Click **Add Command**
3. Name it: `Forensic Scan - Basic`
4. Command Type: **PowerShell** (or leave as Command)
5. Paste the tested command:

```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

6. Save and run from the Commands menu anytime

**For Combined Workbook Version:**
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\FA.ps1" -Encoding UTF8 -Force; powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$env:TEMP\FA.ps1" -ExportXLSX -CombinedWorkbook -OutputPath "C:\SecurityReports"
```

#### Retrieving Reports

After execution completes, reports are saved to:
- **Default Location**: `C:\Users\[Username]\AppData\Local\Temp\ForensicReports\` (or `C:\Windows\Temp\ForensicReports\` if running as SYSTEM)
- **Custom Location**: Path specified with `-OutputPath` parameter (e.g., `-OutputPath "C:\SecurityReports"`)

**Setting Custom Output Path:**
```powershell
# Example: Save to C:\SecurityReports
-OutputPath "C:\SecurityReports"

# Example: Save to network share
-OutputPath "\\server\share\ForensicReports"

# Example: Save to user desktop
-OutputPath "$env:USERPROFILE\Desktop\ForensicReports"
```

To retrieve reports via ScreenConnect:
1. Open **File Manager** in the session
2. Navigate to the report directory (default or custom path)
3. Download the `.xlsx` or `.csv` files
4. Or use ScreenConnect's **Transfer Files** feature

**Tip:** Using a custom output path like `C:\SecurityReports` makes finding and transferring reports much easier than the default temp directory.

#### Troubleshooting ScreenConnect Commands

**Error: "Execution Policy Restricted"**

Try using the direct PowerShell call method with proper encoding:
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "$script = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1' -UseBasicParsing; $script | Out-File -FilePath '$env:TEMP\RemoteLaunch.ps1' -Encoding UTF8 -Force; & '$env:TEMP\RemoteLaunch.ps1'"
```

Or with `#!ps` prefix:
```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Remote-Launch.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\RemoteLaunch.ps1" -Encoding UTF8 -Force; & "$env:TEMP\RemoteLaunch.ps1"
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

## Email Integration with Gmail

The tool includes a wrapper script that automatically emails forensic reports via Gmail after analysis completes. This is ideal for ScreenConnect deployments where you need results delivered automatically without manual file transfer.

### Prerequisites

1. **Gmail Account** with 2-Step Verification enabled
2. **Gmail App Password** (not your regular password)
   - Create at: https://myaccount.google.com/apppasswords
   - Select "Mail" as the app
   - Copy the 16-character password (remove spaces)

### Setup Instructions

#### Step 1: Generate Encrypted Credentials

Run the setup script to create an encrypted password string:

```powershell
.\Setup-SecureCredentials.ps1
```

This will prompt for:
- Your Gmail address
- Your Gmail App Password (16 characters)

The script will output an encrypted string that you'll paste into `Send-ForensicReport.ps1`.

#### Step 2: Encode Credentials for ScreenConnect

Run the encoding script to create a base64-encoded credential string:

```powershell
.\Encode-Credentials.ps1
```

This will prompt for:
- Your Gmail address
- Recipient email (can be same as Gmail address)
- Encrypted password (from Step 1)

The script will output a base64-encoded string that you'll use in your ScreenConnect command.

#### Step 3: Deploy via ScreenConnect

**Option A: Using Base64 Credentials (Recommended - No credentials in GitHub)**

Use this command in ScreenConnect, replacing `YOUR_BASE64_STRING` with the string from Step 2:

```powershell
#!ps
$creds = "YOUR_BASE64_STRING"; $script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Send-ForensicReport.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\SendReport.ps1" -Encoding UTF8 -Force; & "$env:TEMP\SendReport.ps1" -EncryptedCredentialsBase64 $creds
```

**Option B: Configure Script Locally (Alternative)**

If you prefer to configure the script directly, open `Send-ForensicReport.ps1` and update the configuration section at the top:

```powershell
# Update these values:
$GmailAddress = "your-email@gmail.com"
$RecipientEmail = "your-email@gmail.com"  # Can be same or different
$EncryptedPassword = "01000000d08c9ddf..."  # Paste encrypted string from Step 1
```

**⚠️ SECURITY WARNING: Do NOT commit this file to GitHub with real credentials!**

Then use this command in ScreenConnect:

```powershell
#!ps
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Send-ForensicReport.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\SendReport.ps1" -Encoding UTF8 -Force; & "$env:TEMP\SendReport.ps1"
```

**Recommended:** Use Option A (base64) to keep credentials out of GitHub entirely.

The script will:
1. Download and run the forensic analysis
2. Generate CSV reports and ZIP archive
3. Automatically email the ZIP file to your specified recipient
4. Suppress all output (credentials remain secure)

### Security Features

- **Encrypted Credentials**: App Password stored as encrypted SecureString
- **No Output**: All output suppressed to prevent credential exposure
- **App Password**: Uses Gmail App Password (not regular password)
- **Silent Failures**: Errors don't expose sensitive information

### Important Notes

- **Machine-Specific**: Encrypted passwords are machine/user-specific
- **ScreenConnect**: For ScreenConnect deployments, create the encrypted password on a test machine using the same user context that ScreenConnect uses
- **Alternative**: If encrypted passwords don't work due to user context, you can modify the script to use plaintext App Password (less secure but functional)

### Troubleshooting Email

**Email not received:**
- Verify Gmail App Password is correct (16 characters, no spaces)
- Check spam/junk folder
- Verify 2-Step Verification is enabled
- Ensure SMTP port 587 is not blocked

**Encrypted password doesn't work:**
- Create encrypted password on test machine via ScreenConnect (same user context)
- Or modify script to use plaintext App Password temporarily for testing

**Script runs but no email:**
- Check that ZIP file was generated successfully
- Verify Gmail address and recipient email are correct
- Use the debug version to see detailed output:
  ```powershell
  #!ps
  $creds = "YOUR_BASE64_STRING"; $script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Send-ForensicReport-Debug.ps1" -UseBasicParsing; $script | Out-File -FilePath "$env:TEMP\SendReport-Debug.ps1" -Encoding UTF8 -Force; & "$env:TEMP\SendReport-Debug.ps1" -EncryptedCredentialsBase64 $creds
  ```
- Common causes:
  - Encrypted password created on different machine/user (ScreenConnect context issue)
  - ZIP file not found (analysis may have failed silently)
  - Email sending failed (check Gmail App Password)

### Security Best Practices

- **Never commit credentials**: The repository version uses placeholders only
- **Use local copies**: Create `Send-ForensicReport-local.ps1` for your configured version
- **Rotate credentials**: Regenerate App Passwords periodically
- **Private repositories**: If sharing configured scripts, use private repos only
- **Git ignore**: Files matching `*credentials*.ps1` and `*Credential*.ps1` are gitignored

### Manual Email Alternative

If you prefer to send emails manually after analysis, you can use the standard forensic analysis script and manually transfer files via ScreenConnect File Manager.

## Getting a VirusTotal API Key

1. Create a free account at [VirusTotal](https://www.virustotal.com/)
2. Navigate to your profile settings
3. Copy your API key
4. **Note**: Free API keys are limited to 4 requests per minute

## Output Format

### Excel (XLSX) Output

When using the `-ExportXLSX` flag and Microsoft Excel is installed, the tool generates Excel workbooks:

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

### CSV Output (Default)

By default, the tool exports to CSV format which works in all environments including ScreenConnect. Separate CSV files are created:

- `{HOSTNAME}_Autoruns_{TIMESTAMP}.csv`
- `{HOSTNAME}_Services_{TIMESTAMP}.csv`
- `{HOSTNAME}_Network_{TIMESTAMP}.csv`
- `{HOSTNAME}_Processes_{TIMESTAMP}.csv`

**Note**: CSV files include all data but cannot display color coding. CSV is the default format and works reliably in ScreenConnect and other headless environments.

**Export to Excel (XLSX) Format:**
```powershell
.\Invoke-ForensicAnalysis.ps1 -ExportXLSX -OutputPath "C:\SecurityReports"
```
This will export to Excel format with color-coded risk levels. Requires Microsoft Excel to be installed. Use this flag when you need color-coded reports and Excel is available.

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
The tool defaults to CSV export which works in all environments. To use Excel format, install Microsoft Excel and use the `-ExportXLSX` flag. CSV is recommended for ScreenConnect and headless environments to avoid Excel COM automation issues.

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
