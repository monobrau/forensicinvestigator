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
