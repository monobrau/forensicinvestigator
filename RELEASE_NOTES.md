# Release Notes - v1.0.0

## 🎉 First Official Release

This is the first stable release of the Forensic Investigation Tool - a comprehensive PowerShell-based forensic analysis tool that leverages Sysinternals utilities with optional VirusTotal integration.

## ✅ Tested Features

### Core Functionality
- **Comprehensive System Analysis**
  - Autorun entries (startup programs, scheduled tasks, services, drivers)
  - Windows Services (running and stopped)
  - Network connections (TCP listening and established)
  - Running processes

- **Smart Export Options**
  - Separate Excel files (fast, default)
  - Combined Excel workbook (single file with all worksheets)
  - CSV fallback when Excel is unavailable
  - Color-coded risk levels (Red/Yellow/Green)

- **Risk Assessment**
  - Three-tier risk scoring system
  - Digital signature verification
  - Optional VirusTotal malware detection

### Remote Deployment (✅ Tested)
- **ConnectWise ScreenConnect**: Fully tested and working
  - Direct script download and execution
  - Custom output paths
  - Combined workbook support
  - VirusTotal integration

### Key Parameters
- `-OutputPath`: Custom directory for reports
- `-CombinedWorkbook`: Single Excel file with all worksheets
- `-EnableVirusTotal`: Enable malware scanning
- `-VirusTotalApiKey`: Your VT API key
- `-CleanupTools`: Delete Sysinternals tools after completion
- `-ToolsPath`: Custom Sysinternals tools directory

## 📊 Tested Command (ScreenConnect)

```powershell
#!ps
irm "https://raw.githubusercontent.com/YOUR_USERNAME/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1" -OutFile "$env:TEMP\FA.ps1"; & "$env:TEMP\FA.ps1" -OutputPath "C:\SecurityReports"
```

## 🔧 Technical Details

- **Version**: 2.1.4
- **Platform**: Windows (PowerShell 5.1+)
- **Privileges**: Requires Administrator
- **Dependencies**:
  - Optional: Microsoft Excel (for XLSX export with color coding)
  - Optional: VirusTotal API key (for malware scanning)

## 📝 What's Included

- `Invoke-ForensicAnalysis.ps1` - Main forensic analysis script
- `Remote-Launch.ps1` - Remote deployment wrapper
- `Quick-Scan.ps1` - Fast services + network scan
- Comprehensive documentation (README, TESTING, TROUBLESHOOTING)

## 🐛 Bug Fixes

- Fixed CSV fallback when Excel COM fails (running as SYSTEM)
- Fixed Unicode encoding issue with delta symbol in CPU monitoring
- Fixed path truncation in Excel SaveAs operations
- Fixed separate Excel files export with absolute paths

## 🎯 Performance

- **Without VirusTotal**: 2-5 minutes
- **With VirusTotal**: 30-60+ minutes (API rate limited)
- **Autorunsc execution**: Optimized to ~30-60 seconds

## 📚 Documentation

- [README.md](README.md) - Complete usage guide
- [TESTING.md](TESTING.md) - Testing procedures
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions

## 🙏 Acknowledgments

- Sysinternals tools by Microsoft
- VirusTotal API for malware detection
- Community testing and feedback

## ⚠️ Known Limitations

- Excel COM automation fails when running as SYSTEM (auto-falls back to CSV)
- VirusTotal free API limited to 4 requests/minute
- Requires internet connectivity for Sysinternals download and VT scanning

## 🔜 Future Considerations

- Additional RMM platform testing (currently only ScreenConnect tested)
- HTML report export option
- Scheduled scan capabilities
- Network share direct export

---

**Full Changelog**: Initial release
