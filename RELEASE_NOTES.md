# Release Notes

## v2.2.0 - CSV Default Export (2026-01-06)

### 🎯 Major Changes

**CSV is now the default export format** - This change makes the tool work reliably in ScreenConnect backstage and other headless environments where Excel COM automation causes issues (black screens, Office registration problems).

### ✨ New Features

- **Default CSV Export**: Tool now exports to CSV by default, avoiding Excel COM automation issues
- **New `-ExportXLSX` Flag**: Use this flag to export to Excel format when Excel is available and needed
- **ScreenConnect Optimized**: No longer attempts Excel COM automation unless explicitly requested

### 🔄 Changed Behavior

- **Removed `-ForceCSV` parameter**: No longer needed since CSV is the default
- **Excel only checked when `-ExportXLSX` is used**: Prevents Excel COM initialization in headless environments
- **All documentation updated**: README, Remote-Launch.ps1, and wrapper scripts reflect new defaults

### 📝 Migration Guide

**Old usage (v2.1.4):**
```powershell
.\Invoke-ForensicAnalysis.ps1 -ForceCSV -OutputPath "C:\Reports"
```

**New usage (v2.2.0):**
```powershell
# CSV (default) - no flag needed
.\Invoke-ForensicAnalysis.ps1 -OutputPath "C:\Reports"

# Excel format (when needed)
.\Invoke-ForensicAnalysis.ps1 -ExportXLSX -OutputPath "C:\Reports"
```

### 🐛 Bug Fixes

- Fixed Excel COM automation issues in ScreenConnect backstage
- Eliminated black screen issues when Excel tries to register Office
- Improved reliability in headless/remote execution environments

### 📊 Technical Details

- **Version**: 2.2.0-CSVDefault-20260106
- **Breaking Change**: Yes - `-ForceCSV` parameter removed, replaced with `-ExportXLSX`
- **Backward Compatibility**: Scripts using `-ForceCSV` will need to be updated (or simply remove the flag since CSV is now default)

---

## v1.0.0 - First Official Release

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

- **Version**: 2.1.4 (superseded by v2.2.0)
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
