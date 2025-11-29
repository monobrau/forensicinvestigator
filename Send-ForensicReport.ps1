<#
.SYNOPSIS
    Wrapper script that runs forensic analysis and emails results via Gmail.

.DESCRIPTION
    Downloads and executes Invoke-ForensicAnalysis.ps1, then automatically emails
    the generated ZIP report via Gmail SMTP using encrypted App Password credentials.
    All output is suppressed to keep credentials secure.

.SECURITY WARNING
    ⚠️  DO NOT COMMIT THIS FILE TO GITHUB WITH REAL CREDENTIALS!
    ⚠️  Always use placeholders (your-email@gmail.com, PASTE_YOUR_ENCRYPTED_PASSWORD_HERE)
    ⚠️  Keep your configured version local or in a private repository only

.PARAMETER GmailAddress
    Gmail address to send from (optional, can be set in script configuration)

.PARAMETER RecipientEmail
    Email address to send report to (optional, can be set in script configuration)

.PARAMETER EncryptedPassword
    Encrypted App Password string (optional, can be set in script configuration)

.PARAMETER OutputPath
    Directory where reports will be saved. Defaults to C:\SecurityReports

.PARAMETER ScriptUrl
    URL to download Invoke-ForensicAnalysis.ps1 from. Defaults to GitHub main branch.

.EXAMPLE
    .\Send-ForensicReport.ps1

.EXAMPLE
    .\Send-ForensicReport.ps1 -GmailAddress "your-email@gmail.com" -RecipientEmail "recipient@gmail.com"

.NOTES
    Requires Gmail App Password (not regular password).
    Use Setup-SecureCredentials.ps1 to generate encrypted password string.
    All output is suppressed to prevent credential exposure.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GmailAddress = "",
    
    [Parameter(Mandatory=$false)]
    [string]$RecipientEmail = "",
    
    [Parameter(Mandatory=$false)]
    [string]$EncryptedPassword = "",
    
    [Parameter(Mandatory=$false)]
    [string]$EncryptedCredentialsBase64 = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\SecurityReports",
    
    [Parameter(Mandatory=$false)]
    [string]$ScriptUrl = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1"
)

# Suppress all output to keep credentials secure
$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# CONFIGURATION SECTION
# Update these values or pass them as parameters
# ============================================================================

# Gmail Configuration
# Option 1: Pass credentials via base64-encoded parameter (recommended for ScreenConnect)
if (![string]::IsNullOrWhiteSpace($EncryptedCredentialsBase64)) {
    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncryptedCredentialsBase64))
        $parts = $decoded -split "`n"
        if ($parts.Count -ge 3) {
            $GmailAddress = $parts[0]
            $RecipientEmail = $parts[1]
            $EncryptedPassword = $parts[2]
        }
    } catch {
        # Invalid base64 - fall through to embedded/default values
    }
}

# Option 2: Use individual parameters if provided (already handled via param block)

# Option 3: Fall back to embedded values if not provided as parameters
if ([string]::IsNullOrWhiteSpace($GmailAddress)) {
    $GmailAddress = "your-email@gmail.com"  # UPDATE THIS if not using base64 parameter
}

if ([string]::IsNullOrWhiteSpace($RecipientEmail)) {
    $RecipientEmail = "your-email@gmail.com"  # UPDATE THIS if not using base64 parameter
}

# Encrypted App Password
# Generate this using Setup-SecureCredentials.ps1, then paste here:
if ([string]::IsNullOrWhiteSpace($EncryptedPassword)) {
    $EncryptedPassword = "PASTE_YOUR_ENCRYPTED_PASSWORD_HERE"  # UPDATE THIS if not using base64 parameter
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    # Step 1: Download and execute forensic analysis script
    $tempScriptPath = Join-Path $env:TEMP "Invoke-ForensicAnalysis.ps1"
    
    # Download main script
    Invoke-RestMethod -Uri $ScriptUrl -OutFile $tempScriptPath -UseBasicParsing -ErrorAction Stop | Out-Null
    
    # Execute with ForceCSV to generate ZIP file
    & $tempScriptPath -OutputPath $OutputPath -ForceCSV *>&1 | Out-Null
    
    # Step 2: Find the generated ZIP file
    $ZipFile = Get-ChildItem -Path $OutputPath -Filter "*.zip" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 1
    
    if (-not $ZipFile) {
        # No ZIP file found - exit silently
        exit 0
    }
    
    # Step 3: Prepare email credentials
    # Decrypt the App Password
    if ($EncryptedPassword -eq "PASTE_YOUR_ENCRYPTED_PASSWORD_HERE" -or [string]::IsNullOrWhiteSpace($EncryptedPassword)) {
        # Credentials not configured - exit silently
        exit 0
    }
    
    $SecurePassword = $EncryptedPassword | ConvertTo-SecureString -ErrorAction SilentlyContinue
    if (-not $SecurePassword) {
        # Failed to decrypt - exit silently
        exit 0
    }
    
    $Credential = New-Object System.Management.Automation.PSCredential($GmailAddress, $SecurePassword)
    
    # Step 4: Send email
    $Subject = "Forensic Report - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $Body = @"
Forensic analysis completed on $env:COMPUTERNAME
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Report attached.
"@
    
    Send-MailMessage -SmtpServer "smtp.gmail.com" -Port 587 -UseSsl `
        -From $GmailAddress -To $RecipientEmail -Subject $Subject -Body $Body `
        -Attachments $ZipFile.FullName -Credential $Credential `
        -ErrorAction Stop *>&1 | Out-Null
    
    # Step 5: Cleanup temp script
    Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue | Out-Null
    
} catch {
    # Silent failure - don't expose errors or credentials
    exit 0
}

# Exit silently
exit 0

