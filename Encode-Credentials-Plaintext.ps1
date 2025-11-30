<#
.SYNOPSIS
    Helper script to encode Gmail credentials with plaintext App Password for ScreenConnect

.DESCRIPTION
    Creates base64-encoded credentials using plaintext App Password instead of encrypted.
    This works across all machines and user contexts (ideal for ScreenConnect).

.EXAMPLE
    .\Encode-Credentials-Plaintext.ps1
#>

Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║  Encode Credentials (Plaintext) for ScreenConnect        ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "NOTE: This uses plaintext App Password (less secure but works everywhere)" -ForegroundColor Yellow
Write-Host ""

# Get Gmail address
Write-Host "Enter your Gmail address:" -ForegroundColor Yellow
$GmailAddress = Read-Host
if ([string]::IsNullOrWhiteSpace($GmailAddress)) {
    Write-Host "[ERROR] Gmail address is required!" -ForegroundColor Red
    exit 1
}

# Get recipient email
Write-Host "`nEnter recipient email (can be same as Gmail address):" -ForegroundColor Yellow
$RecipientEmail = Read-Host
if ([string]::IsNullOrWhiteSpace($RecipientEmail)) {
    $RecipientEmail = $GmailAddress
    Write-Host "Using Gmail address as recipient" -ForegroundColor Gray
}

# Get plaintext App Password
Write-Host "`nEnter your Gmail App Password (16 characters, no spaces):" -ForegroundColor Yellow
Write-Host "Get one at: https://myaccount.google.com/apppasswords" -ForegroundColor Gray
$AppPassword = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AppPassword)
$PlaintextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Remove any spaces from App Password
$PlaintextPassword = $PlaintextPassword -replace '\s', ''

if ($PlaintextPassword.Length -ne 16) {
    Write-Host "`n[WARNING] App Password should be 16 characters (found $($PlaintextPassword.Length))" -ForegroundColor Yellow
    Write-Host "Continuing anyway..." -ForegroundColor Yellow
}

# Combine credentials with newline separators
# Format: GmailAddress\nRecipientEmail\nPLAINTEXT_PASSWORD_FLAG\nPlaintextPassword
$credentials = "$GmailAddress`n$RecipientEmail`nPLAINTEXT`n$PlaintextPassword"

# Encode to base64
$base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credentials))

# Clear sensitive data from memory
$PlaintextPassword = $null
$AppPassword = $null
[System.GC]::Collect()

# Display results
Write-Host "`n" -NoNewline
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Base64 Encoded Credentials                   ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nBase64 Encoded String:" -ForegroundColor Yellow
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray
Write-Host $base64 -ForegroundColor White -BackgroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

Write-Host "`n" -NoNewline
Write-Host "SCREENCONNECT COMMAND:" -ForegroundColor Yellow -BackgroundColor DarkBlue
Write-Host @"

Copy this command and replace YOUR_BASE64_STRING with the string above:

#!ps
`$creds = "YOUR_BASE64_STRING"; Invoke-RestMethod -Uri "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Send-ForensicReport.ps1" -OutFile "`$env:TEMP\SendReport.ps1"; & "`$env:TEMP\SendReport.ps1" -EncryptedCredentialsBase64 `$creds

"@ -ForegroundColor Cyan

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

