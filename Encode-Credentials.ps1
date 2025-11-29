<#
.SYNOPSIS
    Helper script to encode Gmail credentials for use with Send-ForensicReport.ps1

.DESCRIPTION
    Takes your Gmail address, recipient email, and encrypted password, then
    encodes them as base64 for secure parameter passing in ScreenConnect commands.

.EXAMPLE
    .\Encode-Credentials.ps1
#>

Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║     Encode Credentials for Send-ForensicReport.ps1        ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

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

# Get encrypted password
Write-Host "`nEnter your encrypted password string (from Setup-SecureCredentials.ps1):" -ForegroundColor Yellow
$EncryptedPassword = Read-Host

if ([string]::IsNullOrWhiteSpace($EncryptedPassword)) {
    Write-Host "[ERROR] Encrypted password is required!" -ForegroundColor Red
    exit 1
}

# Combine credentials with newline separators
$credentials = "$GmailAddress`n$RecipientEmail`n$EncryptedPassword"

# Encode to base64
$base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credentials))

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
`$creds = "YOUR_BASE64_STRING"; irm "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Send-ForensicReport.ps1" -OutFile "`$env:TEMP\SendReport.ps1"; & "`$env:TEMP\SendReport.ps1" -EncryptedCredentialsBase64 `$creds

"@ -ForegroundColor Cyan

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

