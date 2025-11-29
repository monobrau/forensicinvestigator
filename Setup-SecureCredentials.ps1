<#
.SYNOPSIS
    Helper script to generate encrypted Gmail App Password for Send-ForensicReport.ps1

.DESCRIPTION
    Prompts for Gmail address and App Password, then creates an encrypted SecureString
    that can be safely embedded in Send-ForensicReport.ps1.

.PARAMETER GmailAddress
    Gmail address (optional - will prompt if not provided)

.PARAMETER AppPassword
    Gmail App Password (optional - will prompt if not provided)

.EXAMPLE
    .\Setup-SecureCredentials.ps1

.EXAMPLE
    .\Setup-SecureCredentials.ps1 -GmailAddress "your-email@gmail.com"

.NOTES
    Gmail App Passwords can be created at: https://myaccount.google.com/apppasswords
    Requires 2-Step Verification to be enabled on your Google account.
    The encrypted password is machine/user-specific. For ScreenConnect, create it
    on a test machine using the same user context that ScreenConnect will use.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GmailAddress = "",
    
    [Parameter(Mandatory=$false)]
    [string]$AppPassword = ""
)

Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║     Gmail Credential Setup for Forensic Investigator      ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Get Gmail address if not provided
if ([string]::IsNullOrWhiteSpace($GmailAddress)) {
    Write-Host "Enter your Gmail address:" -ForegroundColor Yellow
    $GmailAddress = Read-Host
}

if ([string]::IsNullOrWhiteSpace($GmailAddress)) {
    Write-Host "`n[ERROR] Gmail address is required!" -ForegroundColor Red
    exit 1
}

# Get App Password if not provided
if ([string]::IsNullOrWhiteSpace($AppPassword)) {
    Write-Host "`nEnter your Gmail App Password (16 characters, no spaces):" -ForegroundColor Yellow
    Write-Host "Get one at: https://myaccount.google.com/apppasswords" -ForegroundColor Gray
    $AppPasswordSecure = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AppPasswordSecure)
    $AppPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

if ([string]::IsNullOrWhiteSpace($AppPassword)) {
    Write-Host "`n[ERROR] App Password is required!" -ForegroundColor Red
    exit 1
}

# Remove any spaces from App Password (Google shows them with spaces)
$AppPassword = $AppPassword -replace '\s', ''

if ($AppPassword.Length -ne 16) {
    Write-Host "`n[WARNING] App Password should be 16 characters (found $($AppPassword.Length))" -ForegroundColor Yellow
    Write-Host "Continuing anyway..." -ForegroundColor Yellow
}

# Create SecureString from App Password
$SecurePassword = ConvertTo-SecureString $AppPassword -AsPlainText -Force

# Create credential object
$Credential = New-Object System.Management.Automation.PSCredential($GmailAddress, $SecurePassword)

# Convert to encrypted string
$EncryptedPassword = $Credential.Password | ConvertFrom-SecureString

# Clear sensitive data from memory
$AppPassword = $null
$SecurePassword = $null
$Credential = $null
[System.GC]::Collect()

# Display results
Write-Host "`n" -NoNewline
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Encrypted Credentials Generated              ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nGmail Address: " -NoNewline
Write-Host $GmailAddress -ForegroundColor Cyan

Write-Host "`nEncrypted Password String:" -ForegroundColor Yellow
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray
Write-Host $EncryptedPassword -ForegroundColor White -BackgroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

Write-Host "`n" -NoNewline
Write-Host "NEXT STEPS:" -ForegroundColor Yellow -BackgroundColor DarkBlue
Write-Host @"

1. Copy the encrypted password string above
2. Open Send-ForensicReport.ps1
3. Find the line: `$EncryptedPassword = "PASTE_YOUR_ENCRYPTED_PASSWORD_HERE"`
4. Replace PASTE_YOUR_ENCRYPTED_PASSWORD_HERE with the copied string
5. Update `$GmailAddress` and `$RecipientEmail` in the configuration section

Example:
    `$EncryptedPassword = "$EncryptedPassword"`

"@ -ForegroundColor Cyan

Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow -BackgroundColor DarkRed
Write-Host @"
• The encrypted password is machine/user-specific
• For ScreenConnect: Create this on a test machine using the same user context
• Store this encrypted string securely - you'll need it for each script deployment
• If you lose it, run this script again to generate a new one

"@ -ForegroundColor Yellow

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

