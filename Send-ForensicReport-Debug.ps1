<#
.SYNOPSIS
    Debug version of Send-ForensicReport.ps1 with output for troubleshooting
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
    [string]$ScriptUrl = "https://raw.githubusercontent.com/monobrau/forensicinvestigator/main/Invoke-ForensicAnalysis.ps1",
    
    [Parameter(Mandatory=$false)]
    [string]$LocalScriptPath = ""
)

# Enable TLS 1.2 for older Windows versions
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

$ErrorActionPreference = "Continue"  # Show errors for debugging

Write-Host "=== Send-ForensicReport Debug Mode ===" -ForegroundColor Cyan
Write-Host ""

# Decode base64 credentials if provided
if (![string]::IsNullOrWhiteSpace($EncryptedCredentialsBase64)) {
    Write-Host "[DEBUG] Decoding base64 credentials..." -ForegroundColor Yellow
    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncryptedCredentialsBase64))
        $parts = $decoded -split "`n"
        
        if ($parts.Count -ge 3) {
            $GmailAddress = $parts[0]
            $RecipientEmail = $parts[1]
            $EncryptedPassword = $parts[2]
            Write-Host "[+] Credentials decoded successfully" -ForegroundColor Green
            Write-Host "    From: $GmailAddress" -ForegroundColor Gray
            Write-Host "    To:   $RecipientEmail" -ForegroundColor Gray
            Write-Host "    Encrypted Password Length: $($EncryptedPassword.Length)" -ForegroundColor Gray
        } else {
            Write-Host "[!] Error: Decoded credentials don't have 3 parts (got $($parts.Count))" -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "[!] Error decoding base64: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[DEBUG] No base64 credentials provided, using individual parameters or defaults" -ForegroundColor Yellow
}

# Use individual parameters if provided
if ([string]::IsNullOrWhiteSpace($GmailAddress)) {
    $GmailAddress = "your-email@gmail.com"
    Write-Host "[!] Warning: Using default Gmail address (not configured)" -ForegroundColor Yellow
}

if ([string]::IsNullOrWhiteSpace($RecipientEmail)) {
    $RecipientEmail = "your-email@gmail.com"
    Write-Host "[!] Warning: Using default recipient email (not configured)" -ForegroundColor Yellow
}

if ([string]::IsNullOrWhiteSpace($EncryptedPassword)) {
    $EncryptedPassword = "PASTE_YOUR_ENCRYPTED_PASSWORD_HERE"
    Write-Host "[!] Warning: Using default encrypted password (not configured)" -ForegroundColor Yellow
}

# Function to try multiple GitHub alternative domains
function Get-ScriptFromGitHub {
    param(
        [string]$OriginalUrl,
        [string]$OutputPath
    )
    
    # Extract user/repo/branch/file from GitHub URL
    if ($OriginalUrl -match 'raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)') {
        $user = $matches[1]
        $repo = $matches[2]
        $branch = $matches[3]
        $file = $matches[4]
        
        # Alternative GitHub domains/CDNs to try
        $alternatives = @(
            # Original GitHub
            "https://raw.githubusercontent.com/$user/$repo/$branch/$file",
            # jsDelivr CDN (free, production-ready)
            "https://cdn.jsdelivr.net/gh/$user/$repo@$branch/$file",
            # StaticDelivr CDN (production CDN)
            "https://cdn.staticdelivr.com/gh/$user/$repo/$branch/$file",
            # Githack (caching proxy)
            "https://raw.githack.com/$user/$repo/$branch/$file",
            # Rawgit (caching proxy)
            "https://rawgit.net/$user/$repo/$branch/$file"
        )
        
        foreach ($altUrl in $alternatives) {
            try {
                Write-Host "    Trying: $altUrl" -ForegroundColor Gray
                $script = Invoke-RestMethod -Uri $altUrl -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
                Write-Host "[+] Successfully downloaded from: $altUrl" -ForegroundColor Green
                $script | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
                return $true
            } catch {
                Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor DarkGray
                continue
            }
        }
    }
    
    return $false
}

<<<<<<< HEAD
try {
    $response = Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop
    $content = if ($response.Content -is [byte[]]) { 
        [System.Text.Encoding]::UTF8.GetString($response.Content) 
    } else { 
        $response.Content 
    }
    
    # Check for web filter blocking
    if ($content -match '<html|<HTML|<!DOCTYPE|Securly|web filter|geolocation') {
        Write-Host "[!] ERROR: GitHub is blocked by a web filter" -ForegroundColor Red
        Write-Host "    Received HTML page instead of PowerShell script" -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host "SOLUTION - Manual Download:" -ForegroundColor Yellow
        Write-Host "  1. Open: https://github.com/monobrau/forensicinvestigator/blob/main/Invoke-ForensicAnalysis.ps1" -ForegroundColor Cyan
        Write-Host "  2. Click 'Raw' button (top right) - CRITICAL: Must use Raw button!" -ForegroundColor Cyan
        Write-Host "  3. Right-click → Save As → Save as Invoke-ForensicAnalysis.ps1" -ForegroundColor Cyan
        Write-Host "  4. Run manually: .\Invoke-ForensicAnalysis.ps1 -OutputPath '$OutputPath'" -ForegroundColor Cyan
        exit 1
    }
    
    $content | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
    Write-Host "[+] Script downloaded successfully" -ForegroundColor Green
} catch {
    $errorMsg = $_.Exception.Message
    Write-Host "[!] Failed to download script: $errorMsg" -ForegroundColor Red
    Write-Host "" -ForegroundColor Red
    
    # Check for SSL/TLS errors
    if ($errorMsg -match 'SSL/TLS|TLS|secure channel|Could not create') {
        Write-Host "POSSIBLE CAUSE: SSL/TLS error (Windows Server 2012 R2 needs TLS 1.2)" -ForegroundColor Yellow
        Write-Host "" -ForegroundColor Red
        Write-Host "SOLUTION - Manual Download:" -ForegroundColor Yellow
        Write-Host "  1. Open: https://github.com/monobrau/forensicinvestigator/blob/main/Invoke-ForensicAnalysis.ps1" -ForegroundColor Cyan
        Write-Host "  2. Click 'Raw' button (top right) - CRITICAL: Must use Raw button!" -ForegroundColor Cyan
        Write-Host "  3. Right-click → Save As → Save as Invoke-ForensicAnalysis.ps1" -ForegroundColor Cyan
        Write-Host "  4. Run manually: .\Invoke-ForensicAnalysis.ps1 -OutputPath '$OutputPath'" -ForegroundColor Cyan
        Write-Host "" -ForegroundColor Red
        Write-Host "Alternative: Enable TLS 1.2:" -ForegroundColor Yellow
        Write-Host "  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" -ForegroundColor Cyan
    } else {
        Write-Host "POSSIBLE CAUSES:" -ForegroundColor Yellow
        Write-Host "  - Web filter blocking GitHub" -ForegroundColor Gray
        Write-Host "  - Network connectivity issues" -ForegroundColor Gray
        Write-Host "  - Invalid URL" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Red
        Write-Host "SOLUTION: Download script manually from GitHub (see instructions above)" -ForegroundColor Yellow
    }
=======
Write-Host ""
Write-Host "=== Step 1: Load Script ===" -ForegroundColor Cyan
$tempScriptPath = Join-Path $env:TEMP "Invoke-ForensicAnalysis.ps1"

# Check if local script path is provided and exists
if (![string]::IsNullOrWhiteSpace($LocalScriptPath) -and (Test-Path $LocalScriptPath)) {
    Write-Host "Using local script file: $LocalScriptPath" -ForegroundColor Gray
    Write-Host "Copying to: $tempScriptPath" -ForegroundColor Gray
    try {
        Copy-Item $LocalScriptPath -Destination $tempScriptPath -Force -ErrorAction Stop
        Write-Host "[+] Script copied successfully" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to copy script: $_" -ForegroundColor Red
        Write-Host "    Error details: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} elseif (![string]::IsNullOrWhiteSpace($ScriptUrl)) {
    Write-Host "Downloading from: $ScriptUrl" -ForegroundColor Gray
    Write-Host "Saving to: $tempScriptPath" -ForegroundColor Gray
    
    # Check if it's a GitHub URL - try alternatives automatically
    if ($ScriptUrl -match 'githubusercontent\.com|github\.com') {
        Write-Host "GitHub URL detected - trying alternative domains..." -ForegroundColor Yellow
        $success = Get-ScriptFromGitHub -OriginalUrl $ScriptUrl -OutputPath $tempScriptPath
        
        if (-not $success) {
            Write-Host "All alternative domains failed, trying original URL..." -ForegroundColor Yellow
            try {
                Invoke-RestMethod -Uri $ScriptUrl -OutFile $tempScriptPath -UseBasicParsing -ErrorAction Stop
                Write-Host "[+] Script downloaded successfully" -ForegroundColor Green
            } catch {
                Write-Host "[!] Failed to download script: $_" -ForegroundColor Red
                Write-Host "    Error details: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    TIP: Use -LocalScriptPath parameter with a local file path if GitHub is blocked" -ForegroundColor Yellow
                exit 1
            }
        }
    } else {
        # Non-GitHub URL
        try {
            Invoke-RestMethod -Uri $ScriptUrl -OutFile $tempScriptPath -UseBasicParsing -ErrorAction Stop
            Write-Host "[+] Script downloaded successfully" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to download script: $_" -ForegroundColor Red
            Write-Host "    Error details: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    TIP: Use -LocalScriptPath parameter with a local file path" -ForegroundColor Yellow
            exit 1
        }
    }
} else {
    Write-Host "[!] ERROR: No script source provided" -ForegroundColor Red
    Write-Host "    Use -ScriptUrl or -LocalScriptPath parameter" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=== Step 2: Run Forensic Analysis ===" -ForegroundColor Cyan
Write-Host "Output Path: $OutputPath" -ForegroundColor Gray
Write-Host "This may take 2-5 minutes..." -ForegroundColor Yellow

try {
    & $tempScriptPath -OutputPath $OutputPath
    Write-Host "[+] Analysis completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Analysis failed: $_" -ForegroundColor Red
    Write-Host "    Error details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Step 3: Find ZIP File ===" -ForegroundColor Cyan
$ZipFile = Get-ChildItem -Path $OutputPath -Filter "*.zip" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1

if (-not $ZipFile) {
    Write-Host "[!] No ZIP file found immediately, waiting 10 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    $ZipFile = Get-ChildItem -Path $OutputPath -Filter "*.zip" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 1
}

if (-not $ZipFile) {
    Write-Host "[!] ERROR: No ZIP file found in $OutputPath" -ForegroundColor Red
    Write-Host "    Checking for CSV files..." -ForegroundColor Yellow
    $csvFiles = Get-ChildItem -Path $OutputPath -Filter "*.csv" -ErrorAction SilentlyContinue
    if ($csvFiles) {
        Write-Host "    Found $($csvFiles.Count) CSV files but no ZIP" -ForegroundColor Yellow
        Write-Host "    CSV files:" -ForegroundColor Gray
        $csvFiles | ForEach-Object { Write-Host "      - $($_.Name)" -ForegroundColor Gray }
    } else {
        Write-Host "    No files found in $OutputPath" -ForegroundColor Yellow
        Write-Host "    Directory exists: $(Test-Path $OutputPath)" -ForegroundColor Gray
    }
    exit 1
}

Write-Host "[+] Found ZIP file: $($ZipFile.Name)" -ForegroundColor Green
Write-Host "    Size: $([math]::Round($ZipFile.Length/1KB, 2)) KB" -ForegroundColor Gray
Write-Host "    Path: $($ZipFile.FullName)" -ForegroundColor Gray

Write-Host ""
Write-Host "=== Step 4: Prepare Credentials ===" -ForegroundColor Cyan

if ($EncryptedPassword -eq "PASTE_YOUR_ENCRYPTED_PASSWORD_HERE" -or [string]::IsNullOrWhiteSpace($EncryptedPassword)) {
    Write-Host "[!] ERROR: Encrypted password not configured" -ForegroundColor Red
    exit 1
}

try {
    $SecurePassword = $EncryptedPassword | ConvertTo-SecureString -ErrorAction Stop
    Write-Host "[+] Password decrypted successfully" -ForegroundColor Green
} catch {
    Write-Host "[!] ERROR: Failed to decrypt password: $_" -ForegroundColor Red
    Write-Host "    This usually means the encrypted password was created on a different machine/user" -ForegroundColor Yellow
    Write-Host "    For ScreenConnect: Create encrypted password on test machine using same user context" -ForegroundColor Yellow
    exit 1
}

try {
    $Credential = New-Object System.Management.Automation.PSCredential($GmailAddress, $SecurePassword)
    Write-Host "[+] Credential object created successfully" -ForegroundColor Green
} catch {
    Write-Host "[!] ERROR: Failed to create credential: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Step 5: Send Email ===" -ForegroundColor Cyan
$Subject = "Forensic Report - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
$Body = @"
Forensic analysis completed on $env:COMPUTERNAME
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Report attached.
"@

Write-Host "SMTP Server: smtp.gmail.com:587" -ForegroundColor Gray
Write-Host "From: $GmailAddress" -ForegroundColor Gray
Write-Host "To: $RecipientEmail" -ForegroundColor Gray
Write-Host "Subject: $Subject" -ForegroundColor Gray
Write-Host "Attachment: $($ZipFile.Name)" -ForegroundColor Gray

try {
    Send-MailMessage -SmtpServer "smtp.gmail.com" -Port 587 -UseSsl `
        -From $GmailAddress -To $RecipientEmail -Subject $Subject -Body $Body `
        -Attachments $ZipFile.FullName -Credential $Credential `
        -ErrorAction Stop
    
    Write-Host ""
    Write-Host "[+] Email sent successfully!" -ForegroundColor Green
    Write-Host "    Check inbox at: $RecipientEmail" -ForegroundColor Cyan
    Write-Host "    Subject: $Subject" -ForegroundColor Cyan
    
} catch {
    Write-Host ""
    Write-Host "[!] ERROR: Failed to send email: $_" -ForegroundColor Red
    Write-Host "    Error details: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host "    Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "  1. Gmail App Password incorrect (must be 16 characters, no spaces)" -ForegroundColor Gray
    Write-Host "  2. 2-Step Verification not enabled" -ForegroundColor Gray
    Write-Host "  3. SMTP port 587 blocked by firewall" -ForegroundColor Gray
    Write-Host "  4. Encrypted password created on different machine/user context" -ForegroundColor Gray
    exit 1
}

Write-Host ""
Write-Host "=== Cleanup ===" -ForegroundColor Cyan
try {
    Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Temp script cleaned up" -ForegroundColor Green
} catch {
    Write-Host "[!] Warning: Failed to cleanup temp script: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Complete ===" -ForegroundColor Green

