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
    Use this parameter if GitHub is blocked and you have an alternative hosting location.

.PARAMETER LocalScriptPath
    Local file path to Invoke-ForensicAnalysis.ps1. If provided, this takes precedence over ScriptUrl.
    Use this when running from a local file or network share instead of downloading from the web.

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
    [string]$PlaintextAppPassword = "",
    
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
            
            # Check if using plaintext password (for ScreenConnect compatibility)
            if ($parts.Count -ge 4 -and $parts[2] -eq "PLAINTEXT") {
                $PlaintextAppPassword = $parts[3]
            } else {
                $EncryptedPassword = $parts[2]
            }
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
                $script = Invoke-RestMethod -Uri $altUrl -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
                $script | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
                return $true
            } catch {
                continue
            }
        }
    }
    
    return $false
}

try {
    # Step 1: Download and execute forensic analysis script
    $tempScriptPath = Join-Path $env:TEMP "Invoke-ForensicAnalysis.ps1"
    
<<<<<<< HEAD
    # Download main script with error handling
    try {
        $response = Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop
        $content = if ($response.Content -is [byte[]]) { 
            [System.Text.Encoding]::UTF8.GetString($response.Content) 
        } else { 
            $response.Content 
        }
        
        # Check for web filter blocking
        if ($content -match '<html|<HTML|<!DOCTYPE|Securly|web filter') {
            # Silent failure - don't expose errors in production script
            exit 0
        }
        
        $content | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
    } catch {
        # Silent failure - don't expose errors
=======
    # Check if local script path is provided and exists
    if (![string]::IsNullOrWhiteSpace($LocalScriptPath) -and (Test-Path $LocalScriptPath)) {
        # Use local script file
        Copy-Item $LocalScriptPath -Destination $tempScriptPath -Force -ErrorAction Stop | Out-Null
    } elseif (![string]::IsNullOrWhiteSpace($ScriptUrl)) {
        # Check if it's a GitHub URL - try alternatives automatically
        if ($ScriptUrl -match 'githubusercontent\.com|github\.com') {
            # Try alternative GitHub domains
            $success = Get-ScriptFromGitHub -OriginalUrl $ScriptUrl -OutputPath $tempScriptPath
            
            if (-not $success) {
                # Fall back to original URL
                try {
                    Invoke-RestMethod -Uri $ScriptUrl -OutFile $tempScriptPath -UseBasicParsing -ErrorAction Stop | Out-Null
                } catch {
                    # Try alternate download method
                    try {
                        (New-Object System.Net.WebClient).DownloadFile($ScriptUrl, $tempScriptPath)
                    } catch {
                        # Download failed - exit silently
                        exit 0
                    }
                }
            }
        } else {
            # Non-GitHub URL - try direct download
            try {
                Invoke-RestMethod -Uri $ScriptUrl -OutFile $tempScriptPath -UseBasicParsing -ErrorAction Stop | Out-Null
            } catch {
                # Try alternate download method
                try {
                    (New-Object System.Net.WebClient).DownloadFile($ScriptUrl, $tempScriptPath)
                } catch {
                    # Download failed - exit silently
                    exit 0
                }
            }
        }
    } else {
        # No script source provided - exit silently
        exit 0
    }
    
    # Execute (defaults to CSV which generates ZIP file)
    & $tempScriptPath -OutputPath $OutputPath *>&1 | Out-Null
    
    # Step 2: Find the generated ZIP file
    $ZipFile = Get-ChildItem -Path $OutputPath -Filter "*.zip" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 1
    
    if (-not $ZipFile) {
        # No ZIP file found - wait a bit and try again (analysis might still be running)
        Start-Sleep -Seconds 10
        $ZipFile = Get-ChildItem -Path $OutputPath -Filter "*.zip" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if (-not $ZipFile) {
            # Still no ZIP file - exit silently
            exit 0
        }
    }
    
    # Step 3: Prepare email credentials
    # Try plaintext App Password first (for ScreenConnect compatibility)
    $SecurePassword = $null
    
    if (![string]::IsNullOrWhiteSpace($PlaintextAppPassword)) {
        # Use plaintext App Password (works across all machines/users)
        $SecurePassword = ConvertTo-SecureString $PlaintextAppPassword -AsPlainText -Force -ErrorAction SilentlyContinue
    } elseif ($EncryptedPassword -ne "PASTE_YOUR_ENCRYPTED_PASSWORD_HERE" -and ![string]::IsNullOrWhiteSpace($EncryptedPassword)) {
        # Try encrypted password (machine/user-specific)
        $SecurePassword = $EncryptedPassword | ConvertTo-SecureString -ErrorAction SilentlyContinue
    }
    
    if (-not $SecurePassword) {
        # Failed to get password - exit silently
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

