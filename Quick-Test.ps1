<#
.SYNOPSIS
    Quick test script to identify what's causing crashes

.DESCRIPTION
    Runs each component separately to identify the problem area
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:TEMP\ForensicTest",

    [Parameter(Mandatory=$false)]
    [string]$ToolsPath = "$env:TEMP\SysinternalsTools"
)

Write-Host "=== Forensic Analysis - Component Test ===" -ForegroundColor Cyan
Write-Host "This will test each component separately to identify issues`n" -ForegroundColor Yellow

# Create directories
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null

# Test 1: Download Sysinternals
Write-Host "[Test 1/6] Downloading Sysinternals tools..." -ForegroundColor Cyan
try {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "64" } else { "" }
    $tool = "autorunsc$arch.exe"
    $url = "https://live.sysinternals.com/$tool"
    $dest = Join-Path $ToolsPath $tool

    if (!(Test-Path $dest)) {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 30
    }
    Write-Host "[PASS] Sysinternals download" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Sysinternals download: $_" -ForegroundColor Red
}

# Test 2: Run Autorunsc (with timeout)
Write-Host "`n[Test 2/6] Testing Autorunsc (30 second timeout)..." -ForegroundColor Cyan
try {
    $autorunsc = Join-Path $ToolsPath "autorunsc$arch.exe"

    if (Test-Path $autorunsc) {
        $job = Start-Job -ScriptBlock {
            param($exe)
            & $exe -accepteula -a b -c 2>&1 | Select-Object -First 10
        } -ArgumentList $autorunsc

        $result = Wait-Job $job -Timeout 30

        if ($result) {
            $output = Receive-Job $job
            Write-Host "[PASS] Autorunsc completed" -ForegroundColor Green
            Write-Host "  Sample output: $($output -join ' | ')" -ForegroundColor Gray
            Remove-Job $job -Force
        } else {
            Write-Host "[WARN] Autorunsc timed out (might be slow on your system)" -ForegroundColor Yellow
            Stop-Job $job
            Remove-Job $job -Force
        }
    } else {
        Write-Host "[SKIP] Autorunsc not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[FAIL] Autorunsc test: $_" -ForegroundColor Red
}

# Test 3: Service enumeration
Write-Host "`n[Test 3/6] Testing Service enumeration..." -ForegroundColor Cyan
try {
    $services = Get-WmiObject -Class Win32_Service -ErrorAction Stop | Select-Object -First 5
    Write-Host "[PASS] Service enumeration ($($services.Count) services sampled)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Service enumeration: $_" -ForegroundColor Red
}

# Test 4: Network connections
Write-Host "`n[Test 4/6] Testing Network connection enumeration..." -ForegroundColor Cyan
try {
    $connections = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -First 5
    Write-Host "[PASS] Network enumeration ($($connections.Count) connections sampled)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Network enumeration: $_" -ForegroundColor Red
}

# Test 5: Process enumeration
Write-Host "`n[Test 5/6] Testing Process enumeration..." -ForegroundColor Cyan
try {
    $processes = Get-Process | Where-Object { $_.Path } | Select-Object -First 5
    Write-Host "[PASS] Process enumeration ($($processes.Count) processes sampled)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Process enumeration: $_" -ForegroundColor Red
}

# Test 6: Excel COM
Write-Host "`n[Test 6/6] Testing Excel COM (if installed)..." -ForegroundColor Cyan
try {
    $excel = New-Object -ComObject Excel.Application -ErrorAction Stop
    $excel.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
    [System.GC]::Collect()
    Write-Host "[PASS] Excel COM object creation and cleanup" -ForegroundColor Green
} catch {
    Write-Host "[INFO] Excel not available (will use CSV export)" -ForegroundColor Yellow
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
Write-Host @"

Recommendations:
- If Autorunsc timed out, use: -SkipAutoruns parameter
- If Excel failed, CSV export will be used automatically
- If any test failed, that component may cause crashes

Safe mode command:
.\Invoke-ForensicAnalysis-Safe.ps1 -SkipAutoruns -OutputPath "$OutputPath"

"@ -ForegroundColor Yellow
