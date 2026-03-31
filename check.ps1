# ============================================================================
# Axios Supply Chain Attack — Detection Script (Windows)
# ============================================================================
# Checks if your system was affected by the axios@1.14.1 / axios@0.30.4
# supply chain attack that dropped a cross-platform RAT via plain-crypto-js.
#
# Source: StepSecurity, Socket.dev, GitHub Issue #10604
# ============================================================================
# Run in PowerShell: .\check.ps1
# ============================================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Axios Supply Chain Attack - Detection" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$found = $false

# --- Check 1: Installed axios version in entire dependency tree ---
Write-Host "[1/6] Checking axios versions in entire dependency tree..." -ForegroundColor Yellow
if (Get-Command npm -ErrorAction SilentlyContinue) {
    # Get full tree output so parent packages are visible
    $axiosTree = npm list axios --all 2>$null
    $axiosInstances = $axiosTree | Select-String "axios@"

    if ($axiosInstances) {
        $compromised = $axiosInstances | Select-String "axios@1\.14\.1|axios@0\.30\.4"
        if ($compromised) {
            Write-Host "  !! AFFECTED: Compromised axios version found in dependency tree" -ForegroundColor Red
            $axiosTree | ForEach-Object { Write-Host "    $_" }
            $found = $true
        } else {
            Write-Host "  OK: No compromised axios version in dependency tree" -ForegroundColor Green
            Write-Host "  Found versions (showing parent dependencies):"
            $axiosTree | ForEach-Object { Write-Host "    $_" }
        }
    } else {
        Write-Host "  OK: axios not found in dependencies" -ForegroundColor Green
    }
} else {
    Write-Host "  SKIP: npm not found"
}

# --- Check 2: Parse lockfile for axios-specific entries ---
Write-Host ""
Write-Host "[2/6] Checking lockfile for axios-specific entries..." -ForegroundColor Yellow
if (Test-Path "package-lock.json") {
    $content = Get-Content "package-lock.json"
    $axiosLock = $false
    for ($i = 0; $i -lt $content.Length; $i++) {
        if ($content[$i] -match '"axios":') {
            # Check the next 3 lines for a compromised version within this axios block
            $block = ($content[$i..([Math]::Min($i + 3, $content.Length - 1))]) -join "`n"
            if ($block -match '"version":\s*"(1\.14\.1|0\.30\.4)"') {
                $axiosLock = $true
                break
            }
        }
    }
    if ($axiosLock) {
        Write-Host "  !! AFFECTED: Compromised axios version found in package-lock.json" -ForegroundColor Red
        $found = $true
    } else {
        Write-Host "  OK: No compromised axios in package-lock.json" -ForegroundColor Green
    }
} elseif (Test-Path "yarn.lock") {
    $content = Get-Content "yarn.lock"
    $axiosLock = $false
    for ($i = 0; $i -lt $content.Length - 1; $i++) {
        if ($content[$i] -match "^axios@") {
            if ($content[$i + 1] -match "version (1\.14\.1|0\.30\.4)") {
                $axiosLock = $true
                break
            }
        }
    }
    if ($axiosLock) {
        Write-Host "  !! AFFECTED: Compromised axios version found in yarn.lock" -ForegroundColor Red
        $found = $true
    } else {
        Write-Host "  OK: No compromised axios in yarn.lock" -ForegroundColor Green
    }
} else {
    Write-Host "  SKIP: No lockfile found in current directory"
}

# --- Check 3: Lockfile git history ---
Write-Host ""
Write-Host "[3/6] Checking lockfile git history (forensic source of truth)..." -ForegroundColor Yellow
if (Test-Path ".git") {
    $gitHit = git log -p -- package-lock.json yarn.lock 2>$null | Select-String "plain-crypto-js" | Select-Object -First 3
    if ($gitHit) {
        Write-Host "  !! WARNING: plain-crypto-js appeared in lockfile history" -ForegroundColor Red
        Write-Host "  $gitHit"
        Write-Host "  (Your system MAY have been compromised even if node_modules is clean now)" -ForegroundColor Yellow
        $found = $true
    } else {
        Write-Host "  OK: No trace in git history" -ForegroundColor Green
    }
} else {
    Write-Host "  SKIP: Not a git repository"
}

# --- Check 4: Malicious dependency in node_modules ---
Write-Host ""
Write-Host "[4/6] Checking for malicious package in node_modules..." -ForegroundColor Yellow
if (Test-Path "node_modules\plain-crypto-js") {
    Write-Host "  !! AFFECTED: node_modules\plain-crypto-js EXISTS" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: plain-crypto-js not in node_modules" -ForegroundColor Green
    Write-Host "  (Note: Malware self-destructs - absence does NOT guarantee safety)"
}

# --- Check 5: RAT artifacts on disk ---
Write-Host ""
Write-Host "[5/6] Checking for RAT artifacts..." -ForegroundColor Yellow

# Windows RAT: wt.exe dropped in ProgramData
$wtPath = "$env:PROGRAMDATA\wt.exe"
if (Test-Path $wtPath) {
    Write-Host "  !! CRITICAL: Windows RAT found at $wtPath" -ForegroundColor Red
    Get-Item $wtPath | Format-List Name, Length, LastWriteTime
    $found = $true
} else {
    Write-Host "  OK: wt.exe not found in ProgramData" -ForegroundColor Green
}

# Temp payload files
$vbsPath = "$env:TEMP\6202033.vbs"
$ps1Path = "$env:TEMP\6202033.ps1"
if ((Test-Path $vbsPath) -or (Test-Path $ps1Path)) {
    Write-Host "  !! WARNING: Temp payload files found" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: No temp payload files" -ForegroundColor Green
}

# --- Check 6: Network connections to C2 ---
Write-Host ""
Write-Host "[6/6] Checking for C2 connections..." -ForegroundColor Yellow
$c2Check = netstat -an | Select-String "142\.11\.206\.73"
if ($c2Check) {
    Write-Host "  !! CRITICAL: Active connection to C2 server (142.11.206.73)" -ForegroundColor Red
    Write-Host "  $c2Check"
    $found = $true
} else {
    Write-Host "  OK: No active C2 connections detected" -ForegroundColor Green
}

# DNS cache check
$dnsCache = ipconfig /displaydns 2>$null | Select-String "sfrclak\.com"
if ($dnsCache) {
    Write-Host "  !! WARNING: DNS queries to sfrclak.com found in DNS cache" -ForegroundColor Red
    $found = $true
}

# --- Summary ---
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
if ($found) {
    Write-Host "  !! POTENTIAL COMPROMISE DETECTED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Immediate actions:"
    Write-Host "  1. Pin axios to 1.14.0 or 0.30.3"
    Write-Host "  2. Remove-Item -Recurse node_modules; npm ci"
    Write-Host "  3. Rotate ALL credentials (npm tokens, AWS, SSH, API keys)"
    Write-Host "  4. Block sfrclak.com and 142.11.206.73 at firewall"
    Write-Host "  5. If RAT artifacts found: FULL SYSTEM REBUILD"
    Write-Host ""
    Write-Host "  Ref: https://github.com/axios/axios/issues/10604"
} else {
    Write-Host "  ALL CLEAR — No indicators of compromise found" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Preventive steps:"
    Write-Host "  - Pin axios: npm install axios@1.14.0 --save-exact"
    Write-Host "  - Use npm ci (not npm install) in CI/CD"
    Write-Host "  - Set ignore-scripts=true in .npmrc"
    Write-Host "  - Run: npm config set min-release-age 3"
}
Write-Host "============================================" -ForegroundColor Cyan
