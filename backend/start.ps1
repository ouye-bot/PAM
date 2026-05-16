# PAM System Start Script
# Support encrypted SM2 private key decryption

param(
    [SecureString]$Password,
    [string]$PasswordPlain
)

$ErrorActionPreference = "Stop"

# Skip Docker check, PAM backend runs directly in Windows native Python environment

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = $scriptDir

# Read .env file
$envPath = Join-Path $backendDir ".env"
if (-not (Test-Path $envPath)) {
    Write-Host ".env file not found" -ForegroundColor Red
    exit 1
}

$envVars = @{}
Get-Content $envPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $parts = $line -split "=", 2
        if ($parts.Length -eq 2) {
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            $envVars[$key] = $value
        }
    }
}

# Check if using encrypted private key
$isEncrypted = $envVars['SM2_PRIVATE_KEY_ENCRYPTED'] -eq 'true'

if ($isEncrypted) {
    Write-Host "Detected encrypted SM2 private key" -ForegroundColor Cyan

    # Determine password source: PasswordPlain > Password > interactive prompt
    if ($PasswordPlain) {
        $plainPassword = $PasswordPlain
        Write-Host "Using provided password" -ForegroundColor Green
    } elseif ($Password) {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    } else {
        Write-Host "Please enter SM2 private key decryption password..." -ForegroundColor Yellow
        $secPassword = Read-Host -AsSecureString "Password"
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }

    # Set environment variable
    $env:SM2_PRIVATE_KEY_PASSWORD = $plainPassword

    Write-Host "Password set, starting backend service..." -ForegroundColor Green
} else {
    Write-Host "Detected plain text SM2 private key, starting directly..." -ForegroundColor Cyan
}

# Start backend service
Write-Host ""
Write-Host "Starting PAM backend service..." -ForegroundColor Cyan
Write-Host ""

# Start MySQL proxy (background process)
Write-Host "Starting MySQL proxy..." -ForegroundColor Cyan
Start-Process -NoNewWindow python -ArgumentList "backend/app/services/mysql_proxy.py"

try {
    Set-Location $backendDir
    python app.py
} finally {
    # Clean up environment variable
    if ($isEncrypted) {
        Remove-Item Env:\SM2_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "Cleaned up sensitive environment variable" -ForegroundColor Cyan
    }
}
