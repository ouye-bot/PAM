<#
.SYNOPSIS
    Verify PAM system bypass login detection function

.DESCRIPTION
    Use SSH client to directly connect to specified asset (bypassing PAM proxy) to trigger a bypass login

.PARAMETER IP
    Asset IP address, default value is localhost

.PARAMETER Port
    SSH port, default value is 2221

.PARAMETER Username
    SSH username, default value is root

.PARAMETER Password
    SSH password

.PARAMETER PamUsername
    PAM system administrator username (default: admin)

.PARAMETER PamPassword
    PAM system administrator password

.PARAMETER Token
    Directly provide PAM system JWT token (skip login)

.PARAMETER NoPrompt
    Do not show interactive prompt, automatically query alerts

.EXAMPLE
    .\test_bypass.ps1 -Port 2221 -Password "your_password" -PamUsername "admin" -PamPassword "admin123"

.EXAMPLE
    .\test_bypass.ps1 -Port 2221 -Password "your_password" -Token "eyJhbGciOi..."

.NOTES
    Author: PAM System
    Date: 2026-04-19
#>

param(
    [string]$IP = "localhost",
    [int]$Port = 2221,
    [string]$Username = "root",
    [string]$Password = "",
    [string]$PamUsername = "admin",
    [string]$PamPassword = "",
    [string]$Token = "",
    [switch]$NoPrompt = $false
)

$API_BASE = "http://localhost:5000/api"
$TOKEN_CACHE_FILE = "$env:TEMP\PAM_Bypass_Test_Token.tmp"
$TOKEN_EXPIRY_HOURS = 24

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    if ($Level -eq "Error") {
        Write-Host $logEntry -ForegroundColor Red
    } elseif ($Level -eq "Warning") {
        Write-Host $logEntry -ForegroundColor Yellow
    } else {
        Write-Host $logEntry -ForegroundColor Green
    }
}

function Get-CachedToken {
    if (Test-Path $TOKEN_CACHE_FILE) {
        $cache = Get-Content $TOKEN_CACHE_FILE | ConvertFrom-Json
        $cachedTime = [DateTime]::Parse($cache.timestamp)
        $elapsed = (Get-Date) - $cachedTime

        if ($elapsed.TotalHours -lt $TOKEN_EXPIRY_HOURS) {
            return $cache.token
        }
    }
    return $null
}

function Save-CachedToken {
    $cache = @{
        token = $Token
        timestamp = (Get-Date).ToString("o")
    }
    $cache | ConvertTo-Json | Set-Content $TOKEN_CACHE_FILE
}

function Get-PamToken {
    if (-not [string]::IsNullOrEmpty($Token)) {
        Write-Log "Using provided token"
        return $Token
    }

    $cachedToken = Get-CachedToken
    if ($cachedToken) {
        Write-Log "Using cached token"
        return $cachedToken
    }

    if ([string]::IsNullOrEmpty($PamPassword)) {
        $securePassword = Read-Host "Please enter PAM system admin password" -AsSecureString
        $PamPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        )
    }

    if ([string]::IsNullOrEmpty($PamPassword)) {
        Write-Log "Error: PAM password cannot be empty" "Error"
        return $null
    }

    Write-Log "Logging in to PAM system..."
    try {
        $loginResponse = Invoke-RestMethod -Uri "$API_BASE/auth/login" `
            -Method Post `
            -ContentType "application/json" `
            -Body (ConvertTo-Json @{username=$PamUsername;password=$PamPassword}) `
            -TimeoutSec 10

        if ($loginResponse.code -eq 200) {
            $global:Token = $loginResponse.token
            Save-CachedToken
            Write-Log "Successfully obtained token"
            return $global:Token
        } else {
            Write-Log "Login failed: $($loginResponse.message)" "Error"
            return $null
        }
    } catch {
        Write-Log "Login failed: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Query-BypassAlerts {
    param([string]$AuthToken)

    $headers = @{
        "Authorization" = "Bearer $AuthToken"
    }

    try {
        $apiResponse = Invoke-RestMethod -Uri "$API_BASE/dashboard/stats" `
            -Method Get `
            -Headers $headers `
            -TimeoutSec 10

        if ($apiResponse.code -eq 200) {
            if ($apiResponse.data.bypass_alerts_count -gt 0) {
                Write-Log "Detected $($apiResponse.data.bypass_alerts_count) bypass alerts" "Warning"
                if ($apiResponse.data.bypass_alerts.Count -gt 0) {
                    Write-Log "Recent bypass alerts:" "Warning"
                    $apiResponse.data.bypass_alerts | ForEach-Object {
                        Write-Log "Time: $($_.time) - Asset: $($_.asset) - Details: $($_.message)"
                    }
                }
            } else {
                Write-Log "No bypass alerts detected" "Info"
            }
        } else {
            Write-Log "API returned error: $($apiResponse.message)" "Error"
        }
    } catch {
        Write-Log "Failed to query alerts: $($_.Exception.Message)" "Error"
    }
}

$logFile = "$PSScriptRoot\test_bypass.log"

Write-Log "=== PAM System Bypass Detection Verification Script Started ==="

if ([string]::IsNullOrEmpty($IP)) {
    Write-Log "Error: IP address cannot be empty" "Error"
    exit 1
}

if ($Port -lt 1 -or $Port -gt 65535) {
    Write-Log "Error: Port number must be between 1-65535" "Error"
    exit 1
}

if ([string]::IsNullOrEmpty($Username)) {
    Write-Log "Error: Username cannot be empty" "Error"
    exit 1
}

if ([string]::IsNullOrEmpty($Password)) {
    $securePassword = Read-Host "Please enter SSH password" -AsSecureString
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    )
    if ([string]::IsNullOrEmpty($Password)) {
        Write-Log "Error: Password cannot be empty" "Error"
        exit 1
    }
}

Write-Log "Target asset: ${IP}:${Port}"
Write-Log "Username: $Username"
Write-Log "Attempting direct SSH connection (bypassing PAM proxy)..."

if (-not (Test-Path "C:\Windows\System32\OpenSSH\ssh.exe")) {
    Write-Log "Error: SSH client not found, please ensure OpenSSH client is installed" "Error"
    Write-Log "Installation method: Settings -> Apps -> Optional features -> Add feature -> OpenSSH Client" "Warning"
    exit 1
}

try {
    Write-Log "Executing command: ssh -p $Port $Username@$IP"
    Write-Log ""
    Write-Log "============================================="
    Write-Log "Note: After login, please immediately type 'exit' to quit, avoid long-term occupation" "Warning"
    Write-Log "============================================="
    Write-Log ""

    $process = Start-Process "ssh.exe" -ArgumentList "-p", $Port, "$Username@$IP" -PassThru -Wait

    Write-Log ""
    Write-Log "=== Connection Completed ==="
    Write-Log "Exit code: $($process.ExitCode)"
    Write-Log ""
} catch {
    Write-Log "SSH connection failed: $($_.Exception.Message)" "Error"
    exit 1
}

Write-Log "Please check PAM system:" "Warning"
Write-Log "1. Dashboard -> Bypass alert card"
Write-Log "2. Audit log -> Find bypass detection records"
Write-Log ""

$shouldQuery = $NoPrompt
if (-not $NoPrompt) {
    Write-Host "Auto query recent bypass alerts? (Y/N)" -ForegroundColor Cyan
    $response = Read-Host
    $shouldQuery = ($response -eq "Y" -or $response -eq "y")
}

if ($shouldQuery) {
    Write-Log "Obtaining PAM system token..."
    $authToken = Get-PamToken

    if ($authToken) {
        Write-Log "Querying recent bypass alerts..."
        Query-BypassAlerts -AuthToken $authToken
    } else {
        Write-Log "Cannot query alerts: Failed to obtain token. Please login to PAM system manually." "Warning"
    }
}

Write-Log ""
Write-Log "=== Verification Completed ==="
Write-Log "Log file: $logFile"