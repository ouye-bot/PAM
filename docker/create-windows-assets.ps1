param(
    [int]$Count = 0
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Info  { Write-Host @args }
function Write-Ok   { Write-Host "OK: $($args -join ' ')" -ForegroundColor Green }
function Write-Warn { Write-Host "WARNING: $($args -join ' ')" -ForegroundColor Yellow }
function Write-Err  { Write-Host "ERROR: $($args -join ' ')" -ForegroundColor Red }
function Write-Step { Write-Host ">>> $($args -join ' ')" -ForegroundColor Cyan }

Write-Step "Check Docker service status"
$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker service is not running. Please start Docker Desktop first."
    exit 1
}
Write-Ok "Docker service is running"

Write-Step "Check Docker container mode"
$osType = docker info --format '{{.OSType}}' 2>&1
if ($osType -ne 'windows') {
    Write-Err "Current mode is Linux containers. Please switch to Windows containers:"
    Write-Err "  Right-click Docker icon in taskbar -> Switch to Windows containers..."
    Write-Err "  Or run: & 'C:\Program Files\Docker\Docker\DockerCli.exe' -SwitchDaemon"
    exit 1
}
Write-Ok "Docker container mode: Windows"

Write-Step "Check Windows base image"
$imageName = "mcr.microsoft.com/windows/servercore:ltsc2022"
$imageExists = docker images -q $imageName 2>$null
if (-not $imageExists) {
    Write-Warn "Image $imageName not found. Pulling (4-8GB, may take a while)..."
    docker pull $imageName
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to pull $imageName. Please pull manually:"
        Write-Err "  docker pull $imageName"
        exit 1
    }
    Write-Ok "$imageName pulled successfully"
} else {
    Write-Ok "$imageName already exists"
}

Write-Step "Check Docker network pam-net"
$networkName = "pam-net"
$networkExists = docker network ls -q -f "name=$networkName" 2>$null
if (-not $networkExists) {
    Write-Warn "Network pam-net not found. Creating..."
    docker network create $networkName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create pam-net network"
        exit 1
    }
    Write-Ok "pam-net network created"
} else {
    Write-Ok "pam-net network already exists"
}

Write-Step "Configure creation parameters"
if ($Count -le 0) {
    $inputCount = Read-Host "Enter number of Windows containers to create (default 1; recommended to start with 1 as Windows containers are slow to start)"
    if (-not $inputCount) { $inputCount = 1 }
    $Count = [int]$inputCount
}
Write-Info "Preparing to create $Count Windows container(s)" -ForegroundColor White
if ($Count -le 0 -or $Count -gt 5) {
    if ($Count -gt 5) {
        $confirm = Read-Host "Count exceeds 5. Windows containers are resource-intensive. Continue? (y/N)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Info "Cancelled" -ForegroundColor Yellow
            exit 0
        }
    } else {
        Write-Err "Count out of range (1-5). Please re-run."
        exit 1
    }
}

Write-Step "Start creating Windows containers"

$BASE_PORT = 5985
$ADMIN_PASSWORD = "123456"
$created = @()
$skipped = @()
$failed = @()

for ($i = 1; $i -le $Count; $i++) {
    $containerName = "windows-asset-$i"
    $hostPort = $BASE_PORT + $i - 1

    $existing = docker ps -a -q -f "name=^/${containerName}$" 2>$null
    if ($existing) {
        $status = docker inspect $existing --format '{{.State.Status}}' 2>$null
        Write-Warn "Container $containerName already exists (status: $status), skipping"
        $skipped += @{ Name = $containerName; Port = $hostPort; Status = $status }
        continue
    }

    Write-Info "Creating container $containerName (port mapping: $hostPort -> 5985)..." -ForegroundColor Yellow

    $runArgs = @(
        "run", "-d",
        "--name", $containerName,
        "--network", $networkName,
        "-p", "${hostPort}:5985",
        "-e", "ADMIN_PASSWORD=$ADMIN_PASSWORD",
        $imageName,
        "powershell", "-Command",
        "Start-Sleep -Seconds 3600"
    )

    $result = docker @runArgs 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Info "  Container $containerName created. Waiting for readiness..." -ForegroundColor Green

        $containerReady = $false
        $maxWait = 120
        for ($w = 0; $w -lt $maxWait; $w += 5) {
            $state = docker inspect $containerName --format '{{.State.Status}}' 2>$null
            if ($state -eq 'running') {
                $containerReady = $true
                Write-Ok "Container $containerName is now running"
                break
            }
            Write-Info "  Waiting for container to run... (${w}s / ${maxWait}s)" -ForegroundColor Gray
            Start-Sleep -Seconds 5
        }

        if (-not $containerReady) {
            Write-Warn "Container $containerName startup timed out (${maxWait}s)"
            Write-Info "  Container logs (last 10 lines):" -ForegroundColor Yellow
            docker logs $containerName --tail 10 2>&1
            $failed += @{ Name = $containerName; Port = $hostPort; Error = "Startup timeout" }
            continue
        }

        Write-Info "  Configuring WinRM service..." -ForegroundColor Yellow

        $winrmConfig = @'
net user pamadmin 123456 /add
net localgroup Administrators pamadmin /add
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985
Restart-Service WinRM
'@

        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($winrmConfig))
        $execResult = docker exec $containerName powershell -EncodedCommand $encodedCommand 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Container $containerName WinRM config may not be fully applied"
            Write-Info "  docker exec output: $execResult" -ForegroundColor Gray
        } else {
            Write-Ok "Container $containerName WinRM configured"
        }

        Write-Info "  Waiting for WinRM service readiness..." -ForegroundColor Yellow

        $winrmReady = $false
        $maxWinrmWait = 60
        for ($w = 0; $w -lt $maxWinrmWait; $w += 10) {
            $listener = docker exec $containerName powershell -Command "winrm enumerate winrm/config/listener" 2>&1
            if ($listener -match "Transport\s*=\s*HTTP" -and $listener -match "Port\s*=\s*5985") {
                $winrmReady = $true
                Write-Ok "Container $containerName WinRM listener ready (HTTP:5985)"
                break
            }
            Write-Info "  Waiting for WinRM listener... (${w}s / ${maxWinrmWait}s)" -ForegroundColor Gray
            Start-Sleep -Seconds 10
        }

        if (-not $winrmReady) {
            Write-Warn "Container $containerName WinRM readiness timed out (${maxWinrmWait}s)"
            Write-Info "  Manual check steps:" -ForegroundColor Yellow
            Write-Info "    docker exec $containerName powershell -Command `"winrm enumerate winrm/config/listener`"" -ForegroundColor Gray
            Write-Info "    docker exec $containerName powershell -Command `"Get-Service WinRM`"" -ForegroundColor Gray
        }

        $created += @{
            Name       = $containerName
            Port       = $hostPort
            Ready      = $containerReady
            WinrmReady = $winrmReady
        }
    } else {
        Write-Err "Container $containerName creation failed"
        Write-Info "  Error: $result" -ForegroundColor Red
        $failed += @{ Name = $containerName; Port = $hostPort; Error = $result }
    }
}

Write-Step "Creation summary"
Write-Host "======================================" -ForegroundColor Cyan

if ($created.Count -gt 0) {
    Write-Host "Successfully created containers:" -ForegroundColor Green
    foreach ($c in $created) {
        Write-Host ""
        Write-Host "  Name:       $($c.Name)" -ForegroundColor White
        Write-Host "  Port:       $($c.Port) -> 5985" -ForegroundColor White
        Write-Host "  Status:     $(if($c.Ready){'Running'}else{'Timeout (manual check required)'})" -ForegroundColor $(if($c.Ready){'Green'}else{'Yellow'})
        Write-Host "  WinRM:      $(if($c.WinrmReady){'Ready'}else{'Timeout (manual check required)'})" -ForegroundColor $(if($c.WinrmReady){'Green'}else{'Yellow'})
        Write-Host ""
        Write-Host "  Connection test:" -ForegroundColor Cyan
        Write-Host "    Test-NetConnection -ComputerName 127.0.0.1 -Port $($c.Port)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  WinRM direct test:" -ForegroundColor Cyan
        Write-Host "    `$password = ConvertTo-SecureString '123456' -AsPlainText -Force" -ForegroundColor Gray
        Write-Host "    `$cred = New-Object System.Management.Automation.PSCredential('pamadmin', `$password)" -ForegroundColor Gray
        Write-Host "    Test-WSMan -ComputerName 127.0.0.1 -Port $($c.Port) -Credential `$cred" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  PAM registration info:" -ForegroundColor Cyan
        Write-Host "    Type:       Windows" -ForegroundColor Cyan
        Write-Host "    Host:       127.0.0.1" -ForegroundColor Cyan
        Write-Host "    Port:       $($c.Port)" -ForegroundColor Cyan
        Write-Host "    Username:   pamadmin" -ForegroundColor Cyan
        Write-Host "    Password:   123456" -ForegroundColor Cyan
        Write-Host "    Acct Type:  local" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Web PowerShell access:" -ForegroundColor Cyan
        Write-Host "    PAM frontend -> Asset list -> Select Windows asset -> Click 'Web PowerShell'" -ForegroundColor Gray
    }
}

if ($skipped.Count -gt 0) {
    Write-Host ""
    Write-Host "Skipped (already exist):" -ForegroundColor Yellow
    foreach ($c in $skipped) {
        Write-Host "  $($c.Name) (port: $($c.Port), status: $($c.Status))" -ForegroundColor Yellow
    }
}

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed:" -ForegroundColor Red
    foreach ($c in $failed) {
        Write-Host "  $($c.Name) (port: $($c.Port))" -ForegroundColor Red
        Write-Host "  Error: $($c.Error)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Done!" -ForegroundColor Green
Write-Host "  Success: $($created.Count)" -ForegroundColor Green
Write-Host "  Skipped: $($skipped.Count)" -ForegroundColor Yellow
Write-Host "  Failed:  $($failed.Count)" -ForegroundColor $(if($failed.Count -gt 0){'Red'}else{'Green'})
Write-Host "======================================" -ForegroundColor Cyan

if ($created.Count -gt 0) {
    Write-Host ""
    Write-Host "Quick connectivity test (host verification):" -ForegroundColor Cyan
    Write-Host "  Test-NetConnection -ComputerName 127.0.0.1 -Port $($created[0].Port)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "PAM frontend guide:" -ForegroundColor Cyan
    Write-Host "  1. Log in to PAM frontend, go to Asset Management" -ForegroundColor Gray
    Write-Host "  2. Click Add Asset, select Windows type" -ForegroundColor Gray
    Write-Host "  3. Fill in: 127.0.0.1 + $($created[0].Port) + pamadmin + 123456 + local" -ForegroundColor Gray
    Write-Host "  4. After adding, click Connection Test to verify" -ForegroundColor Gray
    Write-Host "  5. Click Web PowerShell to open Windows terminal" -ForegroundColor Gray
    Write-Host "  6. Run whoami to confirm win-xxx\pamadmin" -ForegroundColor Gray
}

exit 0
