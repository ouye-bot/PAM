# Check Docker service status
Write-Host "Checking Docker service status..." -ForegroundColor Cyan
$dockerStatus = docker info 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker service is not running, please start Docker Desktop first" -ForegroundColor Red
    exit 1
}
Write-Host "OK: Docker service is running normally" -ForegroundColor Green

# Image name
$imageName = "ubuntu-ssh-target"

# Network name
$networkName = "pam-net"
$networkExists = docker network ls -q -f "name=$networkName"
if (-not $networkExists) {
    Write-Host "Creating Docker network $networkName ..." -ForegroundColor Yellow
    docker network create $networkName | Out-Null
}

# Ask for creation count
$count = Read-Host "Please enter the number of new containers to create (default 3)"
if (-not $count) { $count = 3 }
$count = [int]$count

# Create containers
$created = @()
for ($i = 1; $i -le $count; $i++) {
    $containerName = "asset-$i"
    $hostPort = 2220 + $i

    Write-Host "Creating container $containerName (mapping port: $hostPort)..." -ForegroundColor Yellow
    $cmd = "docker run -d --name $containerName --network $networkName -p ${hostPort}:22 $imageName"
    Write-Host "Executing command: $cmd"
    Invoke-Expression $cmd
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK: Container $containerName created successfully" -ForegroundColor Green
        $created += @{ Name = $containerName; Port = $hostPort }
    } else {
        Write-Host "ERROR: Container $containerName creation failed" -ForegroundColor Red
    }
}

# Output results
Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "SSH asset container creation completed!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan

if ($created.Count -eq 0) {
    Write-Host "WARNING: No new containers created" -ForegroundColor Yellow
} else {
    foreach ($c in $created) {
        Write-Host ""
        Write-Host "Container name: $($c.Name)" -ForegroundColor White
        Write-Host "Mapping port: $($c.Port)" -ForegroundColor White
        Write-Host "Connection command: ssh root@localhost -p $($c.Port)" -ForegroundColor Gray
        Write-Host "Password: 123456" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Test connection example: ssh root@localhost -p $($created[0].Port)" -ForegroundColor Cyan
}
Write-Host "======================================" -ForegroundColor Cyan