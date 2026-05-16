# Fix running SSH containers to ensure auth.log exists and SSH logging works properly

$containers = @("asset-1", "asset-2", "asset-3")

foreach ($container in $containers) {
    Write-Host "Fixing container: $container"
    
    # Execute fix commands
    docker exec $container bash -c "touch /var/log/auth.log && chmod 666 /var/log/auth.log && sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/' /etc/ssh/sshd_config && sed -i 's/LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config && service ssh restart"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Container $container fixed successfully"
    } else {
        Write-Host "Failed to fix container $container"
    }
    
    Write-Host "------------------------"
}

Write-Host "All containers fixed"
