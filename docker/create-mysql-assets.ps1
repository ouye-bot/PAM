param(
    [int]$Count = 0
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Info  { Write-Host @args }
function Write-Ok   { Write-Host "OK: $($args -join ' ')" -ForegroundColor Green }
function Write-Warn { Write-Host "WARNING: $($args -join ' ')" -ForegroundColor Yellow }
function Write-Err  { Write-Host "ERROR: $($args -join ' ')" -ForegroundColor Red }
function Write-Step { Write-Host ">>> $($args -join ' ')" -ForegroundColor Cyan }

Write-Step "检查 Docker 服务状态"
$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker 服务未运行，请先启动 Docker Desktop"
    exit 1
}
Write-Ok "Docker 服务运行正常"

Write-Step "检查 mysql:8.0 镜像"
$imageExists = docker images -q mysql:8.0 2>$null
if (-not $imageExists) {
    Write-Warn "未找到 mysql:8.0 镜像，正在拉取..."
    docker pull mysql:8.0
    if ($LASTEXITCODE -ne 0) {
        Write-Err "拉取 mysql:8.0 镜像失败"
        exit 1
    }
    Write-Ok "mysql:8.0 镜像拉取完成"
} else {
    Write-Ok "mysql:8.0 镜像已存在"
}

Write-Step "检查 Docker 网络 pam-net"
$networkExists = docker network ls -q -f "name=pam-net" 2>$null
if (-not $networkExists) {
    Write-Warn "未找到 pam-net 网络，正在创建..."
    docker network create pam-net 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "创建 pam-net 网络失败"
        exit 1
    }
    Write-Ok "pam-net 网络创建成功"
} else {
    Write-Ok "pam-net 网络已存在"
}

Write-Step "配置创建参数"
if ($Count -le 0) {
    $inputCount = Read-Host "请输入要创建的 MySQL 容器数量（默认 3）"
    if (-not $inputCount) { $inputCount = 3 }
    $Count = [int]$inputCount
}
Write-Info "准备创建 $Count 个 MySQL 容器" -ForegroundColor White
if ($Count -le 0 -or $Count -gt 20) {
    Write-Err "数量超出合理范围（1-20），请重新运行"
    exit 1
}

Write-Step "开始创建 MySQL 容器"

$BASE_PORT = 3309
$MYSQL_ROOT_PASSWORD = "123456"
$created = @()
$skipped = @()
$failed = @()

for ($i = 1; $i -le $Count; $i++) {
    $containerName = "mysql-asset-$i"
    $hostPort = $BASE_PORT + $i - 1

    $existing = docker ps -a -q -f "name=^/${containerName}$" 2>$null
    if ($existing) {
        $status = docker inspect $existing --format '{{.State.Status}}' 2>$null
        Write-Warn "容器 $containerName 已存在（状态: $status），跳过创建"
        $skipped += @{ Name = $containerName; Port = $hostPort; Status = $status }
        continue
    }

    Write-Info "正在创建容器 $containerName（映射端口: $hostPort -> 3306）..." -ForegroundColor Yellow

    $runArgs = @(
        "run", "-d",
        "--name", $containerName,
        "--network", "pam-net",
        "-p", "${hostPort}:3306",
        "-e", "MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD",
        "-e", "MYSQL_ROOT_HOST=%",
        "mysql:8.0",
        "--default-authentication-plugin=mysql_native_password",
        "--character-set-server=utf8mb4",
        "--collation-server=utf8mb4_unicode_ci"
    )

    $result = docker @runArgs 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Info "  容器 $containerName 创建成功，正在等待 MySQL 就绪..." -ForegroundColor Green

        $ready = $false
        $maxWait = 60
        for ($w = 0; $w -lt $maxWait; $w++) {
            $logs = docker logs $containerName 2>&1
            if ($logs -match "ready for connections.*port: 3306") {
                $ready = $true
                break
            }
            Start-Sleep -Seconds 1
        }

        if ($ready) {
            Write-Ok "容器 $containerName 已就绪（MySQL 3306 端口已监听）"
        } else {
            Write-Warn "容器 $containerName 等待超时（${maxWait}s），请手动确认状态"
        }

        $created += @{
            Name  = $containerName
            Port  = $hostPort
            Ready = $ready
        }
    } else {
        Write-Err "容器 $containerName 创建失败"
        Write-Info "  错误信息: $result" -ForegroundColor Red
        $failed += @{ Name = $containerName; Port = $hostPort; Error = $result }
    }
}

Write-Step "创建结果汇总"
Write-Host "======================================" -ForegroundColor Cyan

if ($created.Count -gt 0) {
    Write-Host "以下容器创建成功：" -ForegroundColor Green
    foreach ($c in $created) {
        Write-Host ""
        Write-Host " 容器名称:   $($c.Name)" -ForegroundColor White
        Write-Host " 映射端口:   $($c.Port)" -ForegroundColor White
        Write-Host " 就绪状态:   $(if($c.Ready){'就绪'}else{'超时（请手动检查）'})" -ForegroundColor $(if($c.Ready){'Green'}else{'Yellow'})
        Write-Host ""
        Write-Host "  直连命令:   mysql -h 127.0.0.1 -P $($c.Port) -u root -p$MYSQL_ROOT_PASSWORD" -ForegroundColor Gray
        Write-Host "  密码明文:   $MYSQL_ROOT_PASSWORD" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  PAM 资产注册信息:" -ForegroundColor Cyan
        Write-Host "    资产类型:   MySQL" -ForegroundColor Cyan
        Write-Host "    主机:       127.0.0.1" -ForegroundColor Cyan
        Write-Host "    端口:       $($c.Port)" -ForegroundColor Cyan
        Write-Host "    用户名:     root" -ForegroundColor Cyan
        Write-Host "    密码:       $MYSQL_ROOT_PASSWORD" -ForegroundColor Cyan
    }
}

if ($skipped.Count -gt 0) {
    Write-Host ""
    Write-Host "以下容器已存在，已跳过：" -ForegroundColor Yellow
    foreach ($c in $skipped) {
        Write-Host "  $($c.Name)（端口: $($c.Port)，状态: $($c.Status)）" -ForegroundColor Yellow
    }
}

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "以下容器创建失败：" -ForegroundColor Red
    foreach ($c in $failed) {
        Write-Host "  $($c.Name)（端口: $($c.Port)）" -ForegroundColor Red
        Write-Host "  错误: $($c.Error)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "创建完成！" -ForegroundColor Green
Write-Host "  成功: $($created.Count) 个" -ForegroundColor Green
Write-Host "  跳过: $($skipped.Count) 个" -ForegroundColor Yellow
Write-Host "  失败: $($failed.Count) 个" -ForegroundColor $(if($failed.Count -gt 0){'Red'}else{'Green'})
Write-Host "======================================" -ForegroundColor Cyan

if ($created.Count -gt 0) {
    Write-Host ""
    Write-Host "快速测试连接（直连）：" -ForegroundColor Cyan
    Write-Host "  mysql -h 127.0.0.1 -P $($created[0].Port) -u root -p$MYSQL_ROOT_PASSWORD" -ForegroundColor Gray
    Write-Host ""
    Write-Host "PAM 前端操作指引：" -ForegroundColor Cyan
    Write-Host "  1. 登录 PAM 前端，进入「资产管理」" -ForegroundColor Gray
    Write-Host "  2. 点击「添加资产」，资产类型选择 MySQL" -ForegroundColor Gray
    Write-Host "  3. 填写上述注册信息（127.0.0.1 + 对应端口 + root + $MYSQL_ROOT_PASSWORD）" -ForegroundColor Gray
    Write-Host "  4. 添加后在操作栏点击「SQL测试」验证连通性" -ForegroundColor Gray
    Write-Host "  5. 点击「申请 Token」获取代理连接令牌" -ForegroundColor Gray
    Write-Host "  6. 在终端执行: mysql -h 127.0.0.1 -P 3307 -u root -p<Token> --default-auth=mysql_native_password" -ForegroundColor Gray
}

exit 0
