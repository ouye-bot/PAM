# PAM 系统启动脚本
# 用法: .\start.ps1 [backend|frontend|all]

param([string]$target = "all")

$ErrorActionPreference = "Stop"

# === 可配置变量 ===
$condaActivatePath = "D:\conda\Scripts\activate.bat"

function Check-Dependency {
    param($name, $command, $hint)
    Write-Host -NoNewline "  $name ... "
    try {
        Invoke-Expression "$command --version 2>&1 > `$null"
        Write-Host "OK" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "MISSING" -ForegroundColor Red
        Write-Host "    请安装 $hint" -ForegroundColor Yellow
        return $false
    }
}

function Start-Backend {
    Write-Host "`n=== 启动后端 ===" -ForegroundColor Cyan
    Set-Location "$PSScriptRoot\backend"

    # 检查 .env
    if (-not (Test-Path ".env")) {
        Write-Host "错误: .env 文件不存在，请从 .env.example 复制并配置" -ForegroundColor Red
        return
    }

    # 激活 conda（如果存在）
    if (Test-Path $condaActivatePath) {
        Write-Host "激活 conda 环境..."
        & $condaActivatePath
    }

    python app.py
}

function Start-Frontend {
    Write-Host "`n=== 启动前端 ===" -ForegroundColor Cyan
    Set-Location "$PSScriptRoot\frontend"

    if (-not (Test-Path "node_modules")) {
        Write-Host "正在安装依赖..." -ForegroundColor Yellow
        npm install
    }

    npm run dev
}

# === 主流程 ===
Write-Host "PAM 系统启动脚本" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green
Write-Host ""

# 环境检查
Write-Host "环境检查:" -ForegroundColor Cyan
Check-Dependency "Python" "python" "Python 3.10+ (https://www.python.org/)"
Check-Dependency "Node.js" "node" "Node.js 18+ (https://nodejs.org/)"

$mysqlOk = $false
try {
    mysqladmin ping -h localhost --silent 2>$null
    $mysqlOk = $true
    Write-Host "  MySQL ... OK" -ForegroundColor Green
} catch {
    Write-Host "  MySQL ... 未运行" -ForegroundColor Yellow
    Write-Host "    请确保 MySQL 8.0 已启动" -ForegroundColor Yellow
}

Write-Host ""

# 启动服务
switch ($target) {
    "backend"  { Start-Backend }
    "frontend" { Start-Frontend }
    "all" {
        Start-Backend
        Start-Frontend
    }
}
