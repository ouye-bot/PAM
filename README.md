# PAM 特权账号管理系统

基于**中国国家密码标准（SM2/SM3/SM4）** 的特权账号管理平台，提供资产密码全生命周期管理、堡垒机代理、安全审计等能力。

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Python 3.10+ / Flask / Flask-SocketIO / APScheduler / PyMySQL / Paramiko |
| 前端 | Vue 3 / Element Plus / Xterm.js / Asciinema Player / ECharts |
| 数据库 | MySQL 8.0 |
| 国密算法 | SM2（签名/验签）、SM3（哈希链）、SM4-CBC（信封加密） |
| 代理协议 | SSH、WinRM、MySQL |

## 核心功能

- **三权分立**: 管理员(admin) / 运维(operator) / 审计(auditor) 三种角色，权限严格隔离
- **国密全栈**: SM2用户签名 → SM4凭证信封加密 → SM3审计哈希链，全生命周期国密覆盖
- **资产驱动**: 统一驱动抽象层，支持 SSH/Linux、MySQL、Windows 三种资产类型
- **三阶段改密**: PREPARE→APPLY→COMMIT，原子性保障 + 自动回滚 + 容灾恢复
- **堡垒机代理**: Web SSH / Web PowerShell / MySQL Proxy，全程录像 + SM4加密存储
- **绕行检测**: 检测非堡垒机登录 + 自动阻断 + 蜜罐账号（可选）
- **审计哈希链**: 每条日志包含前后哈希，SM3链式防篡改，一键验证完整性
- **密钥管理**: 主密钥热加载 + 工作密钥平滑轮换（多版本共存 + 渐进式迁移）

## 快速启动

### 1. 环境要求

- Python 3.10+
- Node.js 18+
- MySQL 8.0
- Windows 10+ / Linux

### 2. 配置环境变量

```bash
cd backend
cp .env.example .env
# 编辑 .env，填入数据库密码、生成 MASTER_KEY 和 JWT_SECRET
```

### 3. 初始化数据库

```bash
cd backend
pip install -r requirements.txt
python -c "from app import create_app; app=__import__('app').app; app.app_context().push(); from app.models import *; db.create_all()"
python init_master_key.py  # 可选：将主密钥存入系统密钥链
```

### 4. 启动后端

```bash
cd backend
python app.py
# 服务启动在 http://localhost:5000
```

### 5. 启动前端

```bash
cd frontend
npm install
npm run dev
# 服务启动在 http://localhost:5173
```

### 6. 登录

- 地址: `http://localhost:5173`
- 默认账户: `admin` / `admin123`
- 首次登录后自动配置 SM2 密钥对

## 系统架构

```
┌─────────────────────────────────────────────────────┐
│                    前端 (Vue 3)                      │
│  Login │ Dashboard │ Assets │ Sessions │ Audit │ ... │
└────────────────────────┬────────────────────────────┘
                         │ HTTP REST + Socket.IO
┌────────────────────────┴────────────────────────────┐
│                 后端 (Flask)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ REST API │ │Socket.IO │ │    APScheduler       │ │
│  │ assets   │ │ SSH/WS   │ │  rotation/detect/    │ │
│  │ auth     │ │ WinRM    │ │  progressive_reenc   │ │
│  │ audit    │ │ recording│ │  risk_score           │ │
│  │ keys     │ │          │ │                      │ │
│  └────┬─────┘ └────┬─────┘ └──────────┬───────────┘ │
│       │            │                  │              │
│  ┌────┴────────────┴──────────────────┴───────────┐ │
│  │              Drivers (资产驱动抽象层)           │ │
│  │  SSHDriver │ MySQLDriver │ WindowsDriver       │ │
│  └────────────────────┬───────────────────────────┘ │
│                       │                              │
│  ┌────────────────────┴───────────────────────────┐ │
│  │           CryptoService (国密服务)              │ │
│  │  SM2签名验签 │ SM3哈希 │ SM4-CBC加解密         │ │
│  └────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────┐
│              MySQL 8.0 (数据库)                      │
│  users │ assets │ credentials │ audit_logs │ ...     │
└─────────────────────────────────────────────────────┘
```

## 国密算法使用

| 算法 | 使用场景 | 模式 |
|------|----------|------|
| SM2 | 用户登录签名验证、高危命令不可抵赖签名 | 签名/验签 |
| SM3 | 审计日志哈希链、密码历史哈希 | 哈希 |
| SM4 | 凭证密码加密、工作密钥加密、录像文件加密 | CBC模式 |

## 许可证

内部项目 - 仅供竞赛演示和教学用途
