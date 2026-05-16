# P6 功能打磨批次设计文档

> 日期: 2026-05-16 | 状态: 待审批 | 总计: 7项任务

---

## 概述

P6 批次聚焦业务逻辑完善和密码学规范修正，分两个 Phase 执行：

- **Phase 1 — P5-C 业务逻辑完善（5项）**: 弱密码统计、合规分页、健康检查增强、Redis 限流、调度器优雅关闭
- **Phase 2 — P5-D 密码技术修正（2项）**: 零IV回退移除、HMAC 标准构造

**决策记录：**
- D3（密码历史加盐）已跳过 — SM4 加密已足够保护，回滚能力不可妥协
- SM2 引导流程不实施 — 静默生成+自动签名是正确的零摩擦体验

---

## Phase 1: P5-C 业务逻辑完善

### C1: 弱密码统计

**现状**: `dashboard.py` 中 `weak_password_assets` 硬编码为 0。

**方案**: 在 `get_dashboard_stats()` 中添加真实查询逻辑：
1. 查询所有活跃资产的最新凭据密码（SM4 解密后）
2. 弱密码判定规则：长度 < 8、纯数字、纯字母、常见弱密码字典（top 100）
3. 返回弱密码资产计数

**改动文件**:
- `backend/app/api/dashboard.py` — 添加弱密码检测函数，替换硬编码 0

**注意**: 需要解密密码进行检查，仅在 dashboard 统计时执行，不做持久化存储。

### C2: 合规报告分页

**现状**: `compliance.py` 的 `GET /api/compliance/report` 一次性返回完整报告，无分页。

**方案**:
1. 后端支持 `?page=1&size=10` 查询参数，对5项检查结果列表分页
2. 响应增加 `total`、`page`、`size` 分页元数据
3. 前端 `ComplianceReport.vue` 添加 ElPagination 分页组件

**改动文件**:
- `backend/app/api/compliance.py` — 添加分页参数处理
- `frontend/src/components/ComplianceReport.vue` — 添加分页组件

### C3: 健康检查增强

**现状**: `/api/health` 仅检查 DB/主密钥/工作密钥，无超时保护。

**方案**: 增加以下检查项，每项设置 3 秒超时：
1. **Redis 连接** — `redis.ping()`，不可用时标记 `degraded` 而非 `down`
2. **调度器状态** — `scheduler.running` 布尔值
3. **录制目录可写性** — 检查 `recordings/` 目录存在且可写

**改动文件**:
- `backend/app.py` — 扩展 `/api/health` 端点

### C4: Redis 限流后端

**现状**: `rate_limiter.py` 纯内存限流，重启丢失，多实例不共享。

**方案**: 添加 Redis 后端，保持内存回退：
1. 限流计数优先写入 Redis（`INCR` + `EXPIRE` 实现滑动窗口）
2. Redis 不可用时自动回退内存模式（现有逻辑不变）
3. 复用 `app.py` 中已有的 Redis 连接（`flask-socketio` 的 `message_queue` 连接）
4. 策略配置不变（login 10/min, sensitive 10/min, normal 120/min, global_ip 300/min）

**改动文件**:
- `backend/app/utils/rate_limiter.py` — 添加 Redis 后端，保留内存回退

**关键设计**: Redis 键格式 `pam:ratelimit:{bucket}:{identifier}`，TTL 与窗口大小一致。

### C5: 调度器优雅关闭

**现状**: `app.py` 无 shutdown hook，APScheduler 任务可能在进程退出时中断。

**方案**:
1. 注册 Flask `atexit` 处理函数
2. 调用 `scheduler.shutdown(wait=True)` 等待正在执行的任务完成
3. 添加 10 秒超时保护，超时后强制退出
4. 关闭 Redis 连接（如已初始化）

**改动文件**:
- `backend/app.py` — 添加 shutdown hook
- `backend/app/scheduler.py` — 暴露 `shutdown_scheduler()` 函数

---

## Phase 2: P5-D 密码技术修正

### D1: 零IV回退移除

**现状**: `crypto_service.py` 中两处零IV回退代码：
- `sm4_decrypt()` lines 224-237 — `UnicodeDecodeError` 时用 `iv = b'\x00' * 16` 重试
- `decrypt_with_work_key()` lines 372-385 — 同样的回退逻辑

**前置条件**: 确认所有旧数据已通过 P4-T4 全量重加密迁移。如果仍有未迁移数据，先执行一次全量重加密。

**方案**:
1. 运行一次全量重加密（确保无遗留旧格式数据）
2. 删除 `sm4_decrypt()` 中的零IV回退代码块
3. 删除 `decrypt_with_work_key()` 中的零IV回退代码块
4. 标准解密失败直接抛出异常，不再静默回退

**改动文件**:
- `backend/app/services/crypto_service.py` — 删除约 20 行回退代码

### D2: HMAC 标准构造

**现状**: SM4-HMAC 使用 `SM3(key + ciphertext)`，非标准构造。密钥直接参与哈希，无独立 HMAC 子密钥。

**方案**: 改为标准 encrypt-then-MAC：
1. 从工作密钥派生独立的 HMAC 子密钥：`hmac_key = SM3(work_key + "hmac-derive")`
2. HMAC 计算改为：`SM3(hmac_key || iv || ciphertext)`
3. 解密时先验证 HMAC，再解密（当前已是此顺序）
4. 添加格式版本标记：新格式在密文头部增加 `0x02` 版本字节（旧格式无版本字节或 `0x01`）
5. 解密时根据版本字节选择 HMAC 验证逻辑，确保过渡期兼容

**改动文件**:
- `backend/app/services/crypto_service.py` — 修改 `sm4_encrypt`/`sm4_decrypt`，添加版本标记

**过渡策略**: 新加密使用 v2 格式，解密同时支持 v1（旧）和 v2（新）。后续版本可移除 v1 支持。

---

## 不实施项（决策记录）

| 项目 | 原因 |
|------|------|
| D3 密码历史加盐 | SM4 加密已足够保护；回滚依赖明文，加盐后回滚断裂；收益有限 |
| SM2 引导流程 | 静默生成+自动签名是正确的零摩擦体验；Profile 已有管理入口 |

---

## 验收标准

- [ ] Dashboard 弱密码统计显示真实数据（非硬编码 0）
- [ ] 合规报告支持分页，前端有分页控件
- [ ] `/api/health` 返回 Redis/调度器/录制目录状态
- [ ] 限流器在 Redis 可用时使用 Redis，不可用时回退内存
- [ ] 后端进程退出时调度器优雅关闭
- [ ] 零IV回退代码已移除，解密失败直接抛异常
- [ ] SM4-HMAC 使用标准 encrypt-then-MAC 构造，带版本标记
