# PAM System Optimization Phase 4 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 8 security and architecture hardening tasks: API rate limiting, audit log immutability, SM2 deterministic k, SM4 full re-encryption, shared recording service, WebSocket Redis persistence, password view re-auth, and batch asset operations.

**Architecture:** Three independent Phase-1 tasks (T1/T2/T3) executed first. T4 depends on T1 stability. T5 refactors recording after crypto stack stabilizes. T6 adds Redis after T5. T7/T8 run in parallel after T6. Each task is self-contained with no cross-task code coupling.

**Tech Stack:** Python 3.13 / Flask / Flask-SocketIO / gmssl / PyMySQL / Redis (new) / Vue 3

---

## File Structure Map

```
backend/
├── app.py                          # [MOD] SocketIO Redis config, rate limiter init
├── app/
│   ├── __init__.py                 # [MOD] __version__ stays
│   ├── api/
│   │   ├── asset.py                # [MOD] T7 re-auth guard, T8 batch endpoints
│   │   ├── auth.py                 # [MOD] T1 remove scattered check_rate_limit
│   │   ├── audit.py                # [MOD] T2 lock/unlock endpoints
│   │   └── key_management.py       # [MOD] T4 synchronous re-encrypt rotate endpoint
│   ├── models/
│   │   └── audit_log.py            # [MOD] T2 is_locked column
│   ├── routes/
│   │   ├── ssh.py                  # [MOD] T5 delegate to recording_service
│   │   └── winrm.py                # [MOD] T5 delegate to recording_service
│   ├── services/
│   │   ├── audit_service.py        # [MOD] T2 lock/unlock/guard logic
│   │   ├── crypto_service.py       # [MOD] T3 deterministic k, T4 re_encrypt_all
│   │   └── recording_service.py    # [NEW] T5 shared recording logic
│   ├── utils/
│   │   ├── rate_limiter.py         # [MOD] T1 extend with multi-strategy
│   │   └── rate_limit_middleware.py # [NEW] T1 before_request hook
│   └── scheduler.py                # [MOD] T4 pause/resume rotation during re-encrypt
├── requirements.txt                # [MOD] T6 add redis
├── migrations/
│   └── 001_add_audit_log_is_locked.sql  # [NEW] T2 DDL
docker/
└── docker-compose.yml              # [MOD] T6 add redis service
frontend/src/
└── components/
    └── AssetList.vue               # [MOD] T7 re-auth dialog, T8 multi-select+batch
```

---

## Migration SQL

Before any code changes, run this one-time DDL for T2:

```sql
-- migrations/001_add_audit_log_is_locked.sql
ALTER TABLE pam_db.audit_logs ADD COLUMN is_locked TINYINT(1) NOT NULL DEFAULT 0;
```

---

### Task 1: API Global Rate Limiting

**Files:**
- Modify: `backend/app/utils/rate_limiter.py:1-92`
- Create: `backend/app/utils/rate_limit_middleware.py`
- Modify: `backend/app.py:242-244`
- Modify: `backend/app/api/auth.py:12,94-97`

- [ ] **Step 1: Extend rate_limiter.py with strategy registry**

Add strategy configuration and a `check_request_limit` function below the existing `check_rate_limit` function in `backend/app/utils/rate_limiter.py`:

```python
# Add after line 91 (after start_cleanup_thread)

# === T1: Multi-strategy rate limit configuration ===

# Thresholds: tuned for single-machine dev/PoC, not production
STRATEGIES = {
    'login':       {'max': 60,  'window': 60},    # 60 req/min per IP
    'sensitive':   {'max': 20,  'window': 60},    # 20 req/min per user
    'normal':      {'max': 120, 'window': 60},    # 120 req/min per user
    'global_ip':   {'max': 300, 'window': 60},    # 300 req/min per IP (catch-all)
}

SENSITIVE_PREFIXES = (
    '/api/keys/rotate',
    '/api/assets/discover',
    '/api/assets/purge',
    '/api/auth/verify-password',
)

LOGIN_ONLY_PREFIXES = (
    '/api/auth/login',
)

def classify_request(path, has_user):
    """Classify a request into a strategy bucket."""
    if path.startswith(LOGIN_ONLY_PREFIXES):
        return 'login'
    if path.startswith(SENSITIVE_PREFIXES):
        return 'sensitive' if has_user else 'global_ip'
    return 'normal' if has_user else 'global_ip'

def check_request_limit(path, user_id, client_ip):
    """
    Check rate limit for a request. Returns (allowed: bool, retry_after: int|None).
    user_id=None means unauthenticated request.
    """
    has_user = user_id is not None
    strategy = classify_request(path, has_user)
    cfg = STRATEGIES[strategy]

    if has_user:
        key_type = f"rl_{strategy}"
        key_value = str(user_id)
    else:
        key_type = "rl_ip"
        key_value = client_ip

    allowed = check_rate_limit(key_type, key_value, cfg['max'], cfg['window'], lock_seconds=cfg['window'] * 2)
    if not allowed:
        remaining = get_lock_remaining(key_type, key_value)
        return False, remaining
    return True, None
```

- [ ] **Step 2: Create rate_limit_middleware.py**

Create `backend/app/utils/rate_limit_middleware.py`:

```python
from flask import request, jsonify
from app.utils.rate_limiter import check_request_limit
from app.utils.logger import get_logger

logger = get_logger('app.utils.rate_limit_middleware')

EXCLUDED_PATHS = ('/api/health', '/', '/socket.io')

def init_rate_limit_middleware(app):
    """Register before_request hook for global rate limiting."""

    @app.before_request
    def _rate_limit_check():
        path = request.path
        if path.startswith(EXCLUDED_PATHS):
            return None

        client_ip = request.remote_addr or '127.0.0.1'
        user_id = getattr(request, 'user_id', None)

        allowed, retry_after = check_request_limit(path, user_id, client_ip)
        if not allowed:
            logger.warning("Rate limit hit: path=%s, user=%s, ip=%s", path, user_id, client_ip)
            resp = jsonify({'code': 429, 'message': '请求过于频繁，请稍后再试'})
            resp.headers['Retry-After'] = str(retry_after)
            return resp, 429
        return None
```

- [ ] **Step 3: Wire middleware into app.py**

In `backend/app.py:242-244`, replace the existing rate limiter cleanup init section with:

```python
    # 初始化全局速率限制器
    from app.utils.rate_limiter import start_cleanup_thread
    start_cleanup_thread(interval=300)
    from app.utils.rate_limit_middleware import init_rate_limit_middleware
    init_rate_limit_middleware(app)
    logger.info("[APP] Global rate limiter initialized")
```

- [ ] **Step 4: Remove scattered check_rate_limit calls from auth.py**

In `backend/app/api/auth.py`, remove line 12:
```python
# DELETE: from app.utils.rate_limiter import check_rate_limit, clear_rate_limit, get_lock_remaining
# REPLACE with:
from app.utils.rate_limiter import clear_rate_limit
```

In `backend/app/api/auth.py:94-97`, change the login failed block:

```python
# OLD (lines 94-97):
    if not user or not verify_password(password, user.password):
        check_rate_limit('ip', client_ip, max_attempts=10, window_seconds=300, lock_seconds=900)
        if user:
            check_rate_limit('username', username, max_attempts=5, window_seconds=300, lock_seconds=900)
        return jsonify({'code': 401, 'message': '用户名或密码错误'}), 401

# NEW:
    if not user or not verify_password(password, user.password):
        # Rate limiting for failed logins is now handled globally by rate_limit_middleware
        return jsonify({'code': 401, 'message': '用户名或密码错误'}), 401
```

Also update lines 100-101 to remove clear_rate_limit calls (they only clear the old key type; the global limiter auto-expires):

```python
# OLD (lines 100-101):
    clear_rate_limit('ip', client_ip)
    clear_rate_limit('username', username)

# NEW:
    # Global rate limiter auto-expires; no explicit clear needed
```

- [ ] **Step 5: Restart backend and verify**

Run:
```bash
cd D:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python app.py
```

Test: Rapid-fire curl to `/api/auth/login` should return 429 after 60 requests in one minute.
Test: Normal browsing of asset list should not trigger any limits.

- [ ] **Step 6: Commit**

```bash
git add backend/app/utils/rate_limiter.py backend/app/utils/rate_limit_middleware.py backend/app.py backend/app/api/auth.py
git commit -m "feat: add API global rate limiting with multi-strategy thresholds"
```

---

### Task 2: Audit Log Immutability Locking

**Files:**
- Modify: `backend/app/models/audit_log.py:4-17`
- Modify: `backend/app/services/audit_service.py:1-75`
- Modify: `backend/app/api/audit.py` (partial — add lock/unlock routes)
- Modify: `backend/app.py:192-236` (startup hash chain rebuild)
- Create: `backend/migrations/001_add_audit_log_is_locked.sql`

- [ ] **Step 1: Run migration SQL**

```bash
python -c "import pymysql; c=pymysql.connect(host='localhost',user='root',password='123456',database='pam_db'); c.cursor().execute('ALTER TABLE audit_logs ADD COLUMN is_locked TINYINT(1) NOT NULL DEFAULT 0'); c.commit(); c.close(); print('Migration complete')"
```

- [ ] **Step 2: Add is_locked to AuditLog model**

In `backend/app/models/audit_log.py`, add after line 17 (`is_deleted`):

```python
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
```

- [ ] **Step 3: Add lock/unlock functions to audit_service.py**

Append to `backend/app/services/audit_service.py`:

```python
def lock_audit_logs(start_id, end_id, operator='system'):
    """
    Lock audit logs in the given ID range.
    Locked logs cannot be soft-deleted, restored, or have operation_detail modified.
    Does NOT modify hashes — the hash chain remains intact.
    """
    from app.models import AuditLog
    updated = AuditLog.query.filter(
        AuditLog.id >= start_id,
        AuditLog.id <= end_id,
        AuditLog.is_locked == False
    ).update({'is_locked': True}, synchronize_session=False)
    db.session.commit()
    return updated


def unlock_audit_logs(start_id, end_id, operator='system'):
    """Unlock audit logs (admin only)."""
    from app.models import AuditLog
    updated = AuditLog.query.filter(
        AuditLog.id >= start_id,
        AuditLog.id <= end_id,
        AuditLog.is_locked == True
    ).update({'is_locked': False}, synchronize_session=False)
    db.session.commit()
    return updated


def auto_lock_old_logs(retention_days=30):
    """Lock all unlocked logs older than retention_days. Called by scheduler."""
    from datetime import datetime, timedelta
    from app.models import AuditLog
    cutoff = datetime.now() - timedelta(days=retention_days)
    updated = AuditLog.query.filter(
        AuditLog.timestamp <= cutoff,
        AuditLog.is_locked == False
    ).update({'is_locked': True}, synchronize_session=False)
    db.session.commit()
    return updated
```

- [ ] **Step 4: Guard soft-delete and operation_detail modifications**

In `backend/app/services/audit_service.py`, the `write_audit_log` function does not modify existing logs, so no change needed there. The guards need to be in the API layer and any service that does soft-delete. Let me check what soft-deletes exist...

The audit.py API handles soft-delete. We'll add a guard there in Step 5. For `write_audit_log`, add a docstring note but no code change — it only creates new logs.

- [ ] **Step 5: Add lock/unlock API routes to audit.py**

Read the existing `backend/app/api/audit.py` to find where routes are defined, then add these two routes:

```python
@audit_bp.route('/lock', methods=['POST'])
@token_required
@role_required('admin', 'auditor')
def lock_audit_logs():
    """Lock audit logs in a range (auditor/admin). Locked logs become immutable."""
    data = request.get_json()
    start_id = data.get('start_id')
    end_id = data.get('end_id')
    if not start_id or not end_id:
        return jsonify({'code': 400, 'message': 'start_id and end_id are required'}), 400
    count = lock_audit_logs(int(start_id), int(end_id), operator=request.username)
    write_audit_log('audit_lock', operator=request.username,
                    source_ip=request.remote_addr or '127.0.0.1',
                    target_asset='system',
                    operation_detail=f'Locked {count} audit logs (IDs {start_id}-{end_id})',
                    result='success')
    return jsonify({'code': 200, 'message': f'{count} audit logs locked', 'data': {'locked_count': count}})


@audit_bp.route('/unlock', methods=['POST'])
@token_required
@role_required('admin')
def unlock_audit_logs():
    """Unlock audit logs (admin only)."""
    data = request.get_json()
    start_id = data.get('start_id')
    end_id = data.get('end_id')
    if not start_id or not end_id:
        return jsonify({'code': 400, 'message': 'start_id and end_id are required'}), 400
    count = unlock_audit_logs(int(start_id), int(end_id), operator=request.username)
    write_audit_log('audit_unlock', operator=request.username,
                    source_ip=request.remote_addr or '127.0.0.1',
                    target_asset='system',
                    operation_detail=f'Unlocked {count} audit logs (IDs {start_id}-{end_id})',
                    result='success')
    return jsonify({'code': 200, 'message': f'{count} audit logs unlocked', 'data': {'unlocked_count': count}})
```

Also add a check in the existing soft-delete route — if the log is locked, reject with 403. Find the soft-delete function in audit.py and add at the top:

```python
# Inside the soft-delete route handler, after finding the audit log:
if audit_log.is_locked:
    return jsonify({'code': 403, 'message': '该审计日志已被锁定，无法删除'}), 403
```

- [ ] **Step 6: Update startup hash chain rebuild in app.py to skip when locked logs exist**

In `backend/app.py:192-236`, add a lock-check guard before the rebuild loop:

```python
    # 重建审计日志哈希链
    with app.app_context():
        from app.models import AuditLog
        from app.services.crypto_service import CryptoService

        locked_count = AuditLog.query.filter_by(is_locked=True).count()
        if locked_count > 0:
            logger.info("=== 哈希链重建跳过: 存在 %d 条已锁定日志，链已永久冻结 ===", locked_count)
        else:
            logger.info("=== 开始重建审计日志哈希链 ===")

            logs = AuditLog.query.order_by(AuditLog.id).all()
            if logs:
                # ... existing rebuild logic unchanged ...
                logger.info("=== 哈希链重建完成 ===")
                logger.info("成功更新 %d 条审计日志", updated_count)
            else:
                logger.info("没有审计日志需要处理")
```

- [ ] **Step 7: Update rebuild_hash_chain in audit_service.py — refuse if locked logs exist**

In `backend/app/services/audit_service.py:53-75`, replace `rebuild_hash_chain()`:

```python
def rebuild_hash_chain():
    """重建全部审计日志哈希链。
    如果存在已锁定的日志，拒绝重建——锁定意味着链已永久冻结。
    仅在没有锁定日志时才能安全重建。
    """
    from app.services.crypto_service import CryptoService

    locked_count = AuditLog.query.filter_by(is_locked=True).count()
    if locked_count > 0:
        logger.warning("[HASH-REBUILD] Refusing to rebuild: %d locked logs exist. "
                       "Locked logs have frozen hashes that cannot be rebuilt.", locked_count)
        return -1  # signal: cannot rebuild

    logs = AuditLog.query.order_by(AuditLog.id).all()
    if not logs:
        return 0

    previous_hash = ''
    updated = 0
    for log in logs:
        is_deleted_val = 1 if log.is_deleted else 0
        data_to_hash = (
            f"{log.log_type}|{log.operator}|{log.source_ip}|"
            f"{log.target_asset}|{log.operation_detail}|{log.result}|"
            f"{log.timestamp}|{previous_hash}|{is_deleted_val}"
        )
        log.previous_hash = previous_hash
        log.current_hash = CryptoService.sm3_hash(data_to_hash)
        previous_hash = log.current_hash
        updated += 1

    db.session.commit()
    return updated
```

- [ ] **Step 8: Register auto-lock job in scheduler**

In `backend/app/scheduler.py`, inside `init_scheduler()`, add after the other job registrations:

```python
    # 审计日志自动锁定（每日凌晨3点，锁定30天前的日志）
    scheduler.add_job(
        id='auto_lock_audit_logs',
        func=auto_lock_old_logs,
        trigger='cron',
        hour=3,
        minute=0
    )
```

Also add the import at the top of scheduler.py:
```python
from app.services.audit_service import auto_lock_old_logs
```

- [ ] **Step 9: Restart backend and verify**

Run:
```bash
cd D:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python app.py
```

Test: Lock some logs via `POST /api/audit/lock {"start_id": 1, "end_id": 10}`.
Test: Verify hash chain integrity via `GET /api/audit/verify`.
Test: Attempt to soft-delete a locked log — should return 403.

- [ ] **Step 10: Commit**

```bash
git add backend/migrations/001_add_audit_log_is_locked.sql backend/app/models/audit_log.py backend/app/services/audit_service.py backend/app/api/audit.py backend/app.py backend/app/scheduler.py
git commit -m "feat: add audit log immutability locking (manual + auto 30-day)"
```

---

### Task 3: SM2 Deterministic k Signature (RFC 6979)

**Files:**
- Modify: `backend/app/services/crypto_service.py:453-463`

- [ ] **Step 1: Implement deterministic k in sm2_sign**

Replace the existing `sm2_sign` function in `backend/app/services/crypto_service.py:453-463`:

```python
def _sm2_deterministic_k(private_key_hex: str, message_hash_hex: str, n_hex: str) -> str:
    """
    Derive a deterministic k value for SM2 signing per RFC 6979 concept.
    Uses iterative SM3 over (private_key || message_hash || counter) as the entropy source.
    Loops until k is in the valid range [1, n-1].
    """
    from gmssl.sm3 import sm3_hash as _sm3
    n = int(n_hex, 16)
    seed = (private_key_hex + message_hash_hex).encode()
    extra = 0
    while True:
        k_input = seed + extra.to_bytes(4, 'big')
        k_hex = _sm3(list(k_input))
        k = int(k_hex, 16) % n
        if 1 <= k <= n - 1:
            return hex(k)[2:].zfill(64)
        extra += 1


def sm2_sign(data: str) -> str:
    from gmssl import sm2

    private_key = get_sm2_private_key()
    if not private_key:
        raise ValueError("SM2 私钥未配置")

    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")

    # Compute SM3 hash of the message
    msg_hash = CryptoService.sm3_hash(data)

    # Derive deterministic k from private key + message hash
    n_hex = sm2_crypt.ecc_table['n']
    deterministic_k = _sm2_deterministic_k(private_key, msg_hash, n_hex)

    signature_hex = sm2_crypt.sign(data.encode(), deterministic_k)
    return base64.b64encode(signature_hex.encode()).decode()
```

- [ ] **Step 2: Verify — same message produces same signature**

Run in Python:
```python
sig1 = sm2_sign("test message")
sig2 = sm2_sign("test message")
assert sig1 == sig2, "Deterministic k should produce identical signatures for identical messages"
print("Deterministic k verified: same message → same signature")
```

- [ ] **Step 3: Verify — existing signature verification still works**

```python
# Sign a test message
test_msg = "det-k-test-2026"
sig = sm2_sign(test_msg)
# Verify it
assert sm2_verify(test_msg, sig), "Self-verification failed"
# Verify via public key API
pubkey = get_sm2_public_key()
assert CryptoService.sm2_verify_with_public_key(test_msg, sig, base64.b64encode(bytes.fromhex(pubkey)).decode()), "Public key verification failed"
print("Verification compatibility confirmed")
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/services/crypto_service.py
git commit -m "feat: implement SM2 deterministic k signing per RFC 6979 concept"
```

---

### Task 4: SM4 Key Rotation Full Re-encryption

**Files:**
- Modify: `backend/app/services/crypto_service.py` — add `re_encrypt_all_credentials()`
- Modify: `backend/app/api/key_management.py:69-138` — rewrite `/rotate` endpoint
- Modify: `backend/app/scheduler.py` — add pause/resume helpers

- [ ] **Step 1: Add re_encrypt_all_credentials to crypto_service.py**

Append to `backend/app/services/crypto_service.py`:

```python
@staticmethod
def re_encrypt_all_credentials(old_key_id, new_key_id, old_work_key, new_work_key):
    """
    Synchronously re-encrypt ALL credential data from old_key to new_key.
    Covers: credentials.encrypted_password, credentials.pending_password,
            credentials.previous_passwords, and any recording DEKs.

    Returns: (migrated: int, failed: int, errors: list)
    On any failure, partial results are committed per-batch — old key stays active.
    Caller is responsible for rollback decision.
    """
    from app import db
    from app.models import Credential
    import json

    errors = []
    migrated = 0
    failed = 0
    batch_size = 50

    # 1. Credential passwords (encrypted_password + pending_password)
    total = Credential.query.count()
    offset = 0
    while offset < total:
        batch = Credential.query.order_by(Credential.id).offset(offset).limit(batch_size).all()
        if not batch:
            break
        for cred in batch:
            try:
                # Re-encrypt encrypted_password
                if cred.key_version == old_key_id:
                    password = CryptoService.decrypt_with_work_key(cred.encrypted_password, old_work_key)
                    if password is None:
                        raise ValueError(f"Decrypt failed for cred {cred.id}")
                    cred.encrypted_password = CryptoService.encrypt_with_work_key(password, new_work_key)
                    cred.key_version = new_key_id

                # Re-encrypt pending_password
                if cred.pending_password and cred.pending_key_version == old_key_id:
                    pending = CryptoService.decrypt_with_work_key(cred.pending_password, old_work_key)
                    if pending is not None:
                        cred.pending_password = CryptoService.encrypt_with_work_key(pending, new_work_key)
                        cred.pending_key_version = new_key_id

                # Re-encrypt previous_passwords JSON
                if cred.previous_passwords and cred.previous_passwords != '[]':
                    try:
                        prev_list = json.loads(cred.previous_passwords)
                        re_encrypted = False
                        for entry in prev_list:
                            if entry.get('key_version') == old_key_id:
                                old_pwd = CryptoService.decrypt_with_work_key(entry['encrypted_password'], old_work_key)
                                if old_pwd is not None:
                                    entry['encrypted_password'] = CryptoService.encrypt_with_work_key(old_pwd, new_work_key)
                                    entry['key_version'] = new_key_id
                                    re_encrypted = True
                        if re_encrypted:
                            cred.previous_passwords = json.dumps(prev_list, ensure_ascii=False)
                    except (json.JSONDecodeError, KeyError):
                        pass  # malformed JSON — skip, not critical

                migrated += 1
            except Exception as e:
                failed += 1
                errors.append(f"cred_id={cred.id}: {str(e)}")

        db.session.commit()
        offset += batch_size

    return migrated, failed, errors
```

- [ ] **Step 2: Rewrite /api/keys/rotate endpoint for synchronous re-encryption**

Replace the existing `rotate_key()` function in `backend/app/api/key_management.py:69-138`:

```python
@key_bp.route('/rotate', methods=['POST'])
@token_required
@role_required('admin')
def rotate_key():
    """
    Synchronous key rotation with full re-encryption.
    1. Create new key (rotating)
    2. Pause scheduler rotation jobs
    3. Re-encrypt ALL credentials synchronously
    4. On success: old key → retired, new key → active
    5. On failure: old key → active, new key → retired (data still decryptable)
    6. Resume scheduler
    """
    from app import db
    from app.models import KeyVersion, Credential
    from app.scheduler import pause_rotation_jobs, resume_rotation_jobs

    try:
        # Check for existing rotation
        existing_rotating = KeyVersion.query.filter_by(status='rotating').first()
        if existing_rotating:
            return jsonify({
                'code': 409,
                'message': f'已有正在进行的密钥轮换 (密钥ID: {existing_rotating.id})'
            }), 409

        # 1. Create new key
        old_key = KeyVersion.query.filter_by(status='active').first()
        new_work_key = CryptoService.generate_work_key()
        encrypted_new_key = CryptoService.encrypt_work_key(new_work_key)

        new_key_version = KeyVersion(
            encrypted_key=encrypted_new_key,
            status='rotating'
        )
        db.session.add(new_key_version)
        db.session.flush()
        new_key_id = new_key_version.id
        old_key_id = old_key.id if old_key else None
        db.session.commit()

        # 2. Pause scheduler rotation jobs
        pause_rotation_jobs()
        logger.info("[KEY-ROTATION] Scheduler rotation jobs paused")

        total_creds = Credential.query.count()

        try:
            # 3. Full re-encryption
            old_work_key = CryptoService.decrypt_work_key(old_key.encrypted_key)
            if old_work_key is None:
                raise RuntimeError("Cannot decrypt old work key — master key may have changed")

            migrated, failed, errors = CryptoService.re_encrypt_all_credentials(
                old_key_id, new_key_id, old_work_key, new_work_key
            )

            if failed > 0:
                # Partial failure — keep old key active, retire new key for safety
                raise RuntimeError(f"Re-encryption partially failed: {failed}/{total_creds} errors: {errors[:5]}")

            # 4. Success: old → retired, new → active
            if old_key:
                old_key.status = 'retired'
            new_key_version.status = 'active'
            db.session.commit()

            write_audit_log(
                log_type='key_rotation',
                operator=request.username or 'system',
                source_ip=request.remote_addr or '127.0.0.1',
                target_asset='System',
                operation_detail=f'密钥轮换完成: {migrated}条凭证已重加密, 旧密钥ID {old_key_id} retired, 新密钥ID {new_key_id} active',
                result='success'
            )

            return jsonify({
                'code': 200,
                'message': f'密钥轮换完成，{migrated} 条凭证已重加密',
                'data': {
                    'new_key_id': new_key_id,
                    'old_key_id': old_key_id,
                    'migrated_count': migrated,
                    'status': 'complete'
                }
            })

        except Exception as re_encrypt_error:
            # 5. Failure rollback: old key stays active, new key becomes retired
            db.session.rollback()
            if old_key:
                old_key.status = 'active'
            new_key_version.status = 'retired'
            db.session.commit()

            logger.error("[KEY-ROTATION] Re-encryption failed, old key preserved, new key retired: %s", re_encrypt_error)

            write_audit_log(
                log_type='key_rotation',
                operator=request.username or 'system',
                source_ip=request.remote_addr or '127.0.0.1',
                target_asset='System',
                operation_detail=f'密钥轮换失败: {str(re_encrypt_error)[:200]}, 旧密钥保持active',
                result='failed'
            )

            return jsonify({
                'code': 500,
                'message': f'重加密失败，旧密钥保持活跃，系统正常运行: {str(re_encrypt_error)[:200]}'
            }), 500

        finally:
            # 6. Always resume scheduler
            resume_rotation_jobs()
            logger.info("[KEY-ROTATION] Scheduler rotation jobs resumed")

    except Exception as e:
        db.session.rollback()
        logger.error("[KEY-ROTATION] Rotation failed: %s", e)
        return jsonify({'code': 500, 'message': f'密钥轮换失败: {str(e)}'}), 500
```

- [ ] **Step 3: Add pause/resume helpers to scheduler.py**

Add to `backend/app/scheduler.py` before `init_scheduler()`:

```python
# === T4: Pause/resume rotation jobs during key re-encryption ===

_paused_rotation_jobs = []

def pause_rotation_jobs():
    """Pause all rotation_schedule_ jobs during key re-encryption."""
    global _paused_rotation_jobs
    _paused_rotation_jobs = []
    for job in scheduler.get_jobs():
        if job.id.startswith('rotation_schedule_'):
            scheduler.pause_job(job.id)
            _paused_rotation_jobs.append(job.id)
    logger.info("[SCHEDULER] Paused %d rotation jobs for re-encryption", len(_paused_rotation_jobs))


def resume_rotation_jobs():
    """Resume previously paused rotation jobs."""
    for job_id in _paused_rotation_jobs:
        scheduler.resume_job(job_id)
    logger.info("[SCHEDULER] Resumed %d rotation jobs", len(_paused_rotation_jobs))
    _paused_rotation_jobs.clear()
```

- [ ] **Step 4: Disable the old progressive_re_encrypt scheduler job**

In `backend/app/scheduler.py:744-749`, remove or comment out the progressive re-encrypt job registration:

```python
    # REMOVED: Progressive re-encrypt job — replaced by synchronous re-encryption in T4
    # scheduler.add_job(
    #     id='progressive_re_encrypt',
    #     func=_progressive_re_encrypt,
    #     trigger='interval',
    #     seconds=30
    # )
```

The `_progressive_re_encrypt` function itself can stay in the file (dead code, harmless).

- [ ] **Step 5: Restart backend and test rotation**

Run:
```bash
cd D:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python app.py
```

Test: `POST /api/keys/rotate` — should complete synchronously and return migrated count.
Test: `GET /api/keys/status` — should show new key active, old key retired.
Test: Verify passwords still decryptable by viewing a credential password.

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/crypto_service.py backend/app/api/key_management.py backend/app/scheduler.py
git commit -m "feat: synchronous SM4 key rotation with full re-encryption (old keys retired, never deleted)"
```

---

### Task 5: Extract Shared Recording Service

**Files:**
- Create: `backend/app/services/recording_service.py`
- Modify: `backend/app/routes/ssh.py:25-28,74-93,109-110,265-267,279-280,287,301,354-355`
- Modify: `backend/app/routes/winrm.py:22-24,30-49,73-74,185-187,197-198,206,221`

- [ ] **Step 1: Create recording_service.py**

Create `backend/app/services/recording_service.py`:

```python
import os
import struct
from app import db
from app.services.crypto_service import CryptoService
from app.utils.logger import get_logger

logger = get_logger('app.services.recording_service')

RECORDINGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'recordings')


def ensure_recordings_dir():
    if not os.path.exists(RECORDINGS_DIR):
        os.makedirs(RECORDINGS_DIR)
    return RECORDINGS_DIR


def start_recording(asset_id, user_id, session_id):
    """Create a new recording file and return (file_handle, file_path)."""
    ensure_recordings_dir()
    filename = f"{asset_id}_{user_id}_{session_id}.cast"
    filepath = os.path.join(RECORDINGS_DIR, filename)
    fh = open(filepath, 'w', encoding='utf-8')
    return fh, filepath


def write_recording_header(fh, width, height, start_time_iso):
    """Write asciicast v2 header."""
    import json
    header = {"version": 2, "width": width, "height": height, "timestamp": int(start_time_iso) if isinstance(start_time_iso, (int, float)) else 0}
    header_line = json.dumps(header, ensure_ascii=False) + "\n"
    fh.write(header_line)
    fh.flush()


def append_recording_frame(fh, event_type, data, timestamp):
    """Append a single asciicast frame. event_type: 'o' for output, 'i' for input."""
    import json
    line = json.dumps([timestamp, event_type, data], ensure_ascii=False) + "\n"
    fh.write(line)
    fh.flush()


def finish_recording(session_record):
    """Encrypt the plaintext .cast file with SM4-CBC + DEK, save as .cast.enc, delete plaintext."""
    plaintext_path = session_record.recording_path
    if not plaintext_path or not os.path.exists(plaintext_path):
        return
    if not plaintext_path.endswith('.cast'):
        return

    enc_path = plaintext_path + '.enc'
    with open(plaintext_path, 'rb') as f:
        plaintext = f.read()

    dek = os.urandom(16)
    iv, ciphertext = CryptoService.sm4_cbc_encrypt_bytes(plaintext, dek)
    encrypted_dek = CryptoService.encrypt_dek_with_master_key(dek)

    with open(enc_path, 'wb') as f:
        f.write(struct.pack('>I', len(encrypted_dek)))
        f.write(encrypted_dek)
        f.write(iv)
        f.write(ciphertext)

    os.remove(plaintext_path)
    session_record.recording_path = enc_path
    db.session.commit()
    logger.info("[RECORDING] Encrypted recording saved: %s", enc_path)


def cleanup_recording(file_handle, session_record):
    """Close file handle and encrypt recording."""
    if file_handle:
        try:
            file_handle.close()
        except Exception:
            pass
    finish_recording(session_record)
```

- [ ] **Step 2: Refactor ssh.py to use recording_service**

In `backend/app/routes/ssh.py`:

Remove lines 25-28 (recordings_dir setup) and line 74-93 (`_encrypt_recording_file`).

Add import at top:
```python
from app.services.recording_service import start_recording, write_recording_header, append_recording_frame, finish_recording, cleanup_recording
```

Replace recording init (around line 265-267):
```python
        # OLD:
        recording_filename = f"{asset_id}_{decoded.get('user_id')}_{session_id}.cast"
        recording_path = os.path.join(recordings_dir, recording_filename)
        recording_file = open(recording_path, 'w', encoding='utf-8')

        # NEW:
        recording_file, recording_path = start_recording(asset_id, decoded.get('user_id'), session_id)
```

Replace header writing (around line 279-280):
```python
        # OLD:
        header_line = json.dumps({"version": 2, "width": term_width, "height": term_height, "timestamp": int(time.time())}, ensure_ascii=False) + "\n"
        recording_file.write(header_line)
        recording_file.flush()

        # NEW:
        write_recording_header(recording_file, term_width, term_height, int(time.time()))
```

Replace all `recording_file.write(line)` / `recording_file.flush()` calls (lines 354-355, 575-576):
```python
        # OLD:
        recording_file.write(line)
        recording_file.flush()

        # NEW:
        append_recording_frame(recording_file, 'o', data, timestamp)
```

Replace cleanup (around line 109-117):
```python
        # OLD:
        if conn_info.get('recording_file'):
            conn_info['recording_file'].close()
        # ...
        _encrypt_recording_file(session_record)

        # NEW:
        cleanup_recording(conn_info.get('recording_file'), session_record)
```

- [ ] **Step 3: Refactor winrm.py to use recording_service**

Same pattern as Step 2. Remove lines 22-24 and 30-49. Add the import. Replace:
- Recording init → `start_recording()`
- Header → `write_recording_header()`
- `_write_recording_output()` calls → `append_recording_frame()`
- `_encrypt_recording_file()` → `cleanup_recording(conn_info.get('recording_file'), session_record)`

- [ ] **Step 4: Verify — SSH and WinRM sessions produce correct recordings**

Start backend, connect via SSH terminal and PowerShell, verify recordings are created and playable.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/recording_service.py backend/app/routes/ssh.py backend/app/routes/winrm.py
git commit -m "refactor: extract shared recording service from ssh/winrm routes"
```

---

### Task 6: WebSocket Session Redis Persistence

**Files:**
- Modify: `backend/requirements.txt` — add `redis`
- Modify: `backend/app.py:72-78` — SocketIO Redis with fallback
- Modify: `docker/docker-compose.yml` — add redis service

- [ ] **Step 1: Add redis dependency**

Append to `backend/requirements.txt`:
```
redis
```

Install:
```bash
cd D:/PAM/pam-system/backend && pip install redis
```

- [ ] **Step 2: Configure SocketIO with Redis fallback**

Replace `backend/app.py:72-78`:

```python
# 初始化SocketIO — 优先使用Redis消息队列，不可用时回退内存模式
import os
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
socketio_kwargs = {'cors_allowed_origins': '*'}

try:
    import redis
    r = redis.Redis.from_url(redis_url, socket_connect_timeout=2)
    r.ping()
    socketio_kwargs['message_queue'] = redis_url
    logger.info("[SOCKETIO] Using Redis message queue: %s", redis_url)
except Exception as e:
    logger.warning("[SOCKETIO] Redis unavailable (%s), falling back to in-memory mode", e)

socketio = SocketIO(app, **socketio_kwargs)
```

- [ ] **Step 3: Add Redis to docker-compose.yml**

Add to `docker/docker-compose.yml` services:

```yaml
  redis:
    image: redis:7-alpine
    container_name: pam-redis
    ports:
      - "6379:6379"
    networks:
      - pam-net
    restart: unless-stopped
```

- [ ] **Step 4: Start Redis and verify**

```bash
cd D:/PAM/pam-system/docker && docker compose up -d redis
cd D:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python app.py
```

Check logs for: `[SOCKETIO] Using Redis message queue: redis://localhost:6379`

Test: Open two browser tabs, connect to Web SSH, verify sessions work.

Test fallback: Stop Redis (`docker stop pam-redis`), restart backend — should log `Redis unavailable, falling back to in-memory mode` and still work.

- [ ] **Step 5: Commit**

```bash
git add backend/requirements.txt backend/app.py docker/docker-compose.yml
git commit -m "feat: add Redis-backed WebSocket session persistence with in-memory fallback"
```

---

### Task 7: Password View Re-Authentication

**Files:**
- Modify: `backend/app/api/auth.py:20-47` — extend temp token with asset binding
- Modify: `backend/app/api/asset.py:171-228` — add re-auth token check
- Modify: `frontend/src/components/AssetList.vue` — add re-auth dialog

- [ ] **Step 1: Add asset-bound temp token generation in auth.py**

Add a new function after `verify_temp_token` in `backend/app/api/auth.py`:

```python
def generate_password_view_token(user_id, username, asset_id, credential_id):
    """Generate a temp token for password viewing — bound to user+asset+credential, 5min TTL."""
    token = str(uuid.uuid4())
    _temp_tokens[token] = {
        "user_id": user_id,
        "username": username,
        "asset_id": asset_id,
        "credential_id": credential_id,
        "purpose": "password_view",
        "expires_at": time.time() + 300
    }
    return token


def verify_password_view_token(token, credential_id):
    """Verify a password-view temp token. Returns user_info or None."""
    if token not in _temp_tokens:
        return None
    token_data = _temp_tokens[token]
    if time.time() > token_data['expires_at']:
        del _temp_tokens[token]
        return None
    if token_data.get('purpose') != 'password_view':
        return None
    if token_data.get('credential_id') != credential_id:
        return None
    user_info = token_data.copy()
    del _temp_tokens[token]  # one-time use
    return user_info
```

- [ ] **Step 2: Modify view_credential to require re-auth token**

In `backend/app/api/asset.py:24`, add the import:
```python
from app.api.auth import verify_password_view_token
```

In `backend/app/api/asset.py:171-228`, modify `view_credential()` to accept and validate a `view_token`:

```python
@asset_bp.route('/credentials/<int:credential_id>/view', methods=['POST'])
@token_required
@role_required('admin', 'operator')
def view_credential(credential_id):
    """查看密码 — requires password_view_token from re-authentication"""
    try:
        data = request.get_json(silent=True) or {}
        view_token = data.get('view_token')

        if not view_token:
            return jsonify({'code': 401, 'message': '需要二次认证，请先验证密码'}), 401

        token_info = verify_password_view_token(view_token, credential_id)
        if not token_info:
            return jsonify({'code': 401, 'message': '二次认证Token无效或已过期'}), 401

        credential = Credential.query.get(credential_id)
        # ... rest of existing logic unchanged ...
```

- [ ] **Step 3: Add re-auth dialog to frontend AssetList.vue**

Add a password re-auth dialog in the template section of `AssetList.vue`:

```html
    <!-- Re-auth Dialog for password viewing -->
    <el-dialog v-model="reAuthVisible" title="身份验证" width="400px" :close-on-click-modal="false">
      <p style="margin-bottom: 16px;">查看密码需要验证您的身份，请输入当前登录密码</p>
      <el-input v-model="reAuthPassword" type="password" placeholder="请输入当前密码" show-password
                @keyup.enter="confirmReAuth" />
      <template #footer>
        <el-button @click="reAuthVisible = false">取消</el-button>
        <el-button type="primary" :loading="reAuthLoading" @click="confirmReAuth">确认</el-button>
      </template>
    </el-dialog>
```

Add to `<script setup>` (add `ElMessageBox` to the existing element-plus imports at the top of the script):
```javascript
import { ElMessage, ElMessageBox } from 'element-plus'
```

Then add these reactive variables and functions:
```javascript
const reAuthVisible = ref(false)
const reAuthPassword = ref('')
const reAuthLoading = ref(false)
const pendingViewAssetId = ref(null)
const pendingViewCredentialId = ref(null)

const requestPasswordView = (assetId, credentialId) => {
  pendingViewAssetId.value = assetId
  pendingViewCredentialId.value = credentialId
  reAuthPassword.value = ''
  reAuthVisible.value = true
}

const confirmReAuth = async () => {
  reAuthLoading.value = true
  try {
    // Step 1: Verify password
    const verifyRes = await request.post('/api/auth/verify-password', { password: reAuthPassword.value })
    if (!verifyRes.data.valid) {
      ElMessage.error('密码错误')
      return
    }
    // Step 2: Get view token
    const tokenRes = await request.post('/api/auth/password-view-token', {
      asset_id: pendingViewAssetId.value,
      credential_id: pendingViewCredentialId.value
    })
    if (tokenRes.code !== 200) {
      ElMessage.error(tokenRes.message || '获取查看Token失败')
      return
    }
    // Step 3: View password with token
    const viewRes = await request.post(`/api/assets/credentials/${pendingViewCredentialId.value}/view`, {
      view_token: tokenRes.data.view_token
    })
    if (viewRes.code === 200) {
      ElMessage.success(`密码: ${viewRes.password}`)
    }
  } finally {
    reAuthLoading.value = false
    reAuthVisible.value = false
  }
}
```

The existing "查看密码" button in the table column handler should be updated to call `requestPasswordView(scope.row.id, scope.row.credentials[0]?.id)` instead of the old inline API call.

- [ ] **Step 4: Add the /password-view-token endpoint to auth.py**

```python
@auth_bp.route('/password-view-token', methods=['POST'])
@token_required
def get_password_view_token():
    """Generate a one-time token for viewing a specific credential's password."""
    data = request.get_json()
    credential_id = data.get('credential_id')
    if not credential_id:
        return jsonify({'code': 400, 'message': 'credential_id is required'}), 400
    token = generate_password_view_token(request.user_id, request.username, data.get('asset_id'), credential_id)
    return jsonify({'code': 200, 'data': {'view_token': token}})
```

- [ ] **Step 5: Verify**

Start frontend and backend. Click "view password" on an asset → re-auth dialog appears → enter admin password → password is displayed.

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/auth.py backend/app/api/asset.py frontend/src/components/AssetList.vue
git commit -m "feat: add password view re-authentication with 5-min one-time token"
```

---

### Task 8: Batch Asset Operations

**Files:**
- Modify: `backend/app/api/asset.py` — add batch test + batch rotate endpoints
- Modify: `frontend/src/components/AssetList.vue` — multi-select + batch action buttons

- [ ] **Step 1: Add batch connectivity test endpoint**

In `backend/app/api/asset.py`, update the Flask import at line 1:
```python
# OLD:
from flask import Blueprint, request, jsonify
# NEW:
from flask import Blueprint, request, jsonify, current_app
```

Then add the following code to the file (before the last line):

```python
_batch_tasks = {}  # task_id -> result dict

@asset_bp.route('/batch/test', methods=['POST'])
@token_required
@role_required('admin', 'operator')
def batch_test_connectivity():
    """Batch connectivity test — async, returns task_id for polling."""
    import uuid
    import threading

    data = request.get_json()
    asset_ids = data.get('asset_ids', [])
    if not asset_ids:
        return jsonify({'code': 400, 'message': 'asset_ids is required'}), 400

    task_id = uuid.uuid4().hex[:12]
    _batch_tasks[task_id] = {'status': 'running', 'results': [], 'total': len(asset_ids), 'done': 0}

    def _run():
        with current_app.app_context():
            for aid in asset_ids:
                try:
                    asset = Asset.query.get(aid)
                    if not asset:
                        _batch_tasks[task_id]['results'].append({'asset_id': aid, 'status': 'not_found'})
                        continue
                    credential = max(asset.credentials, key=lambda c: c.id) if asset.credentials else None
                    if not credential:
                        _batch_tasks[task_id]['results'].append({'asset_id': aid, 'ip': asset.ip, 'status': 'no_credential'})
                        continue
                    password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
                    if password is None:
                        _batch_tasks[task_id]['results'].append({'asset_id': aid, 'ip': asset.ip, 'status': 'decrypt_failed'})
                        continue
                    from app.services.connection_tester import test_connection
                    result = test_connection(asset_type=asset.os_type, host=asset.ip,
                                             port=asset.ssh_port, username=credential.account_name,
                                             password=password)
                    asset.connectivity = 'online' if result['success'] else 'offline'
                    asset.last_check_time = datetime.now()
                    db.session.commit()
                    _batch_tasks[task_id]['results'].append({
                        'asset_id': aid, 'ip': asset.ip, 'status': 'online' if result['success'] else 'offline',
                        'message': result.get('message', '')
                    })
                except Exception as e:
                    _batch_tasks[task_id]['results'].append({'asset_id': aid, 'status': 'error', 'message': str(e)[:200]})
                _batch_tasks[task_id]['done'] += 1
        _batch_tasks[task_id]['status'] = 'completed'

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({'code': 200, 'message': '批量检测已启动', 'data': {'task_id': task_id}})


@asset_bp.route('/batch/result/<task_id>', methods=['GET'])
@token_required
def get_batch_result(task_id):
    """Poll batch task result."""
    task = _batch_tasks.get(task_id)
    if not task:
        return jsonify({'code': 404, 'message': 'Task not found'}), 404
    return jsonify({'code': 200, 'data': task})


@asset_bp.route('/batch/rotate', methods=['POST'])
@token_required
@role_required('admin')
def batch_rotate_passwords():
    """Batch password rotation — serial execution, returns per-asset results."""
    from app.services.password_rotation import rotate_password

    data = request.get_json()
    asset_ids = data.get('asset_ids', [])
    if not asset_ids:
        return jsonify({'code': 400, 'message': 'asset_ids is required'}), 400

    results = []
    for aid in asset_ids:
        try:
            rotate_password(aid)
            results.append({'asset_id': aid, 'status': 'success'})
        except Exception as e:
            results.append({'asset_id': aid, 'status': 'failed', 'message': str(e)[:200]})

    success_count = sum(1 for r in results if r['status'] == 'success')
    return jsonify({
        'code': 200,
        'message': f'批量改密完成: {success_count}/{len(asset_ids)} 成功',
        'data': {'results': results}
    })
```

- [ ] **Step 2: Add multi-select and batch buttons to AssetList.vue**

Add `type="selection"` column to el-table and batch action buttons:

```html
      <el-table :data="assets" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="50" />
        <!-- ... existing columns ... -->
      </el-table>

      <!-- Batch action bar (visible when items selected) -->
      <div v-if="selectedAssets.length > 0" style="margin-top: 12px; display: flex; gap: 8px; align-items: center;">
        <span>已选 {{ selectedAssets.length }} 个资产</span>
        <el-button type="primary" :loading="batchTesting" @click="batchTest">批量检测连通性</el-button>
        <el-button v-if="role === 'admin'" type="warning" :loading="batchRotating" @click="batchRotate">批量改密</el-button>
      </div>
```

Add to `<script setup>` (ensure `ElMessageBox` is in the element-plus import):
```javascript
// At top of script: import { ElMessage, ElMessageBox } from 'element-plus'
```

Then add:
```javascript
const selectedAssets = ref([])
const batchTesting = ref(false)
const batchRotating = ref(false)

const handleSelectionChange = (selection) => {
  selectedAssets.value = selection
}

const batchTest = async () => {
  batchTesting.value = true
  try {
    const ids = selectedAssets.value.map(a => a.id)
    const res = await request.post('/api/assets/batch/test', { asset_ids: ids })
    if (res.code === 200) {
      const taskId = res.data.task_id
      // Poll for results
      const poll = setInterval(async () => {
        const r = await request.get(`/api/assets/batch/result/${taskId}`)
        if (r.data.status === 'completed') {
          clearInterval(poll)
          const online = r.data.results.filter(x => x.status === 'online').length
          ElMessage.success(`检测完成: ${online}/${r.data.total} 在线`)
          fetchAssets()  // refresh table
        }
      }, 2000)
    }
  } finally {
    batchTesting.value = false
  }
}

const batchRotate = async () => {
  await ElMessageBox.confirm(`确认为选中的 ${selectedAssets.value.length} 个资产执行改密？`, '批量改密确认', { type: 'warning' })
  batchRotating.value = true
  try {
    const ids = selectedAssets.value.map(a => a.id)
    const res = await request.post('/api/assets/batch/rotate', { asset_ids: ids })
    ElMessage.success(res.message)
    fetchAssets()
  } finally {
    batchRotating.value = false
  }
}
```

- [ ] **Step 3: Verify**

Start frontend and backend. Select multiple assets → click "批量检测连通性" → results appear.
Select assets → click "批量改密" → confirm dialog → rotation executes.

- [ ] **Step 4: Commit**

```bash
git add backend/app/api/asset.py frontend/src/components/AssetList.vue
git commit -m "feat: add batch asset connectivity test and password rotation"
```

---

## Implementation Order Summary

```
T1 (rate limit) ──┐
T2 (audit lock) ──┼──→ T4 (SM4 re-encrypt) ──→ T5 (recording) ──→ T6 (Redis) ──→ T7 (re-auth)
T3 (SM2 det-k)  ──┘                                                                └──→ T8 (batch ops)
```

- T1/T2/T3 are fully independent — execute in any order
- T4 MUST follow T1 (rate limiter protects key rotation endpoint)
- T5 follows T4 (recording uses SM4 encryption — crypto stack should be stable)
- T6 follows T5 (recording is a shared service, Redis-ifying sessions after is cleaner)
- T7/T8 are independent of each other but both follow T6 (they benefit from Redis-backed sessions indirectly)
