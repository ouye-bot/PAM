# P6 Feature Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 7 optimization tasks across 2 phases — business logic improvements (P5-C) and cryptographic corrections (P5-D).

**Architecture:** Each task modifies 1-2 existing files with minimal blast radius. Tasks are independent and can be executed in any order, though the recommended sequence follows the spec's phase ordering.

**Tech Stack:** Python 3.13 / Flask / SM3/SM4 (gmssl) / Redis / Vue 3 / Element Plus

---

## File Map

| File | Tasks | Responsibility |
|------|-------|---------------|
| `backend/app/api/dashboard.py` | C1 | Add weak password detection |
| `backend/app/api/compliance.py` | C2 | Add pagination support |
| `frontend/src/components/ComplianceReport.vue` | C2 | Add pagination UI |
| `backend/app.py` | C3, C5 | Enhance health check, add shutdown hook |
| `backend/app/utils/rate_limiter.py` | C4 | Add Redis backend |
| `backend/app/scheduler.py` | C5 | Expose shutdown function |
| `backend/app/services/crypto_service.py` | D1, D2 | Remove zero-IV, standardize HMAC |

---

### Task 1: C1 — Weak Password Statistics

**Files:**
- Modify: `backend/app/api/dashboard.py:55-57`

- [ ] **Step 1: Add weak password detection function**

In `backend/app/api/dashboard.py`, add a helper function after the imports (line 9):

```python
import re

WEAK_PASSWORD_PATTERNS = [
    r'^\d+$',           #纯数字
    r'^[a-zA-Z]+$',     #纯字母
    r'^(.)\1{7,}$',     #重复字符8位以上
]

COMMON_WEAK_PASSWORDS = {
    '12345678', '123456789', '1234567890',
    'password', 'admin123', 'root1234',
    'qwerty123', 'abc12345', '11111111',
    '00000000', '88888888', 'a1234567',
}


def _is_weak_password(password):
    """检测密码是否为弱密码"""
    if not password or len(password) < 8:
        return True
    if password.lower() in COMMON_WEAK_PASSWORDS:
        return True
    for pattern in WEAK_PASSWORD_PATTERNS:
        if re.match(pattern, password):
            return True
    return False
```

- [ ] **Step 2: Replace hardcoded weak_password_assets**

In `get_dashboard_stats()`, replace lines 55-57:

```python
        # 5. 弱口令资产数
        # 实际项目中可能需要更复杂的弱口令检测逻辑
        weak_password_assets = 0
```

With:

```python
        # 5. 弱口令资产数（解密最新凭据密码检测）
        weak_password_assets = 0
        try:
            from app.services.crypto_service import CryptoService
            active_assets_with_creds = Asset.query.filter(
                Asset.status == 'active'
            ).all()
            for asset in active_assets_with_creds:
                if not asset.credentials:
                    continue
                credential = max(asset.credentials, key=lambda c: c.id)
                password = CryptoService.sm4_decrypt(
                    credential.encrypted_password, credential.key_version
                )
                if password and _is_weak_password(password):
                    weak_password_assets += 1
                    del password
                elif password:
                    del password
        except Exception as weak_err:
            logger.warning("[DASHBOARD] 弱密码检测异常: %s", weak_err)
```

- [ ] **Step 3: Verify the change**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "from app.api.dashboard import _is_weak_password; assert _is_weak_password('12345678') == True; assert _is_weak_password('Str0ng!P@ss') == False; print('OK')"`

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add backend/app/api/dashboard.py
git commit -m "feat(dashboard): add real weak password detection (C1)"
```

---

### Task 2: C2 — Compliance Report Pagination

**Files:**
- Modify: `backend/app/api/compliance.py`
- Modify: `frontend/src/components/ComplianceReport.vue`

- [ ] **Step 1: Add pagination to compliance API**

Replace `backend/app/api/compliance.py` entirely:

```python
"""国密合规自检API"""
from flask import Blueprint, jsonify, request
from app.utils.auth import token_required, role_required
from app.services.compliance_checker import run_compliance_check

compliance_bp = Blueprint('compliance', __name__, url_prefix='/api')


@compliance_bp.route('/compliance/report', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_compliance_report():
    """获取国密合规自检报告（支持分页）"""
    report = run_compliance_check()

    # 分页：对 checks 列表分页
    checks = report.get('checks', [])
    page = request.args.get('page', 1, type=int)
    size = request.args.get('size', 10, type=int)
    page = max(1, page)
    size = max(1, min(100, size))

    total = len(checks)
    start = (page - 1) * size
    end = start + size
    paginated_checks = checks[start:end]

    report['checks'] = paginated_checks
    report['total'] = total
    report['page'] = page
    report['size'] = size

    return jsonify({
        'code': 200,
        'data': report
    })
```

- [ ] **Step 2: Add pagination UI to ComplianceReport.vue**

In `frontend/src/components/ComplianceReport.vue`, add pagination state and UI.

Replace the `<script setup>` section (add pagination refs and update loadReport):

```javascript
import { ref, computed } from 'vue'
import request from '../utils/request'

const loading = ref(false)
const report = ref(null)
const currentPage = ref(1)
const pageSize = ref(10)
const totalChecks = ref(0)

const gradeClass = computed(() => {
  if (!report.value) return ''
  const g = report.value.grade
  if (g === 'A') return 'grade-a'
  if (g === 'B') return 'grade-b'
  if (g === 'C') return 'grade-c'
  return 'grade-d'
})

const gradeText = computed(() => {
  if (!report.value) return ''
  const g = report.value.grade
  if (g === 'A') return '优秀 - 全面合规'
  if (g === 'B') return '良好 - 基本合规'
  if (g === 'C') return '一般 - 部分不合规'
  return '不合格 - 需立即整改'
})

const tagType = (status) => {
  if (status === 'pass') return 'success'
  if (status === 'warn') return 'warning'
  return 'danger'
}

const statusText = (status) => {
  if (status === 'pass') return '通过'
  if (status === 'warn') return '警告'
  return '未通过'
}

const loadReport = async (page = 1) => {
  loading.value = true
  currentPage.value = page
  try {
    const res = await request.get(`/compliance/report?page=${page}&size=${pageSize.value}`)
    if (res.code === 200) {
      report.value = res.data
      totalChecks.value = res.data.total || 0
    }
  } catch (err) {
    console.error('获取合规报告失败:', err)
  } finally {
    loading.value = false
  }
}

const handlePageChange = (page) => {
  loadReport(page)
}
```

In the template, add pagination after the `checks-list` div (before the closing `</div>` of `report-body`):

```html
          </div>
        </div>

        <div v-if="totalChecks > pageSize" class="pagination-wrapper">
          <el-pagination
            v-model:current-page="currentPage"
            :page-size="pageSize"
            :total="totalChecks"
            layout="prev, pager, next"
            @current-change="handlePageChange"
          />
        </div>
      </div>
```

Add pagination style:

```css
.pagination-wrapper {
  display: flex;
  justify-content: center;
  padding: 20px 0 0;
}
```

- [ ] **Step 3: Verify backend pagination**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "
from app import app
with app.test_client() as c:
    r = c.post('/api/auth/login', json={'username':'admin','password':'admin123'})
    token = r.get_json()['data']['token']
    r2 = c.get('/api/compliance/report?page=1&size=2', headers={'Authorization': f'Bearer {token}'})
    d = r2.get_json()['data']
    assert 'total' in d, 'missing total'
    assert 'page' in d, 'missing page'
    assert len(d['checks']) <= 2, 'pagination not working'
    print(f'OK: total={d[\"total\"]}, page={d[\"page\"]}, checks={len(d[\"checks\"])}')
"`

Expected: `OK: total=5, page=1, checks=2`

- [ ] **Step 4: Commit**

```bash
git add backend/app/api/compliance.py frontend/src/components/ComplianceReport.vue
git commit -m "feat(compliance): add pagination support (C2)"
```

---

### Task 3: C3 — Health Check Enhancement

**Files:**
- Modify: `backend/app.py:108-150`

- [ ] **Step 1: Enhance health check endpoint**

In `backend/app.py`, replace the `health_check` function (lines 108-150) with:

```python
@app.route('/api/health', methods=['GET'])
def health_check():
    checks = {
        'database': 'unknown',
        'master_key': 'unknown',
        'active_work_key': 'unknown',
        'redis': 'unknown',
        'scheduler': 'unknown',
        'recordings_dir': 'unknown',
    }
    overall = 'ok'

    # 数据库检查
    try:
        from app.models import KeyVersion
        KeyVersion.query.first()
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {str(e)}'
        overall = 'degraded'

    # 主密钥检查
    try:
        from app.services.crypto_service import get_master_key
        mk = get_master_key()
        checks['master_key'] = 'ok' if mk and len(mk) == 32 else 'invalid'
    except Exception as e:
        checks['master_key'] = f'error: {str(e)}'
        overall = 'degraded'

    # 活跃工作密钥检查
    try:
        from app.models import KeyVersion
        from app.services.crypto_service import CryptoService
        active_key = KeyVersion.query.filter_by(status='active').first()
        if active_key:
            wk = CryptoService.decrypt_work_key(active_key.encrypted_key)
            checks['active_work_key'] = 'ok' if wk else 'decrypt_failed'
        else:
            checks['active_work_key'] = 'not_found'
    except Exception as e:
        checks['active_work_key'] = f'error: {str(e)}'

    # Redis 检查
    try:
        import redis as redis_lib
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        r = redis_lib.Redis.from_url(redis_url, socket_connect_timeout=2)
        r.ping()
        checks['redis'] = 'ok'
    except Exception as e:
        checks['redis'] = f'error: {str(e)}'
        # Redis 不可用不影响整体状态，仅 degraded
        if overall == 'ok':
            overall = 'degraded'

    # 调度器状态
    try:
        from app.scheduler import scheduler
        checks['scheduler'] = 'ok' if scheduler.running else 'stopped'
    except Exception as e:
        checks['scheduler'] = f'error: {str(e)}'

    # 录制目录可写性
    try:
        import tempfile
        recordings_dir = os.path.join(os.path.dirname(__file__), 'recordings')
        if not os.path.exists(recordings_dir):
            os.makedirs(recordings_dir, exist_ok=True)
        test_file = os.path.join(recordings_dir, '.health_check_tmp')
        with open(test_file, 'w') as f:
            f.write('ok')
        os.remove(test_file)
        checks['recordings_dir'] = 'ok'
    except Exception as e:
        checks['recordings_dir'] = f'error: {str(e)}'

    from app import __version__
    return jsonify({
        'status': overall,
        'version': __version__,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'checks': checks
    })
```

- [ ] **Step 2: Verify health check**

Run: `curl -s http://localhost:5000/api/health | python -m json.tool`

Expected: JSON with 6 check keys (database, master_key, active_work_key, redis, scheduler, recordings_dir)

- [ ] **Step 3: Commit**

```bash
git add backend/app.py
git commit -m "feat(health): add redis/scheduler/recordings checks (C3)"
```

---

### Task 4: C4 — Redis Rate Limiting Backend

**Files:**
- Modify: `backend/app/utils/rate_limiter.py`

- [ ] **Step 1: Add Redis backend to rate_limiter.py**

Add the following after the existing imports in `backend/app/utils/rate_limiter.py`:

```python
import os

# Redis backend (lazy init)
_redis_client = None
_redis_available = False


def _get_redis():
    """Lazy-init Redis connection for rate limiting."""
    global _redis_client, _redis_available
    if _redis_client is not None:
        return _redis_client if _redis_available else None
    try:
        import redis
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        _redis_client = redis.Redis.from_url(redis_url, socket_connect_timeout=2)
        _redis_client.ping()
        _redis_available = True
        logger.info("[RATE_LIMITER] Using Redis backend: %s", redis_url)
        return _redis_client
    except Exception as e:
        _redis_available = False
        logger.warning("[RATE_LIMITER] Redis unavailable (%s), using in-memory backend", e)
        return None
```

- [ ] **Step 2: Add Redis-backed rate limit check function**

Add after the `_get_redis` function:

```python
def _redis_check_rate_limit(key_type, key_value, max_attempts, window_seconds, lock_seconds):
    """Redis-backed sliding window rate limit. Returns True if allowed."""
    r = _get_redis()
    if r is None:
        return None  # signal to fall back to in-memory

    cache_key = f"pam:ratelimit:{key_type}:{key_value}"
    lock_key = f"pam:ratelimit:lock:{key_type}:{key_value}"

    try:
        # Check lock first
        if r.get(lock_key):
            return False

        # Increment counter
        pipe = r.pipeline()
        pipe.incr(cache_key)
        pipe.expire(cache_key, window_seconds)
        result = pipe.execute()
        count = result[0]

        if count > max_attempts:
            # Set lock
            r.setex(lock_key, lock_seconds, '1')
            r.delete(cache_key)
            logger.warning(f"Rate limit triggered (Redis): {cache_key}, locked for {lock_seconds}s")
            return False

        return True
    except Exception as e:
        logger.warning(f"Redis rate limit error: {e}, falling back to in-memory")
        return None
```

- [ ] **Step 3: Update check_rate_limit to try Redis first**

Replace the `check_rate_limit` function:

```python
def check_rate_limit(key_type, key_value, max_attempts, window_seconds=300, lock_seconds=900):
    # Try Redis first
    redis_result = _redis_check_rate_limit(key_type, key_value, max_attempts, window_seconds, lock_seconds)
    if redis_result is not None:
        return redis_result

    # Fall back to in-memory
    now = time.time()
    cache_key = f"{key_type}:{key_value}"

    with _lock:
        record = _records.get(cache_key)
        if record:
            locked_until = record.get('locked_until')
            if locked_until and now < locked_until:
                remaining_minutes = int((locked_until - now) / 60) + 1
                logger.warning(f"Rate limit locked: {cache_key}, remaining {remaining_minutes}min")
                return False

            if now - record['window_start'] > window_seconds:
                record['window_start'] = now
                record['attempts'] = 1
                return True

            record['attempts'] += 1
            if record['attempts'] >= max_attempts:
                record['locked_until'] = now + lock_seconds
                logger.warning(f"Rate limit triggered: {cache_key}, locked for {lock_seconds}s")
                return False

            return True
        else:
            _records[cache_key] = {
                'attempts': 1,
                'window_start': now,
                'window_seconds': window_seconds
            }
            return True
```

- [ ] **Step 4: Update get_lock_remaining to check Redis**

Replace the `get_lock_remaining` function:

```python
def get_lock_remaining(key_type, key_value):
    # Check Redis lock
    r = _get_redis()
    if r is not None:
        try:
            lock_key = f"pam:ratelimit:lock:{key_type}:{key_value}"
            ttl = r.ttl(lock_key)
            if ttl and ttl > 0:
                return ttl
        except Exception:
            pass

    # Check in-memory
    now = time.time()
    cache_key = f"{key_type}:{key_value}"
    with _lock:
        record = _records.get(cache_key)
        if record:
            locked_until = record.get('locked_until')
            if locked_until and now < locked_until:
                return int(locked_until - now)
    return 0
```

- [ ] **Step 5: Update clear_rate_limit to clear both backends**

Replace the `clear_rate_limit` function:

```python
def clear_rate_limit(key_type, key_value):
    cache_key = f"{key_type}:{key_value}"
    # Clear in-memory
    with _lock:
        _records.pop(cache_key, None)
    # Clear Redis
    r = _get_redis()
    if r is not None:
        try:
            r.delete(f"pam:ratelimit:{key_type}:{key_value}")
            r.delete(f"pam:ratelimit:lock:{key_type}:{key_value}")
        except Exception:
            pass
    logger.debug(f"Rate limit cleared for {cache_key}")
```

- [ ] **Step 6: Verify rate limiter works**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "
from app.utils.rate_limiter import check_rate_limit, _get_redis, _redis_available
# Test in-memory fallback works
result = check_rate_limit('test', 'user1', 5, 60, 120)
assert result == True, 'first request should be allowed'
print(f'In-memory OK: {result}')
# Check Redis status
r = _get_redis()
print(f'Redis available: {_redis_available}')
print('OK')
"`

Expected: `In-memory OK: True` and `Redis available: True` (since pam-redis is running)

- [ ] **Step 7: Commit**

```bash
git add backend/app/utils/rate_limiter.py
git commit -m "feat(ratelimit): add Redis backend with in-memory fallback (C4)"
```

---

### Task 5: C5 — Scheduler Graceful Shutdown

**Files:**
- Modify: `backend/app/scheduler.py`
- Modify: `backend/app.py`

- [ ] **Step 1: Add shutdown function to scheduler.py**

Add at the end of `backend/app/scheduler.py` (after `resume_rotation_jobs`):

```python
def shutdown_scheduler(wait=True, timeout=10):
    """Gracefully shutdown the scheduler, waiting for running jobs."""
    if not scheduler.running:
        logger.info("[SCHEDULER] Scheduler not running, skipping shutdown")
        return
    logger.info("[SCHEDULER] Shutting down scheduler (wait=%s, timeout=%ds)...", wait, timeout)
    try:
        scheduler.shutdown(wait=wait)
        logger.info("[SCHEDULER] Scheduler shutdown complete")
    except Exception as e:
        logger.error("[SCHEDULER] Scheduler shutdown error: %s", e)
```

- [ ] **Step 2: Register atexit handler in app.py**

In `backend/app.py`, add after the scheduler initialization block (after `init_scheduler(app)` call, around line 255):

```python
    # 注册优雅关闭钩子
    import atexit
    from app.scheduler import shutdown_scheduler
    atexit.register(shutdown_scheduler, wait=True, timeout=10)
    logger.info("[APP] Registered graceful shutdown hook")
```

- [ ] **Step 3: Verify shutdown function exists**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "from app.scheduler import shutdown_scheduler; print('OK: shutdown_scheduler exists')"`

Expected: `OK: shutdown_scheduler exists`

- [ ] **Step 4: Commit**

```bash
git add backend/app/scheduler.py backend/app.py
git commit -m "feat(scheduler): add graceful shutdown with atexit hook (C5)"
```

---

### Task 6: D1 — Zero-IV Fallback Removal

**Files:**
- Modify: `backend/app/services/crypto_service.py`

- [ ] **Step 1: Verify no legacy data remains**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "
from app import app, db
from app.models import Credential
from app.services.crypto_service import CryptoService

with app.app_context():
    creds = Credential.query.all()
    failed = 0
    for c in creds:
        pwd = CryptoService.sm4_decrypt(c.encrypted_password, c.key_version)
        if pwd is None:
            failed += 1
            print(f'  FAIL: cred_id={c.id}')
        else:
            del pwd
    print(f'Total: {len(creds)}, Failed: {failed}')
    if failed == 0:
        print('OK: All credentials decrypt with standard method')
    else:
        print(f'WARNING: {failed} credentials need re-encryption first')
"`

Expected: `OK: All credentials decrypt with standard method`

- [ ] **Step 2: Remove zero-IV fallback from sm4_decrypt**

In `backend/app/services/crypto_service.py`, remove the zero-IV fallback block in `sm4_decrypt` (the `except Exception as e:` block that contains the "兼容模式" comment). Replace lines ~224-237 (the second `except` block inside `sm4_decrypt`):

Find and replace this block:

```python
        except Exception as e:
            # 兼容模式：早期版本(P4之前)使用全零IV加密，密文中不包含IV前缀。
            # 当标准解密失败时，尝试用零IV解密原始数据以兼容旧格式。
            # 注意：此回退会绕过IV的语义安全性——仅用于向后兼容，新加密数据一律使用随机IV+前缀格式。
            logger.warning("[DECRYPT] 标准解密失败，尝试零IV兼容模式: key_version_id=%s, err=%s", key_version_id, e)
            try:
                iv = b'\x00' * 16
                actual_ciphertext = data
                sm4 = CryptSM4()
                sm4.set_key(work_key, SM4_DECRYPT)
                plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
                return plaintext.decode()
            except UnicodeDecodeError as e2:
                logger.error("[DECRYPT] 兼容模式UTF-8解码失败: key_version_id=%s, %s", key_version_id, e2)
                return None
            except Exception as e2:
                logger.error("[DECRYPT] 业务密码解密失败(主密钥可能已更换): key_version_id=%s, %s",
                             key_version_id, e2)
                return None
```

With:

```python
        except Exception as e:
            logger.error("[DECRYPT] 业务密码解密失败: key_version_id=%s, err=%s", key_version_id, e)
            return None
```

- [ ] **Step 3: Remove zero-IV fallback from decrypt_with_work_key**

In `decrypt_with_work_key`, find and replace this block:

```python
        except Exception as e:
            try:
                iv = b'\x00' * 16
                actual_ciphertext = data
                sm4 = CryptSM4()
                sm4.set_key(work_key, SM4_DECRYPT)
                plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
                return plaintext.decode()
            except UnicodeDecodeError as e2:
                logger.error("[DECRYPT] decrypt_with_work_key - 兼容模式UTF-8解码失败: %s", e2)
                return None
            except Exception as e2:
                logger.error("[DECRYPT] decrypt_with_work_key - 解密失败(密文可能损坏): %s", e2)
                return None
```

With:

```python
        except Exception as e:
            logger.error("[DECRYPT] decrypt_with_work_key - 解密失败: %s", e)
            return None
```

- [ ] **Step 4: Verify all credentials still decrypt**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "
from app import app, db
from app.models import Credential
from app.services.crypto_service import CryptoService

with app.app_context():
    creds = Credential.query.all()
    failed = 0
    for c in creds:
        pwd = CryptoService.sm4_decrypt(c.encrypted_password, c.key_version)
        if pwd is None:
            failed += 1
        else:
            del pwd
    print(f'Total: {len(creds)}, Failed: {failed}')
    assert failed == 0, f'{failed} credentials failed!'
    print('OK')
"`

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/crypto_service.py
git commit -m "feat(crypto): remove zero-IV fallback, enforce standard format (D1)"
```

---

### Task 7: D2 — HMAC Standard Construction

**Files:**
- Modify: `backend/app/services/crypto_service.py`

- [ ] **Step 1: Add HMAC key derivation and version constants**

Add at the top of the `CryptoService` class (after `get_master_key`):

```python
    # SM4 密文格式版本
    FORMAT_V1 = 0x01  # 旧格式: SM3(work_key + payload)
    FORMAT_V2 = 0x02  # 新格式: SM3(hmac_key + iv + ciphertext), 独立 HMAC 子密钥

    @staticmethod
    def _derive_hmac_key(work_key):
        """从工作密钥派生独立的 HMAC 子密钥"""
        return bytes.fromhex(CryptoService.sm3_hash((work_key + b"hmac-derive").hex()))
```

- [ ] **Step 2: Update sm4_encrypt to use V2 format**

Replace the `sm4_encrypt` method:

```python
    @staticmethod
    def sm4_encrypt(plaintext):
        """使用工作密钥加密明文（SM4-CBC + SM3-HMAC V2）"""
        work_key, key_version = CryptoService.get_or_create_work_key()
        sm4 = CryptSM4()
        sm4.set_key(work_key, SM4_ENCRYPT)
        iv = os.urandom(16)
        ciphertext = sm4.crypt_cbc(iv, plaintext.encode())
        # V2 HMAC: SM3(hmac_key + iv + ciphertext)
        hmac_key = CryptoService._derive_hmac_key(work_key)
        hmac_input = hmac_key + iv + ciphertext
        hmac_hex = CryptoService.sm3_hash(hmac_input.hex())
        hmac_bytes = bytes.fromhex(hmac_hex)
        # Format: [version_byte(1)] + [iv(16)] + [ciphertext] + [hmac(32)]
        version_byte = bytes([CryptoService.FORMAT_V2])
        result = base64.b64encode(version_byte + iv + ciphertext + hmac_bytes).decode()
        return result, key_version
```

- [ ] **Step 3: Update sm4_decrypt to handle V1 and V2**

Replace the HMAC verification section in `sm4_decrypt` (the block starting with `# SM3-HMAC 认证` through the `try: iv = data[:16]` block). Find:

```python
        # SM3-HMAC 认证：验证密文完整性（encrypt-then-MAC）
        has_valid_hmac = False
        if len(data) >= 48:
            payload = data[:-32]
            stored_hmac = data[-32:].hex()
            expected_hmac = CryptoService.sm3_hash((work_key + payload).hex())
            import hmac as hmac_module
            if hmac_module.compare_digest(stored_hmac, expected_hmac):
                has_valid_hmac = True
                data = payload
            else:
                logger.warning("[DECRYPT] SM3-HMAC 认证失败，尝试兼容模式: key_version_id=%s", key_version_id)

        try:
            iv = data[:16]
            actual_ciphertext = data[16:]
        except IndexError as e:
            logger.error("[DECRYPT] 密文数据长度不足: key_version_id=%s, len=%d, %s",
                         key_version_id, len(data), e)
            return None

        try:
            sm4 = CryptSM4()
            sm4.set_key(work_key, SM4_DECRYPT)
            plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
            return plaintext.decode()
        except UnicodeDecodeError as e:
            logger.error("[DECRYPT] 解密结果UTF-8解码失败: key_version_id=%s, %s", key_version_id, e)
            return None
        except Exception as e:
            logger.error("[DECRYPT] 业务密码解密失败: key_version_id=%s, err=%s", key_version_id, e)
            return None
```

With:

```python
        # 检测格式版本
        import hmac as hmac_module
        if len(data) >= 49 and data[0] in (CryptoService.FORMAT_V1, CryptoService.FORMAT_V2):
            fmt_version = data[0]
            data = data[1:]  # 去掉版本字节
        else:
            # 无版本字节 → 旧格式 (V1)
            fmt_version = CryptoService.FORMAT_V1

        # SM3-HMAC 认证
        if len(data) >= 48:
            payload = data[:-32]
            stored_hmac = data[-32:].hex()

            if fmt_version == CryptoService.FORMAT_V2:
                # V2: SM3(hmac_key + iv + ciphertext)
                hmac_key = CryptoService._derive_hmac_key(work_key)
                expected_hmac = CryptoService.sm3_hash((hmac_key + payload).hex())
            else:
                # V1: SM3(work_key + payload)
                expected_hmac = CryptoService.sm3_hash((work_key + payload).hex())

            if hmac_module.compare_digest(stored_hmac, expected_hmac):
                data = payload
            else:
                logger.warning("[DECRYPT] SM3-HMAC 认证失败: key_version_id=%s, version=%s", key_version_id, fmt_version)
                return None
        else:
            logger.error("[DECRYPT] 密文数据过短: key_version_id=%s, len=%d", key_version_id, len(data))
            return None

        try:
            iv = data[:16]
            actual_ciphertext = data[16:]
        except IndexError as e:
            logger.error("[DECRYPT] 密文数据长度不足: key_version_id=%s, len=%d, %s",
                         key_version_id, len(data), e)
            return None

        try:
            sm4 = CryptSM4()
            sm4.set_key(work_key, SM4_DECRYPT)
            plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
            return plaintext.decode()
        except UnicodeDecodeError as e:
            logger.error("[DECRYPT] 解密结果UTF-8解码失败: key_version_id=%s, %s", key_version_id, e)
            return None
        except Exception as e:
            logger.error("[DECRYPT] 业务密码解密失败: key_version_id=%s, err=%s", key_version_id, e)
            return None
```

- [ ] **Step 4: Verify encrypt/decrypt round-trip with V2 format**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "
from app import app
from app.services.crypto_service import CryptoService

with app.app_context():
    # Test V2 encrypt/decrypt
    test_pwd = 'TestP@ssw0rd!'
    encrypted, kv = CryptoService.sm4_encrypt(test_pwd)
    decrypted = CryptoService.sm4_decrypt(encrypted, kv)
    assert decrypted == test_pwd, f'Round-trip failed: {decrypted} != {test_pwd}'
    # Verify V2 format (first byte should be 0x02)
    import base64
    raw = base64.b64decode(encrypted)
    assert raw[0] == 0x02, f'Expected V2 format (0x02), got 0x{raw[0]:02x}'
    print(f'V2 round-trip OK, format byte=0x{raw[0]:02x}')

    # Test that old V1 data still decrypts (backward compat)
    # Simulate V1: no version byte, SM3(work_key + payload)
    work_key, _ = CryptoService.get_or_create_work_key()
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    import os
    sm4 = CryptSM4()
    sm4.set_key(work_key, SM4_ENCRYPT)
    iv = os.urandom(16)
    ct = sm4.crypt_cbc(iv, test_pwd.encode())
    payload = iv + ct
    v1_hmac = bytes.fromhex(CryptoService.sm3_hash((work_key + payload).hex()))
    v1_encrypted = base64.b64encode(payload + v1_hmac).decode()
    v1_decrypted = CryptoService.sm4_decrypt(v1_encrypted, kv)
    assert v1_decrypted == test_pwd, f'V1 backward compat failed: {v1_decrypted}'
    print('V1 backward compatibility OK')
    print('ALL OK')
"`

Expected: `V2 round-trip OK` + `V1 backward compatibility OK` + `ALL OK`

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/crypto_service.py
git commit -m "feat(crypto): standardize HMAC construction with version format (D2)"
```

---

## Post-Implementation Verification

After all 7 tasks are complete:

- [ ] **Final integration test**

Run: `cd d:/PAM/pam-system/backend && SM2_PRIVATE_KEY_PASSWORD=mypam2026! python -c "
from app import app, db
from app.models import Credential
from app.services.crypto_service import CryptoService

with app.app_context():
    # 1. All credentials decrypt
    creds = Credential.query.all()
    ok = 0
    for c in creds:
        pwd = CryptoService.sm4_decrypt(c.encrypted_password, c.key_version)
        if pwd:
            ok += 1
            del pwd
    print(f'[1] Credentials: {ok}/{len(creds)} decrypt OK')

    # 2. New encryption uses V2
    enc, kv = CryptoService.sm4_encrypt('test')
    import base64
    raw = base64.b64decode(enc)
    assert raw[0] == 0x02, 'New encryption should be V2'
    print('[2] New encryption: V2 format OK')

    # 3. Health check has all fields
    with app.test_client() as c:
        r = c.get('/api/health')
        checks = r.get_json()['checks']
        assert 'redis' in checks, 'missing redis check'
        assert 'scheduler' in checks, 'missing scheduler check'
        assert 'recordings_dir' in checks, 'missing recordings_dir check'
        print(f'[3] Health check: {len(checks)} checks OK')

    print('ALL INTEGRATION TESTS PASSED')
"`

Expected: `ALL INTEGRATION TESTS PASSED`

- [ ] **Update CLAUDE.md**

Add P6 completion section to CLAUDE.md after section 4.8.
