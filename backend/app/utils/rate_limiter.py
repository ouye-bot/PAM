import time
import threading
from app.utils.logger import get_logger

logger = get_logger('app.utils.rate_limiter')

_records = {}
_lock = threading.Lock()


def _cleanup():
    now = time.time()
    expired_keys = []
    for key, record in _records.items():
        locked_until = record.get('locked_until')
        if locked_until and now >= locked_until:
            expired_keys.append(key)
            continue
        if now - record.get('window_start', 0) > record.get('window_seconds', 300):
            expired_keys.append(key)
    for k in expired_keys:
        del _records[k]
    if expired_keys:
        logger.debug(f"Rate limiter cleaned {len(expired_keys)} expired records")


def check_rate_limit(key_type, key_value, max_attempts, window_seconds=300, lock_seconds=900):
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


def clear_rate_limit(key_type, key_value):
    cache_key = f"{key_type}:{key_value}"
    with _lock:
        _records.pop(cache_key, None)
    logger.debug(f"Rate limit cleared for {cache_key}")


def get_lock_remaining(key_type, key_value):
    now = time.time()
    cache_key = f"{key_type}:{key_value}"
    with _lock:
        record = _records.get(cache_key)
        if record:
            locked_until = record.get('locked_until')
            if locked_until and now < locked_until:
                return int(locked_until - now)
    return 0


def start_cleanup_thread(interval=300):
    def _cleanup_loop():
        while True:
            time.sleep(interval)
            try:
                _cleanup()
            except Exception as e:
                logger.error(f"Rate limiter cleanup error: {e}", exc_info=True)

    t = threading.Thread(target=_cleanup_loop, daemon=True, name='rate-limiter-cleanup')
    t.start()
    logger.info("Rate limiter cleanup thread started (interval=%ds)", interval)


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
