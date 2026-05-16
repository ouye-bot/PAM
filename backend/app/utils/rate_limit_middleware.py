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
