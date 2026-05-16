class AppException(Exception):
    status_code = 500
    default_message = "服务器内部错误"

    def __init__(self, message=None):
        super().__init__(message or self.default_message)
        self.message = message or self.default_message


class AuthException(AppException):
    status_code = 401
    default_message = "认证失败，请重新登录"


class PermissionException(AppException):
    status_code = 403
    default_message = "无此操作权限"


class NotFoundException(AppException):
    status_code = 404
    default_message = "请求的资源不存在"


class ValidationException(AppException):
    status_code = 422
    default_message = "请求参数校验失败"

    def __init__(self, message=None, errors=None):
        super().__init__(message)
        self.errors = errors or {}


class RateLimitException(AppException):
    status_code = 429
    default_message = "操作过于频繁，请稍后再试"
