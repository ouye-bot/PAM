from functools import wraps
from flask import request, jsonify
import jwt
import os
import json
import time
import base64
from app.utils.logger import get_logger

logger = get_logger('app.utils.auth')

# 导入SM2签名相关函数
from app.services.crypto_service import sm2_sign, sm2_verify

SECRET_KEY = os.getenv('JWT_SECRET')
if not SECRET_KEY:
    raise RuntimeError(
        "环境变量 JWT_SECRET 未配置，系统无法启动。\n"
        "请设置环境变量 JWT_SECRET，例如：\n"
        "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "并将输出的64位十六进制字符串设置为 JWT_SECRET 的值。"
    )
ALGORITHM = 'HS256'

def verify_token(token):
    """
    验证Token，兼容旧HS256 Token
    """
    # 1. 尝试SM2验签
    if token and '.' in token and len(token.split('.')) == 2:
        try:
            payload_b64, signature_b64 = token.split('.')
            # 解码签名
            signature = base64.urlsafe_b64decode(signature_b64 + '==').decode()
            # 验证签名
            if sm2_verify(payload_b64, signature):
                # 解码payload
                payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
                payload = json.loads(payload_json)
                # 检查过期时间
                if payload.get('exp', 0) >= time.time():
                    return payload
        except Exception:
            pass
    
    # 2. 降级为原有HMAC-SHA256 JWT验证
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        return None

def token_required(f):
    """
    JWT token验证装饰器
    用于保护需要认证的API接口
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({
                    'code': 401,
                    'message': 'Token格式无效'
                }), 401

        if not token:
            return jsonify({
                'code': 401,
                'message': '缺少认证Token'
            }), 401

        # 使用新的verify_token函数
        payload = verify_token(token)
        if not payload:
            return jsonify({
                'code': 401,
                'message': 'Token无效或已过期'
            }), 401

        # 注入用户信息到request对象
        request.user_id = payload.get('user_id')
        request.username = payload.get('username')
        request.role = payload.get('role')

        return f(*args, **kwargs)

    return decorated


def role_required(*allowed_roles):
    """
    角色权限验证装饰器
    检查用户角色是否在允许的角色列表中
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(request, 'role'):
                return jsonify({
                    'code': 401,
                    'message': '未认证'
                }), 401
            
            if request.role not in allowed_roles:
                return jsonify({
                    'code': 403,
                    'message': '权限不足'
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def generate_token(user_id, username, role='admin', login_ip=None):
    """
    生成SM2签名的Token
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': int(time.time()) + 86400  # 24小时
    }
    if login_ip:
        payload['login_ip'] = login_ip
    # 序列化payload
    payload_json = json.dumps(payload)
    # Base64 URL Safe编码
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
    # SM2签名
    signature = sm2_sign(payload_b64)
    # Base64 URL Safe编码签名
    signature_b64 = base64.urlsafe_b64encode(signature.encode()).decode().rstrip('=')
    # 组合Token
    return f"{payload_b64}.{signature_b64}"