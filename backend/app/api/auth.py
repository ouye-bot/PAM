import hashlib
from flask import Blueprint, request, jsonify, current_app
import os
import time
import uuid
import base64
import io
import pyotp
import qrcode
from app.utils.auth import generate_token, token_required
from app.utils.password import verify_password, hash_password
from app.utils.rate_limiter import clear_rate_limit
from app.models import User
from app import db
from app.services.crypto_service import CryptoService
from app.services.audit_service import write_audit_log

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# 临时Token存储（内存缓存）
_temp_tokens = {}
_sm2_challenges = {}
_sm2_verify_attempts = {}


def generate_temp_token(user_id, username):
    """生成临时Token"""
    temp_token = str(uuid.uuid4())
    _temp_tokens[temp_token] = {
        "user_id": user_id,
        "username": username,
        "expires_at": time.time() + 300
    }
    return temp_token


def verify_temp_token(temp_token):
    """验证临时Token并返回用户信息"""
    if temp_token not in _temp_tokens:
        return None
    token_data = _temp_tokens[temp_token]
    if time.time() > token_data['expires_at']:
        del _temp_tokens[temp_token]
        return None
    user_info = token_data.copy()
    del _temp_tokens[temp_token]
    return user_info


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
    """Verify a password-view temp token. Returns user_info or None. One-time use."""
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


def generate_sm2_challenge(user_id, client_ip):
    """生成SM2挑战码，返回 (sm2_token, challenge)"""
    nonce = os.urandom(16).hex()
    timestamp = int(time.time())
    user_hash = hashlib.sha3_256(f"uid:{user_id}".encode()).hexdigest()[:16]
    ip_hash = hashlib.sha3_256(f"ip:{client_ip}".encode()).hexdigest()[:16]
    challenge = f"{nonce}:{timestamp}:{user_hash}:{ip_hash}"
    sm2_token = str(uuid.uuid4())
    _sm2_challenges[sm2_token] = {
        "user_id": user_id,
        "client_ip": client_ip,
        "challenge": challenge,
        "expires_at": time.time() + 300
    }
    return sm2_token, challenge


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'code': 400, 'message': '请求数据无效'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'code': 400, 'message': '用户名和密码不能为空'}), 400

    client_ip = request.remote_addr or '127.0.0.1'

    user = User.query.filter_by(username=username).first()

    if not user or not verify_password(password, user.password):
        # Rate limiting for failed logins is handled globally by rate_limit_middleware
        return jsonify({'code': 401, 'message': '用户名或密码错误'}), 401



    sm2_available = data.get('sm2_available', False)
    sm2_token = data.get('sm2_token', '')
    sm2_signature = data.get('signature', '')

    if user.sm2_public_key:
        if not sm2_available:
            write_audit_log('SM2_LOGIN_MISSING', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='当前设备未绑定SM2私钥', result='failed')
            return jsonify({'code': 401, 'message': "当前设备未绑定SM2私钥，请选择'设备丢失/重新绑定'"}), 401

        if not sm2_token or not sm2_signature:
            sm2_token_new, challenge = generate_sm2_challenge(user.id, client_ip)
            return jsonify({
                'code': 200,
                'require_sm2': True,
                'sm2_token': sm2_token_new,
                'challenge': challenge
            })

        challenge_info = _sm2_challenges.pop(sm2_token, None)
        if not challenge_info:
            return jsonify({'code': 401, 'message': 'SM2验证会话已过期，请重新登录'}), 401

        if challenge_info['client_ip'] != client_ip:
            write_audit_log('SM2_LOGIN_FAIL', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='SM2验签失败：IP不匹配', result='failed')
            return jsonify({'code': 401, 'message': 'SM2验证失败：IP不匹配'}), 401

        if time.time() > challenge_info['expires_at']:
            write_audit_log('SM2_LOGIN_FAIL', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='SM2验签失败：挑战码过期', result='failed')
            return jsonify({'code': 401, 'message': 'SM2验证已过期，请重新登录'}), 401

        challenge = challenge_info['challenge']
        valid = CryptoService.sm2_verify_with_public_key(challenge, sm2_signature, user.sm2_public_key)
        if not valid:
            write_audit_log('SM2_LOGIN_FAIL', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='SM2验签失败：签名验证不通过', result='failed')
            return jsonify({'code': 401, 'message': 'SM2验证失败'}), 401

        write_audit_log('SM2_LOGIN_SUCCESS', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='SM2静默认证通过', result='success')
    else:
        # 首次登录：自动生成 SM2 密钥对，用登录密码加密私钥
        sm2_auto_generated = False
        encrypted_private_key = None

        try:
            from gmssl import sm2 as gmssl_sm2, func
            from app.services.crypto_service import CryptoService

            # 生成 SM2 密钥对（使用密码学安全随机数）
            from app.services.crypto_service import secure_random_hex
            private_key_hex = secure_random_hex(32)
            sm2_crypt = gmssl_sm2.CryptSM2(private_key=private_key_hex, public_key='')
            public_key_hex = sm2_crypt._kg(int(private_key_hex, 16), gmssl_sm2.default_ecc_table['g'])

            # 用登录密码派生加密密钥 (PBKDF2 → SM4加密私钥)
            from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
            salt = os.urandom(16)
            derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            iv = os.urandom(16)
            sm4_cipher = CryptSM4()
            sm4_cipher.set_key(derived, SM4_ENCRYPT)
            ciphertext = sm4_cipher.crypt_cbc(iv, private_key_hex.encode())
            encrypted_key = salt + iv + ciphertext

            # 保存公钥
            user.sm2_public_key = public_key_hex
            db.session.commit()

            encrypted_private_key = base64.b64encode(encrypted_key).decode('utf-8')
            sm2_auto_generated = True
            write_audit_log('SM2_KEY_AUTO_GENERATED', operator=user.username, source_ip=client_ip,
                          target_asset='login', operation_detail='首次登录自动生成SM2密钥对', result='success')
        except Exception as e:
            write_audit_log('SM2_KEY_AUTO_GEN_FAILED', operator=user.username, source_ip=client_ip,
                          target_asset='login', operation_detail=f'SM2自动生成失败: {str(e)[:100]}', result='failed')

    if user.totp_enabled:
        temp_token = generate_temp_token(user.id, user.username)
        resp = {
            'code': 200,
            'require_mfa': True,
            'temp_token': temp_token
        }
        if sm2_auto_generated:
            resp['sm2_auto_configured'] = True
            resp['encrypted_private_key'] = encrypted_private_key
        return jsonify(resp)
    else:
        token = generate_token(user.id, user.username, user.role, login_ip=client_ip)
        resp = {
            'code': 200,
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'totp_enabled': user.totp_enabled,
                'sm2_configured': bool(user.sm2_public_key)
            }
        }
        if sm2_auto_generated:
            resp['sm2_auto_configured'] = True
            resp['encrypted_private_key'] = encrypted_private_key
        return jsonify(resp)


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    用户登出接口
    前端清除 Token 即可，后端无需特殊处理
    """
    return jsonify({
        'code': 200,
        'message': '登出成功'
    })


@auth_bp.route('/verify', methods=['GET'])
def verify_token():
    """
    验证 Token 是否有效
    """
    from flask import request, jsonify
    
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
    from app.utils.auth import verify_token as verify_token_func
    payload = verify_token_func(token)
    
    if not payload:
        return jsonify({
            'code': 401,
            'message': 'Token无效或已过期'
        }), 401

    # 获取用户完整信息
    user = User.query.get(payload.get('user_id'))
    if not user:
        return jsonify({
            'code': 404,
            'message': '用户不存在'
        }), 404

    return jsonify({
        'code': 200,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'totp_enabled': user.totp_enabled
        }
    })


@auth_bp.route('/mfa/setup', methods=['GET'])
@token_required
def mfa_setup():
    """
    MFA设置接口
    生成TOTP密钥和二维码
    """
    # 从request获取用户ID
    user_id = request.user_id
    current_app.logger.info(f"MFA setup requested for user_id={user_id}")
    
    user = User.query.get(user_id)
    
    if not user:
        current_app.logger.warning(f"User not found for user_id={user_id}")
        return jsonify({
            'code': 404,
            'message': '用户不存在'
        }), 404
    
    # 即使已启用MFA，也允许重新生成密钥（便于用户换绑）
    # 生成随机密钥
    secret = pyotp.random_base32()
    
    # 保存密钥到用户记录
    user.totp_secret = secret
    # 注意：不修改totp_enabled状态，保持不变
    db.session.commit()
    
    # 生成provisioning URI
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.username, 
        issuer_name='PAM'
    )
    
    # 生成QR码图片
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 转换为base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    qr_base64 = f"data:image/png;base64,{img_str}"
    
    return jsonify({
        'code': 200,
        'secret': secret,
        'qr_url': uri,
        'qr_base64': qr_base64
    })


@auth_bp.route('/mfa/verify', methods=['POST'])
@token_required
def mfa_verify():
    """
    MFA验证接口
    验证动态码并启用MFA
    """
    # 从request获取用户ID
    user_id = request.user_id
    current_app.logger.info(f"MFA verify requested for user_id={user_id}")
    
    user = User.query.get(user_id)
    
    if not user:
        current_app.logger.warning(f"User not found for user_id={user_id}")
        return jsonify({
            'code': 404,
            'message': '用户不存在'
        }), 404
    
    data = request.get_json()
    code = data.get('code')
    
    if not code or len(code) != 6:
        return jsonify({
            'code': 400,
            'message': '动态码格式无效'
        }), 400
    
    # 验证动态码
    if not user.totp_secret:
        return jsonify({
            'code': 400,
            'message': 'MFA未初始化'
        }), 400
    
    totp = pyotp.TOTP(user.totp_secret)
    # 添加时间窗口容差，允许前后2个窗口（共±1分钟）
    if not totp.verify(code, valid_window=2):
        return jsonify({
            'code': 401,
            'message': '动态码错误'
        }), 401
    
    # 启用MFA（如果尚未启用）
    if not user.totp_enabled:
        user.totp_enabled = True
        db.session.commit()
        message = 'MFA enabled successfully'
    else:
        # 已启用MFA的用户重新验证，更新密钥
        message = 'MFA re-verified successfully'
    
    return jsonify({
        'code': 200,
        'message': message
    })


@auth_bp.route('/mfa/login', methods=['POST'])
def mfa_login():
    """
    MFA登录接口
    验证临时Token和动态码
    """
    data = request.get_json()
    temp_token = data.get('temp_token')
    code = data.get('code')
    
    current_app.logger.info(f"MFA login requested with temp_token={temp_token[:8]}...")
    
    if not temp_token or not code:
        current_app.logger.warning("Missing temp_token or code")
        return jsonify({
            'code': 400,
            'message': '参数缺失'
        }), 400
    
    # 验证临时Token
    user_info = verify_temp_token(temp_token)
    if not user_info:
        return jsonify({
            'code': 401,
            'message': '验证码已过期，请重新登录'
        }), 401
    
    # 获取用户
    user = User.query.get(user_info['user_id'])
    if not user or not user.totp_enabled:
        return jsonify({
            'code': 401,
            'message': '用户MFA未启用'
        }), 401
    
    # 验证动态码
    totp = pyotp.TOTP(user.totp_secret)
    # 添加时间窗口容差，允许前后2个窗口（共±1分钟）
    if not totp.verify(code, valid_window=2):
        return jsonify({
            'code': 401,
            'message': '动态码错误'
        }), 401
    
    # 生成正式JWT Token
    token = generate_token(user.id, user.username, user.role, login_ip=request.remote_addr)
    
    # 构建响应
    response_data = {
        'code': 200,
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'totp_enabled': user.totp_enabled
        }
    }
    
    current_app.logger.info(f"MFA login successful for user={user.username}")
    return jsonify(response_data)


@auth_bp.route('/sm2/verify', methods=['POST'])
def sm2_verify():
    """SM2验签端点"""
    data = request.get_json()
    sm2_token = data.get('sm2_token', '')
    signature = data.get('signature', '')
    client_ip = request.remote_addr or '127.0.0.1'

    attempt_key = f"sm2_verify:{client_ip}"
    now = int(time.time())
    window_start = now - 60
    _sm2_verify_attempts[attempt_key] = [t for t in _sm2_verify_attempts.get(attempt_key, []) if t > window_start]
    if len(_sm2_verify_attempts.get(attempt_key, [])) >= 5:
        return jsonify({'code': 429, 'message': '请求过于频繁，请稍后重试'}), 429
    _sm2_verify_attempts.setdefault(attempt_key, []).append(now)

    if not sm2_token or not signature:
        return jsonify({'code': 400, 'message': '参数缺失'}), 400

    challenge_info = _sm2_challenges.pop(sm2_token, None)
    if not challenge_info:
        return jsonify({'code': 401, 'message': '验证会话已过期或已使用'}), 401

    if challenge_info['client_ip'] != client_ip:
        return jsonify({'code': 401, 'message': 'IP不匹配'}), 401

    if time.time() > challenge_info['expires_at']:
        return jsonify({'code': 401, 'message': '验证已过期'}), 401

    user = User.query.get(challenge_info['user_id'])
    if not user or not user.sm2_public_key:
        return jsonify({'code': 401, 'message': '用户未配置SM2密钥'}), 401

    valid = CryptoService.sm2_verify_with_public_key(challenge_info['challenge'], signature, user.sm2_public_key)
    if not valid:
        write_audit_log('SM2_LOGIN_FAIL', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='SM2验签失败', result='failed')
        return jsonify({'code': 401, 'message': 'SM2验证失败'}), 401

    write_audit_log('SM2_LOGIN_SUCCESS', operator=user.username, source_ip=client_ip, target_asset='login', operation_detail='SM2认证通过', result='success')

    if user.totp_enabled:
        temp_token = generate_temp_token(user.id, user.username)
        return jsonify({
            'code': 200,
            'require_mfa': True,
            'temp_token': temp_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'totp_enabled': user.totp_enabled
            }
        })
    else:
        token = generate_token(user.id, user.username, user.role, login_ip=client_ip)
        return jsonify({
            'code': 200,
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'totp_enabled': user.totp_enabled
            }
        })


@auth_bp.route('/sm2/reset', methods=['POST'])
def sm2_reset():
    """SM2密钥重置（设备丢失）"""
    data = request.get_json()
    username = data.get('username', '')
    recovery_code = data.get('recovery_code', '')

    if not username or not recovery_code:
        return jsonify({'code': 400, 'message': '参数缺失'}), 400

    client_ip = request.remote_addr or '127.0.0.1'
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    if not user.sm2_recovery_hashes:
        return jsonify({'code': 400, 'message': '未找到恢复码'}), 400

    matched = False
    remaining = []
    for stored_hash in user.sm2_recovery_hashes:
        from app.utils.password import verify_password
        if verify_password(recovery_code, stored_hash):
            matched = True
        else:
            remaining.append(stored_hash)

    if not matched:
        write_audit_log('SM2_KEY_RESET', operator=username, source_ip=client_ip, target_asset='login', operation_detail='恢复码验证失败', result='failed')
        return jsonify({'code': 401, 'message': '恢复码无效'}), 401

    user.sm2_public_key = None
    user.sm2_recovery_hashes = remaining if remaining else None
    db.session.commit()
    write_audit_log('SM2_KEY_RESET', operator=username, source_ip=client_ip, target_asset='login', operation_detail='SM2密钥已重置', result='success')
    return jsonify({'code': 200, 'message': 'SM2密钥已重置，请重新登录后配置新的密钥对'})


@auth_bp.route('/verify-password', methods=['POST'])
@token_required
def verify_password_endpoint():
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({'code': 400, 'message': '密码不能为空'}), 400
    
    user_id = request.user_id
    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404
    
    if verify_password(password, user.password):
        return jsonify({'code': 200, 'valid': True})
    else:
        return jsonify({'code': 200, 'valid': False})


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