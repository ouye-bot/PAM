from flask import Blueprint, jsonify, request
from app.models import Asset, Credential
from app.services.crypto_service import CryptoService
from app.services.mysql_proxy import generate_token, validate_token, TOKEN_EXPIRY_SECONDS
import uuid
import time
from app.utils.auth import token_required

proxy_bp = Blueprint('proxy', __name__, url_prefix='/api/proxy')

@proxy_bp.route('/token', methods=['POST'])
@token_required
def create_token():
    """
    创建MySQL代理Token
    请求体: {"asset_id": 2}
    返回: {"code": 200, "token": "<uuid>", "expires_in": 300}
    """
    data = request.get_json()
    if not data or 'asset_id' not in data:
        return jsonify({
            'code': 400,
            'message': 'asset_id is required'
        }), 400

    asset_id = data['asset_id']

    # 获取资产信息
    asset = Asset.query.get(asset_id)
    if not asset:
        return jsonify({
            'code': 404,
            'message': 'Asset not found'
        }), 404

    # 获取凭证
    credential = Credential.query.filter_by(asset_id=asset_id).order_by(Credential.id.desc()).first()
    if not credential:
        return jsonify({
            'code': 404,
            'message': 'Credential not found for this asset'
        }), 404

    # 生成Token（存储加密密码，代理线程在连接时解密）
    token = generate_token(
        asset_id=asset.id,
        source_ip=request.remote_addr,
        username=credential.account_name,
        password=credential.encrypted_password,
        key_version=credential.key_version,
        host=asset.ip,
        port=asset.ssh_port
    )

    return jsonify({
        'code': 200,
        'message': 'Token generated successfully',
        'token': token,
        'expires_in': TOKEN_EXPIRY_SECONDS
    })

@proxy_bp.route('/token/validate', methods=['POST'])
def validate_token_api():
    """
    验证Token是否有效
    请求体: {"token": "<uuid>"}
    返回: {"code": 200, "valid": true/false}
    """
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({
            'code': 400,
            'message': 'token is required'
        }), 400

    token = data['token']
    token_info = validate_token(token)

    if token_info:
        remaining = int(token_info['expires_at'] - time.time())
        return jsonify({
            'code': 200,
            'valid': True,
            'remaining_seconds': remaining,
            'asset_id': token_info['asset_id']
        })
    else:
        return jsonify({
            'code': 200,
            'valid': False,
            'message': 'Token is invalid or expired'
        })

@proxy_bp.route('/detect', methods=['POST'])
@token_required
def detect_sql():
    """
    SQL安全检测已由代理在运行时自动强制执行，无需手动调用。
    """
    return jsonify({
        'code': 200,
        'message': 'SQL security check is automatically enforced by the proxy. All SQL is inspected during execution.'
    })

@proxy_bp.route('/status', methods=['GET'])
def get_proxy_status():
    """
    获取代理服务状态
    """
    from app.services.mysql_proxy import token_cache
    active_tokens = len(token_cache)

    return jsonify({
        'code': 200,
        'status': 'running',
        'active_tokens': active_tokens,
        'proxy_port': 3307
    })