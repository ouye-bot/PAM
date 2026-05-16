from flask import Blueprint, request, jsonify
from app import db
from app.models import User
from app.utils.auth import token_required, role_required
from app.utils.password import hash_password
from app.utils.logger import get_logger
from app.services.audit_service import write_audit_log

users_bp = Blueprint('users', __name__, url_prefix='/api/users')
me_bp = Blueprint('me', __name__, url_prefix='/api/me')
logger = get_logger('app.api.users')

ALLOWED_ROLES = ['admin', 'operator', 'auditor']

def _safe_user(user):
    return {
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'totp_enabled': user.totp_enabled,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else None,
        'updated_at': user.updated_at.strftime('%Y-%m-%d %H:%M:%S') if user.updated_at else None
    }


@users_bp.route('', methods=['POST'])
@token_required
@role_required('admin')
def create_user():
    data = request.get_json()
    if not data:
        return jsonify({'code': 400, 'message': '请求数据无效'}), 400

    username = (data.get('username') or '').strip()
    password = data.get('password')
    role = data.get('role', 'operator')

    if not username or len(username) < 3 or len(username) > 32:
        return jsonify({'code': 422, 'message': '用户名长度需为3-32个字符'}), 422

    if not password or len(password) < 8:
        return jsonify({'code': 422, 'message': '密码长度不能少于8位'}), 422

    if role not in ALLOWED_ROLES:
        return jsonify({'code': 422, 'message': f'角色必须是 {", ".join(ALLOWED_ROLES)}'}), 422

    existing = User.query.filter_by(username=username).first()
    if existing:
        return jsonify({'code': 409, 'message': '用户名已存在'}), 409

    user = User(
        username=username,
        password=hash_password(password),
        role=role
    )
    db.session.add(user)
    db.session.commit()

    logger.info("Admin %s created user %s (role=%s)", request.username, username, role)
    write_audit_log('user_management', request.username, request.remote_addr or '127.0.0.1',
                    'System', f'创建用户: {username}', 'success')

    return jsonify({'code': 200, 'message': '用户创建成功', 'data': _safe_user(user)}), 200


@users_bp.route('', methods=['GET'])
@token_required
@role_required('admin')
def list_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)

    query = User.query.order_by(User.id.asc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'code': 200,
        'data': [_safe_user(u) for u in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page
    }), 200


@users_bp.route('/<int:user_id>', methods=['GET'])
@token_required
@role_required('admin')
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    return jsonify({'code': 200, 'data': _safe_user(user)}), 200


@users_bp.route('/<int:user_id>', methods=['PUT'])
@token_required
@role_required('admin')
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'code': 400, 'message': '请求数据无效'}), 400

    changed = []

    if 'username' in data:
        new_username = (data['username'] or '').strip()
        if len(new_username) < 3 or len(new_username) > 32:
            return jsonify({'code': 422, 'message': '用户名长度需为3-32个字符'}), 422
        existing = User.query.filter_by(username=new_username).first()
        if existing and existing.id != user_id:
            return jsonify({'code': 409, 'message': '用户名已存在'}), 409
        user.username = new_username
        changed.append('用户名')

    if 'role' in data:
        if data['role'] not in ALLOWED_ROLES:
            return jsonify({'code': 422, 'message': f'角色必须是 {", ".join(ALLOWED_ROLES)}'}), 422
        user.role = data['role']
        changed.append('角色')

    db.session.commit()
    logger.info("Admin %s updated user %s: %s", request.username, user.username, ', '.join(changed))
    write_audit_log('user_management', request.username, request.remote_addr or '127.0.0.1',
                    'System', f'修改用户: {user.username} ({", ".join(changed)})', 'success')

    return jsonify({'code': 200, 'message': '用户更新成功', 'data': _safe_user(user)}), 200


@users_bp.route('/<int:user_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_user(user_id):
    if user_id == request.user_id:
        return jsonify({'code': 400, 'message': '不能删除自己'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    username = user.username
    db.session.delete(user)
    db.session.commit()

    logger.info("Admin %s deleted user %s", request.username, username)
    write_audit_log('user_management', request.username, request.remote_addr or '127.0.0.1',
                    'System', f'删除用户: {username}', 'success')

    return jsonify({'code': 200, 'message': '用户已删除'}), 200


@users_bp.route('/<int:user_id>/password', methods=['PUT'])
@token_required
@role_required('admin')
def reset_password(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    data = request.get_json()
    if not data or not data.get('new_password'):
        return jsonify({'code': 400, 'message': '新密码不能为空'}), 400

    new_password = data['new_password']
    if len(new_password) < 8:
        return jsonify({'code': 422, 'message': '密码长度不能少于8位'}), 422

    user.password = hash_password(new_password)
    user.token_version = (user.token_version or 0) + 1
    db.session.commit()

    logger.info("Admin %s reset password for user %s", request.username, user.username)
    write_audit_log('password_reset', request.username, request.remote_addr or '127.0.0.1',
                    'System', f'重置用户密码: {user.username}', 'success')

    return jsonify({'code': 200, 'message': '密码重置成功'}), 200


@me_bp.route('/password', methods=['PUT'])
@token_required
def change_own_password():
    data = request.get_json()
    if not data:
        return jsonify({'code': 400, 'message': '请求数据无效'}), 400

    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'code': 400, 'message': '旧密码和新密码不能为空'}), 400

    if len(new_password) < 8:
        return jsonify({'code': 422, 'message': '新密码长度不能少于8位'}), 422

    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    from app.utils.password import verify_password
    if not verify_password(old_password, user.password):
        return jsonify({'code': 400, 'message': '旧密码错误'}), 400

    user.password = hash_password(new_password)
    user.token_version = (user.token_version or 0) + 1
    db.session.commit()

    logger.info("User %s changed own password", request.username)
    write_audit_log('password_change', request.username, request.remote_addr or '127.0.0.1',
                    'System', '修改自己的密码', 'success')

    return jsonify({'code': 200, 'message': '密码修改成功'}), 200


@me_bp.route('/sm2-key', methods=['PUT'])
@token_required
def upload_sm2_public_key():
    data = request.get_json()
    if not data or not data.get('public_key'):
        return jsonify({'code': 400, 'message': 'public_key is required'}), 400

    public_key = data['public_key'].strip()

    import base64
    try:
        decoded = base64.b64decode(public_key)
    except Exception:
        return jsonify({'code': 422, 'message': '公钥格式无效：不是有效的Base64编码'}), 422

    if len(decoded) != 64:
        return jsonify({'code': 422, 'message': f'公钥格式无效：解码后长度为{len(decoded)}字节，期望64字节'}), 422

    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    user.sm2_public_key = public_key
    db.session.commit()

    logger.info("User %s uploaded SM2 public key", request.username)
    write_audit_log('SM2_KEY_UPLOAD', request.username, request.remote_addr or '127.0.0.1',
                    'System', '上传SM2公钥', 'success')

    return jsonify({'code': 200, 'message': 'SM2公钥上传成功'}), 200


@me_bp.route('/sm2-key', methods=['GET'])
@token_required
def get_own_sm2_public_key():
    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    return jsonify({'code': 200, 'data': {'public_key': user.sm2_public_key}}), 200


@me_bp.route('/sm2-recovery-codes', methods=['POST'])
@token_required
def upload_sm2_recovery_codes():
    """上传SM2恢复码的bcrypt哈希"""
    data = request.get_json()
    if not data or 'recovery_hashes' not in data:
        return jsonify({'code': 400, 'message': '缺少recovery_hashes参数'}), 400

    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    user.sm2_recovery_hashes = data['recovery_hashes']
    db.session.commit()

    write_audit_log('SM2_RECOVERY_UPLOAD', operator=user.username,
                    source_ip=request.remote_addr or 'unknown', target_asset='user',
                    operation_detail='SM2恢复码已更新', result='success')
    return jsonify({'code': 200, 'message': '恢复码已保存'})


@users_bp.route('/<int:user_id>/sm2-key', methods=['GET'])
@token_required
@role_required('admin')
def get_user_sm2_public_key(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404

    return jsonify({'code': 200, 'data': {'user_id': user.id, 'username': user.username, 'public_key': user.sm2_public_key}}), 200
