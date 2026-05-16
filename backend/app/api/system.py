from flask import Blueprint, request, jsonify
from app import db
from app.models import SystemConfig
from app.utils.auth import token_required, role_required
from app.utils.logger import get_logger

logger = get_logger('app.api.system')

system_bp = Blueprint('system', __name__, url_prefix='/api/system')

@system_bp.route('/policy', methods=['GET'])
@token_required
def get_policy():
    """
    获取当前密码策略
    所有角色可访问
    """
    try:
        configs = SystemConfig.query.all()
        policy = {c.key: c.value for c in configs}
        data = {
            'min_length': int(policy.get('pwd_min_length', 16)),
            'require_upper': policy.get('pwd_require_upper', 'true').lower() == 'true',
            'require_lower': policy.get('pwd_require_lower', 'true').lower() == 'true',
            'require_digit': policy.get('pwd_require_digit', 'true').lower() == 'true',
            'require_special': policy.get('pwd_require_special', 'true').lower() == 'true',
            'special_chars': policy.get('pwd_special_chars') or '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        logger.info(f"[GET /api/system/policy] Returning policy data")
        return jsonify({
            'code': 200,
            'data': data
        })
    except Exception as e:
        logger.error(f"[GET /api/system/policy] Error: {str(e)}", exc_info=True)
        return jsonify({'code': 500, 'message': '操作失败，请稍后重试'}), 500

@system_bp.route('/policy', methods=['POST'])
@token_required
@role_required('admin')
def update_policy():
    """
    更新密码策略
    仅admin角色可访问
    """
    try:
        data = request.get_json()
        logger.info(f"[POST /api/system/policy] Policy update request received")
        if not data:
            return jsonify({'code': 400, 'message': 'No data provided'}), 400

        policy_keys = {
            'min_length': 'pwd_min_length',
            'require_upper': 'pwd_require_upper',
            'require_lower': 'pwd_require_lower',
            'require_digit': 'pwd_require_digit',
            'require_special': 'pwd_require_special',
            'special_chars': 'pwd_special_chars'
        }

        for key, db_key in policy_keys.items():
            if key in data:
                value = data[key]
                if isinstance(value, bool):
                    value = 'true' if value else 'false'
                elif isinstance(value, int):
                    value = str(value)

                config = SystemConfig.query.filter_by(key=db_key).first()
                if config:
                    config.value = value
                else:
                    config = SystemConfig(key=db_key, value=value)
                    db.session.add(config)

        db.session.commit()

        return jsonify({'code': 200, 'message': '策略已更新'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"[POST /api/system/policy] Error: {str(e)}", exc_info=True)
        return jsonify({'code': 500, 'message': '操作失败，请稍后重试'}), 500
