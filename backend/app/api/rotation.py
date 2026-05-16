from flask import Blueprint, jsonify, request
from datetime import datetime
from app.services.password_rotation import rotate_password
from app.models import RotationTask, Credential, Asset
from app.utils.auth import token_required, role_required
from app.utils.logger import get_logger

logger = get_logger('app.api.rotation')

rotation_bp = Blueprint('rotation', __name__, url_prefix='/api/rotation')

@rotation_bp.route('/trigger/<int:asset_id>', methods=['POST'])
@token_required
@role_required('admin', 'operator')
def trigger_rotation(asset_id):
    """
    触发密码改密
    """
    try:
        logger.info(f"[ROTATION API] Triggering rotation for asset_id: {asset_id}")
        rotate_password(asset_id, operator=request.username)

        logger.info(f"[ROTATION API] Rotation successful for asset_id: {asset_id}")
        return jsonify({
            "code": 200,
            "message": "Rotation completed successfully",
            "data": {}
        })
    except Exception as e:
        logger.error(f"[ROTATION API] Rotation failed for asset_id: {asset_id}", exc_info=True)
        return jsonify({
            "code": 500,
            "message": f"Rotation failed: {str(e)}"
        }), 500

@rotation_bp.route('/history/<int:asset_id>', methods=['GET'])
@token_required
@role_required('admin', 'operator')
def get_rotation_history(asset_id):
    """
    获取资产的改密历史
    """
    try:
        credentials = Credential.query.filter_by(asset_id=asset_id).all()
        credential_ids = [cred.id for cred in credentials]

        rotation_tasks = RotationTask.query.filter(
            RotationTask.credential_id.in_(credential_ids)
        ).order_by(RotationTask.executed_at.desc()).all()

        history = []
        for task in rotation_tasks:
            executed_at_str = task.executed_at.strftime('%Y-%m-%d %H:%M:%S') if task.executed_at else None

            history.append({
                "id": task.id,
                "credential_id": task.credential_id,
                "account_name": task.credential.account_name if task.credential else '已删除',
                "executed_at": executed_at_str,
                "status": task.status,
                "error_msg": task.error_msg,
                "new_password_hash": task.new_password_hash
            })

        return jsonify({
            "code": 200,
            "message": "Success",
            "data": history
        })
    except Exception as e:
        return jsonify({
            "code": 500,
            "message": f"Failed to get rotation history: {str(e)}"
        }), 500


@rotation_bp.route('/schedules', methods=['GET'])
@token_required
@role_required('admin')
def get_schedules():
    """获取所有定时改密调度配置"""
    try:
        from app.scheduler import get_all_schedules
        schedules = get_all_schedules()
        return jsonify({
            "code": 200,
            "data": schedules
        })
    except Exception as e:
        logger.error(f"[SCHEDULE API] Get schedules failed: {str(e)}")
        return jsonify({"code": 500, "message": str(e)}), 500


@rotation_bp.route('/schedules', methods=['POST'])
@token_required
@role_required('admin')
def create_schedule():
    """创建定时改密调度"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"code": 400, "message": "No data provided"}), 400

        name = data.get('name', '').strip()
        if not name:
            return jsonify({"code": 400, "message": "调度名称不能为空"}), 400

        cron = data.get('cron', '').strip()
        parts = cron.split()
        if len(parts) != 5:
            return jsonify({"code": 400, "message": "cron表达式格式错误（需5段：分 时 日 月 周）"}), 400

        asset_ids = data.get('asset_ids', [])
        asset_types = data.get('asset_types', [])
        enabled = data.get('enabled', True)

        from app.scheduler import add_schedule
        result = add_schedule(name, asset_ids, asset_types, cron, enabled)
        return jsonify({"code": 200, "message": "调度创建成功", "data": result})
    except Exception as e:
        logger.error(f"[SCHEDULE API] Create schedule failed: {str(e)}")
        return jsonify({"code": 500, "message": str(e)}), 500


@rotation_bp.route('/schedules/<schedule_id>', methods=['PUT'])
@token_required
@role_required('admin')
def update_schedule(schedule_id):
    """更新定时改密调度"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"code": 400, "message": "No data provided"}), 400

        updates = {}
        if 'name' in data:
            updates['name'] = data['name'].strip()
        if 'asset_ids' in data:
            updates['asset_ids'] = data['asset_ids']
        if 'asset_types' in data:
            updates['asset_types'] = data['asset_types']
        if 'cron' in data:
            parts = data['cron'].strip().split()
            if len(parts) != 5:
                return jsonify({"code": 400, "message": "cron表达式格式错误"}), 400
            updates['cron'] = data['cron'].strip()
        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])

        from app.scheduler import update_schedule as do_update
        result = do_update(schedule_id, updates)
        if result is None:
            return jsonify({"code": 404, "message": "调度不存在"}), 404
        return jsonify({"code": 200, "message": "调度更新成功", "data": result})
    except Exception as e:
        logger.error(f"[SCHEDULE API] Update schedule failed: {str(e)}")
        return jsonify({"code": 500, "message": str(e)}), 500


@rotation_bp.route('/schedules/<schedule_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_schedule(schedule_id):
    """删除定时改密调度"""
    try:
        from app.scheduler import delete_schedule as do_delete
        success = do_delete(schedule_id)
        if not success:
            return jsonify({"code": 404, "message": "调度不存在"}), 404
        return jsonify({"code": 200, "message": "调度已删除"})
    except Exception as e:
        logger.error(f"[SCHEDULE API] Delete schedule failed: {str(e)}")
        return jsonify({"code": 500, "message": str(e)}), 500


@rotation_bp.route('/schedules/asset-options', methods=['GET'])
@token_required
@role_required('admin')
def get_asset_options():
    """获取可用资产列表（供调度配置选择器使用）"""
    try:
        assets = Asset.query.filter_by(status='active').all()
        options = [{
            "id": a.id,
            "ip": a.ip,
            "hostname": a.hostname,
            "os_type": a.os_type,
            "label": f"{a.ip}:{a.ssh_port} ({a.get_display_os_type()})"
        } for a in assets]
        return jsonify({"code": 200, "data": options})
    except Exception as e:
        return jsonify({"code": 500, "message": str(e)}), 500
