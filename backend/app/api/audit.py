from flask import Blueprint, jsonify, request
from app.models import AuditLog
from app.services.crypto_service import CryptoService
from app.services.audit_service import lock_audit_logs, unlock_audit_logs, write_audit_log
from datetime import datetime
from app.utils.auth import token_required, role_required

audit_bp = Blueprint('audit', __name__, url_prefix='/api/audit')

@audit_bp.route('/logs', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_audit_logs():
    """
    获取审计日志列表
    """
    # 获取分页参数
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    log_type_filter = request.args.get('log_type', '')
    
    # 查询审计日志，按时间倒序排列，默认过滤已删除的记录
    query = AuditLog.query.filter_by(is_deleted=False)
    if log_type_filter:
        query = query.filter(AuditLog.log_type.like(f'{log_type_filter}%'))
    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    
    # 构建响应数据
    logs = []
    for log in pagination.items:
        logs.append({
            'id': log.id,
            'log_type': log.log_type,
            'operator': log.operator,
            'source_ip': log.source_ip,
            'target_asset': log.target_asset,
            'operation_detail': log.operation_detail,
            'result': log.result,
            'created_at': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'code': 200,
        'data': {
            'items': logs,
            'total': pagination.total
        }
    })

@audit_bp.route('/verify', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def verify_audit_logs():
    """
    验证审计日志的完整性（增强版：返回元数据支持前端可视化）
    """
    logs = AuditLog.query.order_by(AuditLog.id).all()
    total_logs = len(logs)
    latest_timestamp = logs[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if logs else None

    previous_hash = ''
    for log in logs:
        is_deleted = 1 if log.is_deleted else 0
        data_to_hash = f"{log.log_type}|{log.operator}|{log.source_ip}|{log.target_asset}|{log.operation_detail}|{log.result}|{log.timestamp}|{previous_hash}|{is_deleted}"
        calculated_hash = CryptoService.sm3_hash(data_to_hash)
        if calculated_hash != log.current_hash:
            return jsonify({
                'code': 200,
                'data': {
                    'valid': False,
                    'broken_at': log.id,
                    'total_logs': total_logs,
                    'latest_timestamp': latest_timestamp
                }
            })
        previous_hash = log.current_hash

    return jsonify({
        'code': 200,
        'data': {
            'valid': True,
            'broken_at': None,
            'total_logs': total_logs,
            'latest_timestamp': latest_timestamp
        }
    })

@audit_bp.route('/logs/<int:log_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_audit_log(log_id):
    """
    逻辑删除审计日志
    """
    log = AuditLog.query.get(log_id)
    if not log:
        return jsonify({
            'code': 404,
            'message': 'Log not found'
        }), 404

    if log.is_locked:
        return jsonify({'code': 403, 'message': '该审计日志已被锁定，无法删除'}), 403

    # 逻辑删除（设置is_deleted=True）
    log.is_deleted = True
    
    # 重新计算哈希链（从当前日志开始）
    # 首先获取所有日志，按ID顺序
    all_logs = AuditLog.query.order_by(AuditLog.id).all()
    
    # 找到当前日志的位置
    current_index = -1
    for i, l in enumerate(all_logs):
        if l.id == log_id:
            current_index = i
            break
    
    if current_index >= 0:
        # 重新计算从当前日志开始的哈希
        previous_hash = all_logs[current_index - 1].current_hash if current_index > 0 else ''
        
        for i in range(current_index, len(all_logs)):
            l = all_logs[i]
            # 拼接字符串（包含is_deleted字段）
            is_deleted = 1 if l.is_deleted else 0
            data_to_hash = f"{l.log_type}|{l.operator}|{l.source_ip}|{l.target_asset}|{l.operation_detail}|{l.result}|{l.timestamp}|{previous_hash}|{is_deleted}"
            
            # 计算哈希值
            current_hash = CryptoService.sm3_hash(data_to_hash)
            
            # 更新哈希值
            l.previous_hash = previous_hash
            l.current_hash = current_hash
            
            # 更新previous_hash
            previous_hash = current_hash
    
    # 保存到数据库
    from app import db
    db.session.commit()
    
    return jsonify({
        'code': 200,
        'message': 'Log deleted successfully'
    })

@audit_bp.route('/logs/deleted', methods=['GET'])
@token_required
@role_required('admin')
def get_deleted_audit_logs():
    """获取已删除的审计日志列表"""
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    query = AuditLog.query.filter_by(is_deleted=True)
    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    logs = [{
        'id': log.id,
        'log_type': log.log_type,
        'operator': log.operator,
        'source_ip': log.source_ip,
        'target_asset': log.target_asset,
        'operation_detail': log.operation_detail,
        'result': log.result,
        'created_at': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for log in pagination.items]
    return jsonify({
        'code': 200,
        'data': {'items': logs, 'total': pagination.total}
    })

@audit_bp.route('/logs/<int:log_id>/restore', methods=['POST'])
@token_required
@role_required('admin')
def restore_audit_log(log_id):
    """恢复单个审计日志"""
    log = AuditLog.query.get(log_id)
    if not log:
        return jsonify({'code': 404, 'message': 'Log not found'}), 404
    if log.is_locked:
        return jsonify({'code': 403, 'message': '该审计日志已被锁定，无法恢复'}), 403
    if not log.is_deleted:
        return jsonify({'code': 400, 'message': 'Log is not deleted'}), 400

    log.is_deleted = False
    all_logs = AuditLog.query.order_by(AuditLog.id).all()
    current_index = next((i for i, l in enumerate(all_logs) if l.id == log_id), -1)
    if current_index >= 0:
        prev_hash = all_logs[current_index - 1].current_hash if current_index > 0 else ''
        for i in range(current_index, len(all_logs)):
            l = all_logs[i]
            is_del = 1 if l.is_deleted else 0
            data = f"{l.log_type}|{l.operator}|{l.source_ip}|{l.target_asset}|{l.operation_detail}|{l.result}|{l.timestamp}|{prev_hash}|{is_del}"
            ch = CryptoService.sm3_hash(data)
            l.previous_hash = prev_hash
            l.current_hash = ch
            prev_hash = ch
    from app import db
    db.session.commit()
    return jsonify({'code': 200, 'message': 'Log restored successfully'})

@audit_bp.route('/logs/batch-restore', methods=['PUT'])
@token_required
@role_required('admin')
def batch_restore_audit_logs():
    """批量恢复审计日志"""
    data = request.get_json()
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'code': 400, 'message': 'No IDs provided'}), 400

    locked_ids = [l.id for l in AuditLog.query.filter(AuditLog.id.in_(ids), AuditLog.is_locked == True).all()]
    if locked_ids:
        return jsonify({'code': 403, 'message': f'以下审计日志已被锁定，无法恢复: {locked_ids}'}), 403

    logs = AuditLog.query.filter(AuditLog.id.in_(ids), AuditLog.is_deleted == True).all()
    for log in logs:
        log.is_deleted = False

    all_logs = AuditLog.query.order_by(AuditLog.id).all()
    prev_hash = ''
    for l in all_logs:
        is_del = 1 if l.is_deleted else 0
        data = f"{l.log_type}|{l.operator}|{l.source_ip}|{l.target_asset}|{l.operation_detail}|{l.result}|{l.timestamp}|{prev_hash}|{is_del}"
        ch = CryptoService.sm3_hash(data)
        l.previous_hash = prev_hash
        l.current_hash = ch
        prev_hash = ch
    from app import db
    db.session.commit()
    return jsonify({'code': 200, 'message': f'{len(logs)} logs restored successfully'})


@audit_bp.route('/lock', methods=['POST'])
@token_required
@role_required('admin', 'auditor')
def lock_audit_logs_route():
    """Lock audit logs in a range (auditor/admin). Locked logs become immutable."""
    data = request.get_json()
    start_id = data.get('start_id')
    end_id = data.get('end_id')
    if not start_id or not end_id:
        return jsonify({'code': 400, 'message': 'start_id and end_id are required'}), 400
    count = lock_audit_logs(int(start_id), int(end_id), operator=request.username)
    write_audit_log('audit_lock', operator=request.username,
                    source_ip=request.remote_addr or '127.0.0.1',
                    target_asset='system',
                    operation_detail=f'Locked {count} audit logs (IDs {start_id}-{end_id})',
                    result='success')
    return jsonify({'code': 200, 'message': f'{count} audit logs locked', 'data': {'locked_count': count}})


@audit_bp.route('/unlock', methods=['POST'])
@token_required
@role_required('admin')
def unlock_audit_logs_route():
    """Unlock audit logs (admin only)."""
    data = request.get_json()
    start_id = data.get('start_id')
    end_id = data.get('end_id')
    if not start_id or not end_id:
        return jsonify({'code': 400, 'message': 'start_id and end_id are required'}), 400
    count = unlock_audit_logs(int(start_id), int(end_id), operator=request.username)
    write_audit_log('audit_unlock', operator=request.username,
                    source_ip=request.remote_addr or '127.0.0.1',
                    target_asset='system',
                    operation_detail=f'Unlocked {count} audit logs (IDs {start_id}-{end_id})',
                    result='success')
    return jsonify({'code': 200, 'message': f'{count} audit logs unlocked', 'data': {'unlocked_count': count}})
