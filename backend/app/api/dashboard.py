from flask import Blueprint, jsonify
from datetime import datetime, date, timedelta
from app.models import Asset, RotationTask, AuditLog, Credential
from app.utils.auth import token_required, role_required
from app.utils.logger import get_logger
from sqlalchemy import func
from app import db

logger = get_logger('app.api.dashboard')

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

@dashboard_bp.route('/stats', methods=['GET'])
@token_required
@role_required('admin', 'operator', 'auditor')
def get_dashboard_stats():
    """
    获取仪表盘统计数据
    """
    try:
        # 1. 资产总数（活跃资产）
        total_assets = Asset.query.filter(Asset.status == 'active').count()
        
        # 2. 今日改密成功数
        today = date.today()
        today_rotations = RotationTask.query.filter(
            RotationTask.status == 'success',
            RotationTask.executed_at >= datetime.combine(today, datetime.min.time())
        ).count()
        
        # 3. 待执行改密数（如果有相关状态）
        rotation_pending = RotationTask.query.filter(
            RotationTask.status == 'pending'
        ).count()
        
        # 4. 绕行告警总数
        total_bypass_alerts = AuditLog.query.filter(
            AuditLog.log_type == 'bypass_detected'
        ).count()
        
        # 5. 弱口令资产数（简单实现：这里假设所有资产都有凭证）
        # 实际项目中可能需要更复杂的弱口令检测逻辑
        weak_password_assets = 0
        
        # 6. 今日高危操作拦截数
        today_sql_blocks = AuditLog.query.filter(
            AuditLog.log_type == 'sql_block',
            AuditLog.timestamp >= datetime.combine(today, datetime.min.time())
        ).count()
        
        # 7. 最后改密时间
        last_rotation = RotationTask.query.filter(
            RotationTask.status == 'success'
        ).order_by(RotationTask.executed_at.desc()).first()
        last_rotation_time = last_rotation.executed_at.strftime('%Y-%m-%d %H:%M:%S') if last_rotation else '暂无'
        
        # 8. 最近的绕行告警
        recent_alerts = AuditLog.query.filter(
            AuditLog.log_type == 'bypass_detected'
        ).order_by(AuditLog.timestamp.desc()).limit(10).all()
        
        bypass_alerts = []
        for alert in recent_alerts:
            bypass_alerts.append({
                'id': alert.id,
                'message': alert.operation_detail,
                'asset': alert.target_asset,
                'time': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': alert.source_ip
            })
        
        # 9. 最近的系统通知
        recent_notices = AuditLog.query.filter(
            AuditLog.log_type == 'system_notice'
        ).order_by(AuditLog.timestamp.desc()).limit(5).all()
        
        system_notices = []
        for notice in recent_notices:
            system_notices.append({
                'id': notice.id,
                'message': notice.operation_detail,
                'time': notice.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        # 10. 资产类型分布
        asset_types = db.session.query(
            Asset.os_type,
            func.count(Asset.id)
        ).filter(
            Asset.status == 'active'
        ).group_by(
            Asset.os_type
        ).all()
        
        asset_type_distribution = []
        for os_type, count in asset_types:
            asset_type_distribution.append({
                'type': os_type,
                'count': count
            })
        
        return jsonify({
            'code': 200,
            'data': {
                'total_assets': total_assets,
                'today_rotations': today_rotations,
                'rotation_pending': rotation_pending,
                'bypass_alerts_count': total_bypass_alerts,
                'weak_password_assets': weak_password_assets,
                'sql_blocks': today_sql_blocks,
                'last_rotation_time': last_rotation_time,
                'bypass_alerts': bypass_alerts,
                'system_notices': system_notices,
                'asset_type_distribution': asset_type_distribution
            }
        })
    except Exception as e:
        logger.error("[DASHBOARD API] Error", exc_info=True)
        return jsonify({
            'code': 500,
            'message': f'获取统计数据失败: {str(e)}'
        }), 500

@dashboard_bp.route('/rotation-trend', methods=['GET'])
@token_required
@role_required('admin', 'operator', 'auditor')
def get_rotation_trend():
    """
    获取近7天改密趋势
    """
    try:
        trend = []
        for i in range(6, -1, -1):
            current_date = date.today() - timedelta(days=i)
            count = RotationTask.query.filter(
                RotationTask.status == 'success',
                func.date(RotationTask.executed_at) == current_date
            ).count()
            trend.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        return jsonify({
            'code': 200,
            'data': trend
        })
    except Exception as e:
        logger.error("[ROTATION TREND API] Error", exc_info=True)
        return jsonify({
            'code': 500,
            'message': f'获取改密趋势失败: {str(e)}'
        }), 500