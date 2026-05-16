import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.abspath('.'))

from datetime import datetime, date

# 直接从app.py导入
import app

with app.app.app_context():
    from app.models import Asset, RotationTask, AuditLog
    
    # 资产总数
    total_assets = Asset.query.count()
    print(f"资产总数: {total_assets}")
    
    # 今日改密成功数
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())
    today_rotations = RotationTask.query.filter(
        RotationTask.status == 'success',
        RotationTask.executed_at >= today_start
    ).count()
    print(f"今日改密成功数: {today_rotations}")
    
    # 所有改密成功数
    all_rotations = RotationTask.query.filter(RotationTask.status == 'success').count()
    print(f"所有改密成功数: {all_rotations}")
    
    # 绕行告警数
    bypass_alerts = AuditLog.query.filter(AuditLog.log_type == 'bypass_detected').count()
    print(f"绕行告警数: {bypass_alerts}")
    
    # 今日绕行告警数
    today_bypass = AuditLog.query.filter(
        AuditLog.log_type == 'bypass_detected',
        AuditLog.timestamp >= today_start
    ).count()
    print(f"今日绕行告警数: {today_bypass}")
