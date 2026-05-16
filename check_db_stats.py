import os
import sys

# 改变工作目录到 backend
os.chdir(os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, os.getcwd())

# 导入 app.py
import importlib.util
spec = importlib.util.spec_from_file_location("app_module", os.path.join(os.getcwd(), "app.py"))
app_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_module)

from app import db
from app.models import Asset, RotationTask, AuditLog
from datetime import datetime, date

app = app_module.app
with app.app_context():
    print('='*60)
    print('数据库实际统计')
    print('='*60)

    # 1. 资产总数
    total_assets = Asset.query.count()
    print(f'1. 资产总数: {total_assets}')

    active_assets = Asset.query.filter_by(status='active').count()
    print(f'   - 活跃资产: {active_assets}')

    # 2. 今日改密成功数
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())

    rotation_success = RotationTask.query.filter(
        RotationTask.status == 'success',
        RotationTask.executed_at >= today_start
    ).count()
    print(f'2. 今日改密成功数: {rotation_success}')

    # 3. 今日绕行告警数
    bypass_alerts = AuditLog.query.filter(
        AuditLog.log_type == 'bypass_detected',
        AuditLog.timestamp >= today_start
    ).count()
    print(f'3. 今日绕行告警数: {bypass_alerts}')

    # Asset 模型字段
    print(f'Asset 模型字段: {[c.name for c in Asset.__table__.columns]}')

    print(f'当前本地时间: {datetime.now()}')
    print(f'今日日期: {today}')