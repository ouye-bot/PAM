import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入db对象
from app import db
from app.models import Asset, AuditLog
from app.services.bypass_detector import detect_bypass_for_asset

# 导入app对象
import app as app_module
app = app_module.app

# 添加应用上下文
with app.app_context():
    # 查询所有active状态的资产
    active_assets = Asset.query.filter_by(status='active').all()

    print(f"发现 {len(active_assets)} 个活跃资产")

    # 遍历执行绕行检测
    for asset in active_assets:
        try:
            print(f"\n正在检测资产 {asset.ip} 的绕行登录...")
            bypassed, detail = detect_bypass_for_asset(asset)
            if bypassed:
                print(f"资产 {asset.ip} 检测到绕行登录: {detail}")
                # 写入审计日志
                audit_log = AuditLog(
                    log_type='bypass_detected',
                    operation_detail=detail,
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=asset.ip,
                    result='success'
                )
                db.session.add(audit_log)
                db.session.commit()
                print(f"已写入审计日志")
            else:
                print(f"资产 {asset.ip} 未检测到绕行登录: {detail}")
        except Exception as e:
            print(f"资产 {asset.ip} 绕行检测失败: {str(e)}")
            import traceback
            traceback.print_exc()

    print("\n绕行登录检测任务执行完成")
