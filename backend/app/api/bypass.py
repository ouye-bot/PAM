from flask import Blueprint, jsonify, request, current_app
from app.models import AuditLog, Asset
from app.services.audit_service import write_audit_log
from app.services.bypass_exemption import add_exemption
from app.drivers import get_driver
from app import db
from app.utils.auth import token_required, role_required

bypass_bp = Blueprint('bypass', __name__, url_prefix='/api/bypass')

@bypass_bp.route('/alerts', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_bypass_alerts():
    """
    获取最近的绕行告警列表
    """
    alerts = AuditLog.query.filter_by(log_type='bypass_detected').order_by(AuditLog.timestamp.desc()).limit(10).all()

    alert_list = []
    for alert in alerts:
        alert_list.append({
            'id': alert.id,
            'message': alert.operation_detail,
            'asset': alert.target_asset,
            'time': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': alert.source_ip
        })

    return jsonify({
        'code': 200,
        'data': alert_list
    })

@bypass_bp.route('/trigger', methods=['POST'])
@token_required
@role_required('admin')
def trigger_bypass_detection():
    """
    手动触发绕行登录检测
    """
    try:
        current_app.logger.info("=" * 60)
        current_app.logger.info("[BYPASS API] 开始执行手动绕行登录检测任务...")

        active_assets = Asset.query.filter_by(status='active').all()
        total_assets = len(active_assets)
        detected_bypasses = 0

        current_app.logger.info(f"[BYPASS API] 发现 {total_assets} 个活跃资产")

        bypass_results = []

        for asset in active_assets:
            try:
                current_app.logger.info(f"[BYPASS API] 检测资产: {asset.ip}:{asset.ssh_port}")
                driver = get_driver(asset.os_type)
                bypassed, detail = driver.detect_bypass(asset)
                current_app.logger.info(f"[BYPASS API] 检测结果: bypassed={bypassed}, detail={detail}")

                bypass_results.append({
                    'asset_id': asset.id,
                    'asset_ip': asset.ip,
                    'asset_port': asset.ssh_port,
                    'bypassed': bypassed,
                    'detail': detail
                })

                if bypassed:
                    current_app.logger.warning(f"[BYPASS API] *** 检测到绕行登录: {asset.ip} - {detail}")
                else:
                    current_app.logger.info(f"[BYPASS API] 资产 {asset.ip} 未检测到绕行登录")
            except Exception as e:
                current_app.logger.error(f"[BYPASS API] 资产 {asset.ip} 绕行检测失败: {str(e)}")
                import traceback
                traceback.print_exc()
                continue

        for result in bypass_results:
            current_app.logger.info(f"[BYPASS API] 处理结果: asset={result['asset_ip']}, bypassed={result['bypassed']}, detail={result['detail'][:50] if result['detail'] else 'None'}...")
            if result['bypassed']:
                detected_bypasses += 1
                current_app.logger.info(f"[BYPASS API] 检测到绕行: {result['asset_ip']}, detected_bypasses={detected_bypasses}")

        current_app.logger.info(f"[BYPASS API] 检测完成: 检测了 {total_assets} 个资产，发现 {detected_bypasses} 个绕行")
        current_app.logger.info("=" * 60)

        return jsonify({
            'code': 200,
            'data': {
                'total_assets': total_assets,
                'detected_bypasses': detected_bypasses
            },
            'message': f"成功检测了 {total_assets} 个资产，发现 {detected_bypasses} 个绕行"
        })
    except Exception as e:
        current_app.logger.error(f"[BYPASS API] 手动触发绕行检测失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'code': 500,
            'message': '触发检测失败，请稍后重试'
        })


@bypass_bp.route('/exemption', methods=['POST'])
@token_required
@role_required('admin')
def apply_exemption():
    """申请绕行豁免"""
    data = request.get_json()
    if not data or 'asset_id' not in data:
        return jsonify({'code': 400, 'message': 'asset_id is required'}), 400

    asset = Asset.query.get(data['asset_id'])
    if not asset:
        return jsonify({'code': 404, 'message': '资产不存在'}), 404

    asset_type = (asset.os_type or '').lower()
    driver = get_driver(asset_type)
    if not driver.supports_exemption:
        return jsonify({
            'code': 400,
            'message': '绕行豁免不适用于MySQL资产。MySQL资产的所有操作请通过代理（端口3307）执行。'
        }), 400

    source_ip = data.get('source_ip', request.remote_addr or '127.0.0.1')
    reason = data.get('reason', '手动申请豁免')

    success = add_exemption(asset.id, source_ip, request.username, reason)
    if success:
        return jsonify({'code': 200, 'message': '豁免申请成功，有效期5分钟'})
    return jsonify({'code': 500, 'message': '豁免申请失败'}), 500