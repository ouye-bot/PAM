from flask import Blueprint, request, jsonify
from datetime import datetime
from app import db
from app.models import Asset, Credential, AuditLog, RotationTask, SessionRecord
from app.services.crypto_service import CryptoService
from app.services.audit_service import write_audit_log
from app.services.asset_scanner import scan_network
from app.utils.auth import token_required, role_required
from app.drivers import get_driver
from app.utils.logger import get_logger

logger = get_logger('app.api.asset')

asset_bp = Blueprint('asset', __name__, url_prefix='/api/assets')

def format_datetime(dt):
    """统一时间格式化"""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.strftime('%Y-%m-%d %H:%M:%S')

@asset_bp.route('', methods=['GET'])
@token_required
@role_required('admin', 'operator', 'auditor')
def get_assets():
    """获取资产列表"""
    asset_type = request.args.get('type')
    query = Asset.query.filter(Asset.status != 'deleted')
    if asset_type:
        query = query.filter_by(os_type=asset_type)
    assets = query.all()
    user_role = request.role
    result = []
    for asset in assets:
        allowed_roles = (asset.allowed_roles or 'admin').split(',')
        if user_role == 'operator' and user_role not in allowed_roles:
            continue
        asset_data = {
            'id': asset.id,
            'ip': asset.ip,
            'hostname': asset.hostname or asset.ip,
            'os_type': asset.get_display_os_type(),
            'account_type': asset.account_type or 'local',
            'ssh_port': asset.ssh_port,
            'status': asset.status or 'inactive',
            'connectivity': asset.connectivity or 'unknown',
            'last_check_time': format_datetime(asset.last_check_time),
            'last_agent_login_time': format_datetime(asset.last_agent_login_time),
            'allowed_roles': allowed_roles,
            'host_fingerprint': asset.host_fingerprint,
            'fingerprint_type': asset.fingerprint_type,
            'fingerprint_collected_at': format_datetime(asset.fingerprint_collected_at),
            'created_at': format_datetime(asset.created_at),
            'updated_at': format_datetime(asset.updated_at),
            'credentials': [
                {
                    'id': cred.id,
                    'account_name': cred.account_name,
                    'key_version': cred.key_version
                }
                for cred in asset.credentials
            ]
        }
        result.append(asset_data)
    return jsonify(result)

@asset_bp.route('', methods=['POST'])
@token_required
@role_required('admin')
def add_asset():
    """添加资产"""
    try:
        data = request.get_json()

        if not data:
            logger.info("[ADD ASSET] No data provided")
            return jsonify({'code': 400, 'message': 'No data provided'}), 400

        asset_type = (data.get('asset_type') or 'linux').lower()
        driver = get_driver(asset_type)

        ip = data.get('ip') or data.get('host')
        ssh_port = data.get('ssh_port') or data.get('port', driver.default_port)
        account_name = data.get('account_name') or data.get('username', driver.default_account_name)
        account_type = data.get('account_type', 'local') if asset_type == 'windows' else None
        hostname = data.get('hostname') or data.get('name') or ip

        logger.info(f"[ADD ASSET] Received type={asset_type}, ip={ip}, port={ssh_port}")

        if not ip:
            logger.info("[ADD ASSET] IP/Host is required")
            return jsonify({'code': 400, 'message': 'IP/Host is required'}), 400

        logger.info(f"[ADD ASSET] Checking existence for {ip}:{ssh_port}")

        existing_asset = Asset.query.filter(
            Asset.ip == ip,
            Asset.ssh_port == ssh_port,
            Asset.status != 'deleted'
        ).first()
        if existing_asset:
            logger.info(f"[ADD ASSET] Asset {ip}:{ssh_port} already exists (ID={existing_asset.id})")
            return jsonify({'code': 400, 'message': f'Asset with IP {ip} and port {ssh_port} already exists'}), 400

        deleted_asset = Asset.query.filter(
            Asset.ip == ip,
            Asset.ssh_port == ssh_port,
            Asset.status == 'deleted'
        ).first()

        allowed_roles = data.get('allowed_roles', 'admin')

        if deleted_asset:
            deleted_asset.status = 'active'
            deleted_asset.hostname = hostname
            deleted_asset.os_type = asset_type
            if asset_type == 'windows':
                deleted_asset.account_type = account_type
            deleted_asset.allowed_roles = allowed_roles
            deleted_asset.updated_at = datetime.utcnow()
            db.session.flush()
            asset = deleted_asset
            logger.info(f"[ADD ASSET] Revived deleted asset ID={asset.id} for {ip}:{ssh_port}")
        else:
            asset = Asset(
                ip=ip,
                hostname=hostname,
                os_type=asset_type,
                ssh_port=ssh_port,
                status='active',
                allowed_roles=allowed_roles
            )
            if asset_type == 'windows':
                asset.account_type = account_type
            db.session.add(asset)
            db.session.flush()
            logger.info(f"[ADD ASSET] Created asset ID={asset.id} for {ip}:{ssh_port}")

        password = data.get('password')
        if password:
            encrypted_password, key_version = CryptoService.sm4_encrypt(password)
            credential = Credential(
                asset_id=asset.id,
                account_name=account_name,
                encrypted_password=encrypted_password,
                key_version=key_version
            )
            db.session.add(credential)
            logger.info(f"[ADD ASSET] Created credential for asset {asset.id}")

        db.session.commit()

        os_label = asset_type.upper() if asset_type in ('mysql', 'windows') else asset_type.capitalize()
        write_audit_log(
            log_type='asset_create',
            operator=request.username,
            source_ip=request.remote_addr,
            target_asset=f"{ip}:{ssh_port}",
            operation_detail=f'[资产创建] {os_label} 资产名称：{hostname}，地址：{ip}:{ssh_port}',
            result='success'
        )

        return jsonify({'code': 200, 'message': 'Asset added successfully', 'asset_id': asset.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"[ADD ASSET] Exception", exc_info=True)
        return jsonify({'code': 500, 'message': str(e)}), 500

@asset_bp.route('/credentials/<int:credential_id>/view', methods=['POST'])
@token_required
@role_required('admin', 'operator')
def view_credential(credential_id):
    """查看密码"""
    try:
        credential = Credential.query.get(credential_id)
        if not credential:
            return jsonify({'code': 404, 'message': 'Credential not found'}), 404

        asset = Asset.query.get(credential.asset_id)
        if not asset:
            return jsonify({'code': 404, 'message': 'Asset not found'}), 404

        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if password is None:
            prefix = get_driver(asset.os_type).get_log_type_prefix() if asset.os_type else ''
            log_type = f'PASSWORD_VIEW{prefix}_FAILED'
            write_audit_log(
                log_type=log_type,
                operator=request.username,
                source_ip=request.remote_addr,
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail=f'Failed to decrypt password for account {credential.account_name}',
                result='failed'
            )
            return jsonify({'code': 500, 'message': '密码解密失败'}), 500

        prefix = get_driver(asset.os_type).get_log_type_prefix() if asset.os_type else ''
        log_type = f'PASSWORD_VIEW{prefix}'
        write_audit_log(
            log_type=log_type,
            operator=request.username,
            source_ip=request.remote_addr,
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f'Viewed password for account {credential.account_name}',
            result='success'
        )

        return jsonify({'code': 200, 'password': password})
    except Exception as e:
        try:
            credential = Credential.query.get(credential_id)
            asset = Asset.query.get(credential.asset_id) if credential else None
            prefix = get_driver(asset.os_type).get_log_type_prefix() if asset and asset.os_type else ''
            log_type = f'PASSWORD_VIEW{prefix}'
            write_audit_log(
                log_type=log_type,
                operator=request.username,
                source_ip=request.remote_addr,
                target_asset=asset.ip if asset else 'unknown',
                operation_detail=f'Failed to view password: {str(e)}',
                result='failed'
            )
        except:
            pass

        return jsonify({'code': 500, 'message': str(e)}), 500

@asset_bp.route('/<int:asset_id>', methods=['PUT'])
@token_required
@role_required('admin', 'operator')
def update_asset(asset_id):
    """更新资产元数据（hostname/ip/port/os_type/account_type/allowed_roles）"""
    asset = Asset.query.get(asset_id)
    if not asset or asset.status == 'deleted':
        return jsonify({'code': 404, 'message': '资产不存在或已删除'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'code': 400, 'message': '请求数据无效'}), 400

    updatable = ['hostname', 'ip', 'ssh_port', 'os_type', 'account_type', 'allowed_roles']
    changes = []
    for field in updatable:
        if field in data and getattr(asset, field) != data[field]:
            old_val = getattr(asset, field)
            setattr(asset, field, data[field])
            changes.append(f'{field}: {old_val} -> {data[field]}')

    if not changes:
        return jsonify({'code': 200, 'message': '没有变更'})

    try:
        db.session.commit()
        write_audit_log('asset_update', operator=request.username,
                       source_ip=request.remote_addr or '127.0.0.1',
                       target_asset=f'{asset.ip}:{asset.ssh_port}',
                       operation_detail=f'更新资产 #{asset_id}: {"; ".join(changes)}',
                       result='success')
        return jsonify({'code': 200, 'message': f'资产更新成功，变更: {"; ".join(changes)}', 'data': asset.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'code': 500, 'message': f'更新失败: {str(e)}'}), 500

@asset_bp.route('/<int:asset_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_asset(asset_id):
    """删除资产（逻辑删除）"""
    try:
        asset = Asset.query.get(asset_id)
        if not asset:
            return jsonify({'code': 404, 'message': 'Asset not found'}), 404

        if asset.status == 'deleted':
            return jsonify({'code': 400, 'message': 'Asset already deleted'}), 400

        asset.status = 'deleted'
        db.session.commit()

        write_audit_log(
            log_type='asset_delete',
            operator=request.username,
            source_ip=request.remote_addr,
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f'[资产删除] 资产名称：{asset.hostname}，地址：{asset.ip}:{asset.ssh_port}，类型：{asset.os_type}',
            result='success'
        )

        return jsonify({'code': 200, 'message': 'Asset deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete asset failed", exc_info=True)
        return jsonify({'code': 500, 'message': f'Delete failed: {str(e)}'}), 500

@asset_bp.route('/deleted', methods=['GET'])
@token_required
@role_required('admin')
def get_deleted_assets():
    """获取已删除的资产列表"""
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    query = Asset.query.filter(Asset.status == 'deleted')
    pagination = query.order_by(Asset.updated_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify({
        'code': 200,
        'data': {
            'items': [a.to_dict() for a in pagination.items],
            'total': pagination.total
        }
    })

@asset_bp.route('/<int:asset_id>/restore', methods=['POST'])
@token_required
@role_required('admin')
def restore_asset(asset_id):
    """恢复单个资产"""
    asset = Asset.query.get(asset_id)
    if not asset:
        return jsonify({'code': 404, 'message': 'Asset not found'}), 404
    if asset.status != 'deleted':
        return jsonify({'code': 400, 'message': 'Asset is not deleted'}), 400
    asset.status = 'active'
    db.session.commit()
    write_audit_log(
        log_type='asset_restore',
        operator=request.username,
        source_ip=request.remote_addr,
        target_asset=f"{asset.ip}:{asset.ssh_port}",
        operation_detail=f'[资产恢复] 资产名称：{asset.hostname}，地址：{asset.ip}:{asset.ssh_port}',
        result='success'
    )
    return jsonify({'code': 200, 'message': 'Asset restored successfully', 'data': asset.to_dict()})

@asset_bp.route('/batch-restore', methods=['POST'])
@token_required
@role_required('admin')
def batch_restore_assets():
    """批量恢复资产"""
    data = request.get_json()
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'code': 400, 'message': 'No IDs provided'}), 400
    assets = Asset.query.filter(Asset.id.in_(ids), Asset.status == 'deleted').all()
    for asset in assets:
        asset.status = 'active'
    db.session.commit()
    for asset in assets:
        write_audit_log(
            log_type='asset_restore',
            operator=request.username,
            source_ip=request.remote_addr,
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f'[批量恢复] 资产名称：{asset.hostname}',
            result='success'
        )
    return jsonify({'code': 200, 'message': f'{len(assets)} assets restored successfully'})

@asset_bp.route('/purge', methods=['DELETE'])
@token_required
@role_required('admin')
def purge_assets():
    """彻底删除已删除的资产及其凭证"""
    data = request.get_json()
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'code': 400, 'message': 'No IDs provided'}), 400
    assets = Asset.query.filter(Asset.id.in_(ids), Asset.status == 'deleted').all()
    for asset in assets:
        Credential.query.filter_by(asset_id=asset.id).delete()
        RotationTask.query.filter_by(asset_id=asset.id).delete()
        db.session.delete(asset)
    db.session.commit()
    return jsonify({'code': 200, 'message': f'{len(assets)} assets permanently deleted'})

@asset_bp.route('/discover', methods=['POST'])
@token_required
@role_required('admin')
def discover_assets():
    """扫描并发现资产"""
    try:
        data = request.get_json()
        if not data:
            logger.info("[ERROR] No JSON data received")
            return jsonify({'code': 400, 'message': 'No data provided'}), 400

        ip_range = data.get('ip_range')
        port = data.get('port', 22)
        username = data.get('username', 'root')
        passwords = data.get('passwords', ['123456', 'root', 'admin'])
        scan_type = data.get('scan_type', 'ssh')

        if not ip_range:
            return jsonify({'code': 400, 'message': 'ip_range is required'}), 400

        logger.info(f"[INFO] Starting asset discovery: ip_range={ip_range}, port={port}, username={username}, scan_type={scan_type}")
        logger.debug(f"[INFO] Discovery passwords count: {len(passwords)}")

        existing = Asset.query.filter(Asset.status != 'deleted').all()
        existing_list = [{'ip': a.ip, 'ssh_port': a.ssh_port} for a in existing]

        discovered = scan_network(ip_range, port, username, passwords, scan_type, existing_list)
        logger.info(f"[INFO] Discovery completed. Found {len(discovered)} assets")
        return jsonify({'code': 200, 'data': discovered})
    except Exception as e:
        logger.error("[ERROR] Asset discovery failed", exc_info=True)
        return jsonify({'code': 500, 'message': str(e)}), 500

@asset_bp.route('/<int:asset_id>/test', methods=['POST'])
@token_required
@role_required('admin', 'operator')
def test_asset_connectivity(asset_id):
    """测试指定资产的连通性"""
    try:
        asset = Asset.query.get(asset_id)
        if not asset:
            return jsonify({'code': 404, 'message': 'Asset not found'}), 404

        if not asset.credentials:
            write_audit_log(
                log_type='connectivity_test',
                operator=request.username,
                source_ip=request.remote_addr,
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail='连接测试失败：无关联凭证',
                result='failed'
            )
            asset.connectivity = 'offline'
            asset.last_check_time = datetime.now()
            db.session.commit()
            return jsonify({'code': 0, 'data': {'reachable': False, 'message': '连接失败: 无关联凭证'}})

        credential = max(asset.credentials, key=lambda c: c.id) if asset.credentials else None
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if password is None:
            write_audit_log(
                log_type='connectivity_test',
                operator=request.username,
                source_ip=request.remote_addr,
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail='连接测试失败：密码解密失败',
                result='failed'
            )
            asset.connectivity = 'offline'
            asset.last_check_time = datetime.now()
            db.session.commit()
            return jsonify({'code': 0, 'data': {'reachable': False, 'message': '连接失败: 密码解密失败'}})

        from app.services.connection_tester import test_connection
        result = test_connection(
            asset_type=asset.os_type,
            host=asset.ip,
            port=asset.ssh_port,
            username=credential.account_name,
            password=password
        )

        if result['success']:
            write_audit_log(
                log_type='connectivity_test',
                operator=request.username,
                source_ip=request.remote_addr,
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail=f"连接测试成功",
                result='success'
            )
        else:
            write_audit_log(
                log_type='connectivity_test',
                operator=request.username,
                source_ip=request.remote_addr,
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail=f"连接测试失败: {result['message']}",
                result='failed'
            )

        asset.connectivity = 'online' if result['success'] else 'offline'
        asset.last_check_time = datetime.now()
        db.session.commit()

        return jsonify({'code': 0, 'data': {'reachable': result['success'], 'message': result['message']}})

    except Exception as e:
        logger.error(f"[TEST] Asset connectivity test failed: {str(e)}", exc_info=True)
        return jsonify({'code': 500, 'message': str(e)}), 500


@asset_bp.route('/<int:asset_id>/diag-winrm', methods=['POST'])
@token_required
@role_required('admin')
def diag_winrm(asset_id):
    """诊断 Windows 资产 WinRM 连接问题"""
    try:
        asset = Asset.query.get(asset_id)
        if not asset:
            return jsonify({'code': 404, 'message': 'Asset not found'}), 404
        if not asset.os_type or asset.os_type.lower() != 'windows':
            return jsonify({'code': 400, 'message': 'Not a Windows asset'}), 400

        credential = Credential.query.filter_by(asset_id=asset_id).first()
        if not credential:
            return jsonify({'code': 404, 'message': 'No credential for this asset'}), 404

        import winrm
        result = {
            'asset_id': asset.id,
            'ip': asset.ip,
            'port': asset.ssh_port,
            'hostname': asset.hostname,
            'account_name': credential.account_name,
            'key_version': credential.key_version,
            'diagnostics': []
        }

        # Step 1: Decrypt password
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if password is None:
            result['diagnostics'].append({
                'step': '解密密码',
                'success': False,
                'error': '密码解密失败（SM4 工作密钥可能已更换或数据损坏）'
            })
            result['password_found'] = False
            return jsonify({'code': 200, 'data': result})
        result['password_found'] = True
        result['diagnostics'].append({
            'step': '解密密码',
            'success': True,
            'note': f'密码长度 {len(password)} 字符'
        })

        # Step 2: TCP connectivity check
        import socket
        sock_result = {'step': 'TCP 连接测试', 'success': False}
        try:
            s = socket.create_connection((asset.ip, asset.ssh_port), timeout=5)
            s.close()
            sock_result['success'] = True
            sock_result['note'] = f'{asset.ip}:{asset.ssh_port} 可达'
        except Exception as e:
            sock_result['error'] = f'TCP 连接失败: {str(e)[:120]}'
        result['diagnostics'].append(sock_result)

        if not sock_result['success']:
            return jsonify({'code': 200, 'data': result})

        # Step 3: WinRM connection test with stored password
        winrm_result = {'step': 'WinRM 认证测试（存储密码）', 'success': False}
        try:
            session = winrm.Session(
                f'http://{asset.ip}:{asset.ssh_port}/wsman',
                auth=(credential.account_name, password),
                transport='ntlm',
                operation_timeout_sec=10
            )
            r = session.run_cmd('echo PAM_DIAG_OK')
            if r.status_code == 0:
                output = r.std_out.decode('utf-8', errors='ignore').strip()
                winrm_result['success'] = True
                winrm_result['note'] = f'认证成功，输出: {output[:100]}'
            else:
                err = r.std_err.decode('utf-8', errors='ignore')[:200]
                winrm_result['error'] = f'命令执行失败(status={r.status_code}): {err}'
        except winrm.exceptions.AuthenticationError as e:
            winrm_result['error'] = f'认证失败: 用户名或密码错误 ({str(e)[:100]})'
        except Exception as e:
            winrm_result['error'] = f'WinRM 连接异常: {str(e)[:150]}'
        result['diagnostics'].append(winrm_result)

        # Step 4: Optional — test with custom password from request
        data = request.get_json(silent=True) or {}
        test_password = data.get('test_password')
        if test_password:
            custom_result = {'step': 'WinRM 认证测试（提供的密码）', 'success': False}
            try:
                session = winrm.Session(
                    f'http://{asset.ip}:{asset.ssh_port}/wsman',
                    auth=(credential.account_name, test_password),
                    transport='ntlm',
                    operation_timeout_sec=10
                )
                r = session.run_cmd('echo PAM_DIAG_OK')
                if r.status_code == 0:
                    custom_result['success'] = True
                    custom_result['note'] = '提供的密码认证成功'
                else:
                    custom_result['error'] = '提供的密码认证失败'
            except Exception as e:
                custom_result['error'] = f'提供的密码认证失败: {str(e)[:120]}'
            result['diagnostics'].append(custom_result)

        return jsonify({'code': 200, 'data': result})
    except Exception as e:
        logger.error(f"[DIAG] WinRM diagnostic failed: {str(e)}", exc_info=True)
        return jsonify({'code': 500, 'message': str(e)}), 500


@asset_bp.route('/<int:asset_id>/update-password', methods=['POST'])
@token_required
@role_required('admin')
def update_asset_password(asset_id):
    """更新资产密码（先验证新密码可用性，再安全存储）"""
    try:
        asset = Asset.query.get(asset_id)
        if not asset:
            return jsonify({'code': 404, 'message': 'Asset not found'}), 404

        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password:
            return jsonify({'code': 400, 'message': 'new_password is required'}), 400

        credential = Credential.query.filter_by(asset_id=asset_id).first()
        if not credential:
            return jsonify({'code': 404, 'message': 'No credential for this asset'}), 404

        # For Windows assets, verify the new password via WinRM before saving
        if asset.os_type and asset.os_type.lower() == 'windows':
            import winrm
            try:
                session = winrm.Session(
                    f'http://{asset.ip}:{asset.ssh_port}/wsman',
                    auth=(credential.account_name, new_password),
                    transport='ntlm',
                    operation_timeout_sec=10
                )
                r = session.run_cmd('echo PAM_PWD_OK')
                if r.status_code != 0:
                    return jsonify({'code': 400, 'message': '新密码无法通过 WinRM 认证，请确认密码正确'}), 400
            except Exception as e:
                return jsonify({'code': 400, 'message': f'新密码 WinRM 验证失败: {str(e)[:120]}'}), 400

        # Check password history — reject if password was used before
        from app.services.password_rotation import is_password_reused, validate_password_strength
        if is_password_reused(credential, new_password):
            return jsonify({'code': 400, 'message': '新密码与历史密码重复，请更换密码'}), 400

        # Validate password strength against policy
        valid, errors = validate_password_strength(new_password)
        if not valid:
            return jsonify({'code': 422, 'message': '密码强度不足', 'errors': errors}), 422

        # Encrypt and store the new password
        encrypted_password, key_version = CryptoService.sm4_encrypt(new_password)
        credential.encrypted_password = encrypted_password
        credential.key_version = key_version
        db.session.commit()

        write_audit_log(
            log_type='password_update',
            operator=request.username,
            source_ip=request.remote_addr,
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f'[密码更新] 资产 {asset.hostname}({asset.ip}) 密码已更新',
            result='success'
        )

        return jsonify({'code': 200, 'message': '密码更新成功'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"[PASSWORD_UPDATE] Failed: {str(e)}", exc_info=True)
        return jsonify({'code': 500, 'message': str(e)}), 500


@asset_bp.route('/<int:asset_id>/reset-fingerprint', methods=['POST'])
@token_required
@role_required('admin')
def reset_asset_fingerprint(asset_id):
    """重置主机指纹（资产合理变更后允许重新采集）"""
    asset = Asset.query.get(asset_id)
    if not asset:
        return jsonify({'code': 404, 'message': 'Asset not found'}), 404
    asset.host_fingerprint = None
    asset.fingerprint_type = None
    asset.fingerprint_collected_at = None
    db.session.commit()
    return jsonify({'code': 200, 'message': 'Fingerprint reset successfully'})


@asset_bp.route('/check-connectivity', methods=['POST'])
@token_required
@role_required('admin', 'operator')
def check_connectivity():
    """手动触发资产连通性检测"""
    try:
        from app.scheduler import check_assets_connectivity
        check_assets_connectivity()
        return jsonify({'code': 200, 'message': '资产连通性检测已启动'})
    except Exception as e:
        logger.error("[ERROR] Check connectivity failed", exc_info=True)
        return jsonify({'code': 500, 'message': str(e)}), 500
