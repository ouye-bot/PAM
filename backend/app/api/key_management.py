from flask import Blueprint, jsonify, request
from app import db
from app.models import KeyVersion, Credential, Asset
from app.services.crypto_service import CryptoService
from app.services.audit_service import write_audit_log
from app.utils.auth import token_required, role_required
from app.utils.logger import get_logger
from datetime import datetime

logger = get_logger('app.api.key')

key_bp = Blueprint('key', __name__, url_prefix='/api/keys')

@key_bp.route('/status', methods=['GET'])
@token_required
@role_required('admin', 'operator', 'auditor')
def get_key_status():
    """
    获取密钥状态
    """
    try:
        # 查询当前活跃密钥和正在轮换的密钥
        active_key = KeyVersion.query.filter_by(status='active').first()
        rotating_key = KeyVersion.query.filter_by(status='rotating').first()

        active_key_id = active_key.id if active_key else 0
        active_key_created = active_key.created_at.strftime('%Y-%m-%d %H:%M:%S') if active_key else 'N/A'

        # 统计已加密凭证数（关联活跃资产的凭证）
        active_assets = Asset.query.filter_by(status='active').all()
        active_asset_ids = [asset.id for asset in active_assets]
        encrypted_credentials_count = Credential.query.filter(
            Credential.asset_id.in_(active_asset_ids)
        ).count() if active_asset_ids else 0

        # 统计总密钥版本数
        total_key_versions = KeyVersion.query.count()

        # 轮换进度
        rotation_progress = None
        if rotating_key:
            total_creds = Credential.query.count()
            migrated = Credential.query.filter_by(key_version=rotating_key.id).count()
            rotation_progress = {
                'rotating_key_id': rotating_key.id,
                'rotating_key_created': rotating_key.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'total_credentials': total_creds,
                'migrated_count': migrated,
                'remaining_count': total_creds - migrated
            }

        return jsonify({
            'code': 200,
            'data': {
                'active_key_id': active_key_id,
                'active_key_created': active_key_created,
                'encrypted_credentials_count': encrypted_credentials_count,
                'total_key_versions': total_key_versions,
                'rotation_progress': rotation_progress
            }
        })
    except Exception as e:
        logger.error("获取密钥状态失败", exc_info=True)
        return jsonify({
            'code': 500,
            'message': '获取密钥状态失败'
        }), 500

@key_bp.route('/rotate', methods=['POST'])
@token_required
@role_required('admin')
def rotate_key():
    """
    Synchronous key rotation with full re-encryption.
    1. Create new key (rotating), 2. Pause scheduler, 3. Re-encrypt ALL credentials,
    4. Success: old→retired, new→active, 5. Failure: old→active, new→retired, 6. Resume scheduler
    """
    from app import db
    from app.models import KeyVersion, Credential
    from app.scheduler import pause_rotation_jobs, resume_rotation_jobs

    try:
        existing_rotating = KeyVersion.query.filter_by(status='rotating').first()
        if existing_rotating:
            return jsonify({
                'code': 409,
                'message': f'已有正在进行的密钥轮换 (密钥ID: {existing_rotating.id})'
            }), 409

        old_key = KeyVersion.query.filter_by(status='active').first()
        new_work_key = CryptoService.generate_work_key()
        encrypted_new_key = CryptoService.encrypt_work_key(new_work_key)

        new_key_version = KeyVersion(
            encrypted_key=encrypted_new_key,
            status='rotating'
        )
        db.session.add(new_key_version)
        db.session.flush()
        new_key_id = new_key_version.id
        old_key_id = old_key.id if old_key else None
        db.session.commit()

        pause_rotation_jobs()
        logger.info("[KEY-ROTATION] Scheduler rotation jobs paused")

        total_creds = Credential.query.count()

        try:
            old_work_key = CryptoService.decrypt_work_key(old_key.encrypted_key)
            if old_work_key is None:
                raise RuntimeError("Cannot decrypt old work key — master key may have changed")

            migrated, failed, errors = CryptoService.re_encrypt_all_credentials(
                old_key_id, new_key_id, old_work_key, new_work_key
            )

            if failed > 0:
                raise RuntimeError(f"Re-encryption partially failed: {failed}/{total_creds} errors: {errors[:5]}")

            if old_key:
                old_key.status = 'retired'
            new_key_version.status = 'active'
            db.session.commit()

            write_audit_log(
                log_type='key_rotation',
                operator=request.username or 'system',
                source_ip=request.remote_addr or '127.0.0.1',
                target_asset='System',
                operation_detail=f'密钥轮换完成: {migrated}条凭证已重加密, 旧密钥ID {old_key_id} retired, 新密钥ID {new_key_id} active',
                result='success'
            )

            return jsonify({
                'code': 200,
                'message': f'密钥轮换完成，{migrated} 条凭证已重加密',
                'data': {
                    'new_key_id': new_key_id,
                    'old_key_id': old_key_id,
                    'migrated_count': migrated,
                    'status': 'complete'
                }
            })

        except Exception as re_encrypt_error:
            db.session.rollback()
            if old_key:
                old_key.status = 'active'
            new_key_version.status = 'retired'
            db.session.commit()

            logger.error("[KEY-ROTATION] Re-encryption failed, old key preserved: %s", re_encrypt_error)

            write_audit_log(
                log_type='key_rotation',
                operator=request.username or 'system',
                source_ip=request.remote_addr or '127.0.0.1',
                target_asset='System',
                operation_detail=f'密钥轮换失败: {str(re_encrypt_error)[:200]}, 旧密钥保持active',
                result='failed'
            )

            return jsonify({
                'code': 500,
                'message': f'重加密失败，旧密钥保持活跃，系统正常运行: {str(re_encrypt_error)[:200]}'
            }), 500

        finally:
            resume_rotation_jobs()
            logger.info("[KEY-ROTATION] Scheduler rotation jobs resumed")

    except Exception as e:
        db.session.rollback()
        logger.error("[KEY-ROTATION] Rotation failed: %s", e)
        return jsonify({'code': 500, 'message': f'密钥轮换失败: {str(e)}'}), 500


@key_bp.route('/rotate-status', methods=['GET'])
@token_required
@role_required('admin')
def get_rotate_status():
    """查询当前密钥轮换进度"""
    rotating_key = KeyVersion.query.filter_by(status='rotating').first()
    if not rotating_key:
        return jsonify({
            'code': 200,
            'data': {'active_rotation': False}
        })

    total = Credential.query.count()
    migrated = Credential.query.filter_by(key_version=rotating_key.id).count()
    remaining = total - migrated
    progress_pct = round(migrated / total * 100, 1) if total > 0 else 100.0

    return jsonify({
        'code': 200,
        'data': {
            'active_rotation': True,
            'rotating_key_id': rotating_key.id,
            'rotating_key_created': rotating_key.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'total_credentials': total,
            'migrated_count': migrated,
            'remaining_count': remaining,
            'progress_pct': progress_pct
        }
    })


@key_bp.route('/master-key-status', methods=['GET'])
@token_required
@role_required('admin')
def get_master_key_status():
    """获取主密钥状态（不返回密钥内容）"""
    import os
    import re

    keyring = None
    try:
        import keyring
        keyring_available = True
        stored = keyring.get_password("PAM", "master_key")
        keyring = {'available': True, 'has_key': bool(stored)}
    except Exception:
        keyring = {'available': False}

    env_key = os.getenv('MASTER_KEY')
    env_status = {
        'configured': bool(env_key),
        'length': len(env_key) if env_key else 0,
        'format_valid': bool(re.match(r'^[0-9a-fA-F]{32}$', env_key)) if env_key else False
    }

    # 确定当前主密钥来源
    if keyring and keyring.get('has_key'):
        source = 'keyring'
    elif env_key:
        source = 'environment'
    else:
        source = 'none'

    return jsonify({
        'code': 200,
        'data': {
            'source': source,
            'keyring': keyring,
            'environment': env_status,
            'expected_length': 32,
            'expected_format': '32位十六进制字符串'
        }
    })


@key_bp.route('/reload', methods=['POST'])
@token_required
@role_required('admin')
def reload_keys():
    """验证并重新加载密钥（主密钥每次调用即重新读取，此端点验证可用性）"""
    master_key_ok = False
    work_key_ok = False
    active_key_id = None
    master_key_error = None
    work_key_error = None

    try:
        master_key = CryptoService.get_master_key()
        if master_key and len(master_key) == 32:
            master_key_ok = True
        else:
            master_key_error = f"主密钥长度异常: {len(master_key) if master_key else 0}"
    except Exception as e:
        master_key_error = str(e)

    if master_key_ok:
        active_key = KeyVersion.query.filter_by(status='active').first()
        if active_key:
            active_key_id = active_key.id
            work_key = CryptoService.decrypt_work_key(active_key.encrypted_key)
            if work_key is not None:
                work_key_ok = True
            else:
                work_key_error = '活跃工作密钥解密失败，主密钥可能已更换'
        else:
            work_key_error = '未找到活跃工作密钥'

    all_ok = master_key_ok and work_key_ok
    return jsonify({
        'code': 200,
        'data': {
            'ok': all_ok,
            'master_key_ok': master_key_ok,
            'work_key_ok': work_key_ok,
            'active_key_id': active_key_id,
            'master_key_error': master_key_error,
            'work_key_error': work_key_error
        }
    })
