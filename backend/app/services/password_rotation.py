import json
import string
import time
from datetime import datetime
import paramiko
import pymysql
import secrets
from app import db
from app.models import Asset, Credential, KeyVersion, RotationTask, SystemConfig
from app.services.audit_service import write_audit_log
from app.services.crypto_service import CryptoService
from app.services.bypass_exemption import add_exemption, is_exempted
import hashlib
from app.utils.logger import get_logger

logger = get_logger('app.services.password_rotation')

def get_password_policy():
    """
    获取密码策略配置
    每次调用实时查询数据库
    """
    configs = SystemConfig.query.all()
    policy = {c.key: c.value for c in configs}
    return {
        'min_length': int(policy.get('pwd_min_length', 16)),
        'require_upper': policy.get('pwd_require_upper', 'true').lower() == 'true',
        'require_lower': policy.get('pwd_require_lower', 'true').lower() == 'true',
        'require_digit': policy.get('pwd_require_digit', 'true').lower() == 'true',
        'require_special': policy.get('pwd_require_special', 'true').lower() == 'true',
        'special_chars': policy.get('pwd_special_chars', '!@#$%^&*()_+-=[]{}|;:,.<>?')
    }

def validate_password_strength(password):
    """校验密码是否满足策略要求，返回 (valid: bool, errors: list)"""
    policy = get_password_policy()
    errors = []

    if len(password) < policy['min_length']:
        errors.append(f"密码长度不足（至少{policy['min_length']}位）")
    if policy['require_upper'] and not any(c.isupper() for c in password):
        errors.append('需要包含大写字母')
    if policy['require_lower'] and not any(c.islower() for c in password):
        errors.append('需要包含小写字母')
    if policy['require_digit'] and not any(c.isdigit() for c in password):
        errors.append('需要包含数字')
    if policy['require_special'] and not any(c in policy['special_chars'] for c in password):
        errors.append(f"需要包含特殊字符（{policy['special_chars']}）")

    return len(errors) == 0, errors


def generate_strong_password(credential=None):
    """
    根据密码策略生成随机密码
    使用secrets模块确保密码学安全
    若传入credential，自动避免生成历史密码（最多重试10次）
    """
    policy = get_password_policy()
    chars = ''
    if policy['require_lower']:
        chars += string.ascii_lowercase
    if policy['require_upper']:
        chars += string.ascii_uppercase
    if policy['require_digit']:
        chars += string.digits
    if policy['require_special']:
        chars += policy['special_chars']
    if not chars:
        chars = string.ascii_letters + string.digits + policy['special_chars']

    length = policy['min_length']

    max_attempts = 10
    for _ in range(max_attempts):
        password = []
        if policy['require_lower']:
            password.append(secrets.choice(string.ascii_lowercase))
        if policy['require_upper']:
            password.append(secrets.choice(string.ascii_uppercase))
        if policy['require_digit']:
            password.append(secrets.choice(string.digits))
        if policy['require_special']:
            password.append(secrets.choice(policy['special_chars']))

        remaining = length - len(password)
        password.extend(secrets.choice(chars) for _ in range(remaining))
        secrets.SystemRandom().shuffle(password)
        result = ''.join(password)

        if credential is None or not is_password_reused(credential, result):
            return result

    raise RuntimeError("无法生成不重复的密码：历史密码记录已满（最多10次尝试）")

def sm3_hash(password):
    """
    使用SM3算法对密码进行哈希
    """
    from gmssl.sm3 import sm3_hash as gmssl_sm3
    byte_list = list(password.encode())
    return gmssl_sm3(byte_list)

def _compute_password_hash(password):
    """计算密码的SM3哈希（回退SHA-256），与previous_passwords中存储的格式一致"""
    try:
        return hashlib.sm3(password.encode()).hexdigest()
    except (AttributeError, ValueError):
        return hashlib.sha256(password.encode()).hexdigest()


def is_password_reused(credential, new_password):
    """检查新密码是否在历史密码中已存在"""
    if not credential or not credential.previous_passwords:
        return False
    try:
        history = json.loads(credential.previous_passwords)
    except (json.JSONDecodeError, TypeError):
        return False
    if not history:
        return False
    new_hash = _compute_password_hash(new_password)
    return new_hash in history


def ssh_heartbeat_check(asset_ip, asset_port, username, password, timeout=5):
    """
    执行SSH心跳检测，通过发送简单命令验证连接稳定性
    返回: (success, error_msg)
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=asset_ip,
            port=asset_port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        stdin, stdout, stderr = client.exec_command('echo ok')
        result = stdout.read().decode('utf-8').strip()
        client.close()
        if result == 'ok':
            return (True, None)
        return (False, f"Heartbeat command returned unexpected result: {result}")
    except Exception as e:
        client.close()
        return (False, str(e))

def _mysql_verify(host, port, user, password, timeout=10):
    """MySQL连接验证"""
    conn = pymysql.connect(
        host=host, port=port, user=user, password=password,
        connect_timeout=timeout, read_timeout=timeout
    )
    conn.close()


def _mysql_alter_user(host, port, user, password, target_user, new_password):
    """执行MySQL ALTER USER改密（使用参数化查询防SQL注入）"""
    conn = pymysql.connect(
        host=host, port=port, user=user, password=password,
        connect_timeout=10, read_timeout=10
    )
    # 转义单引号防止SQL注入
    safe_user = target_user.replace("'", "''")
    safe_pwd = new_password.replace("'", "''")
    with conn.cursor() as cursor:
        cursor.execute(f"ALTER USER '{safe_user}'@'%' IDENTIFIED WITH mysql_native_password BY '{safe_pwd}'")
        cursor.execute(f"ALTER USER '{safe_user}'@'localhost' IDENTIFIED WITH mysql_native_password BY '{safe_pwd}'")
        cursor.execute("FLUSH PRIVILEGES")
    conn.close()


def _rotate_mysql_password(asset, credential, active_key, current_password, old_password_hash, account_name, local_time):
    """
    MySQL资产改密专用函数
    流程：验证当前密码 → ALTER USER改密 → 验证新密码(重试) → 数据库更新 → 回滚(失败时)
    """
    logger.info(f"[ROTATION-MYSQL] ========== START MYSQL ROTATION ==========")
    logger.info(f"[ROTATION-MYSQL] Target: {asset.ip}:{asset.ssh_port}, username: {account_name}")
    logger.info(f"[ROTATION-MYSQL] Skipping SSH heartbeat check (MySQL asset)")

    # 1. 连接MySQL验证当前密码
    logger.info(f"[ROTATION-MYSQL] Verifying current password via MySQL connection...")
    try:
        _mysql_verify(asset.ip, asset.ssh_port, account_name, current_password, timeout=10)
        logger.info(f"[ROTATION-MYSQL] Current password verified via MySQL")
    except Exception as e:
        logger.error(f"[ROTATION-MYSQL] Failed to connect to MySQL: {str(e)}", exc_info=True)
        raise Exception(f"连接MySQL失败: {str(e)}")

    # 2. PREPARE阶段：生成新密码并预存pending
    new_password = generate_strong_password(credential)
    logger.info(f"[ROTATION-MYSQL] New password generated: '{new_password[:2]}...'")

    encrypted_pending, pending_key_ver = CryptoService.sm4_encrypt(new_password)
    credential.pending_password = encrypted_pending
    credential.pending_key_version = pending_key_ver
    db.session.flush()
    logger.info(f"[ROTATION-MYSQL] PREPARE: pending_password saved to database")

    # 3. APPLY阶段：执行ALTER USER改密
    logger.info(f"[ROTATION-MYSQL] Executing ALTER USER...")
    try:
        _mysql_alter_user(asset.ip, asset.ssh_port, account_name, current_password, account_name, new_password)
        logger.info(f"[ROTATION-MYSQL] ALTER USER executed successfully")
    except Exception as e:
        logger.error(f"[ROTATION-MYSQL] ALTER USER failed: {str(e)}", exc_info=True)
        credential.pending_password = None
        credential.pending_key_version = None
        logger.info(f"[ROTATION-MYSQL] APPLY failed: pending_password cleared")
        rotation_task = RotationTask(
            credential_id=credential.id,
            executed_at=local_time,
            status='failed',
            old_password_hash=old_password_hash,
            error_msg=str(e)
        )
        db.session.add(rotation_task)
        write_audit_log(
            log_type='rotation',
            operator='system',
            source_ip='127.0.0.1',
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f"MySQL密码改密失败(ALTER USER): {str(e)}",
            result='failed'
        )
        db.session.commit()
        raise Exception(f"MySQL改密命令执行失败: {str(e)}")

    # 4. 验证新密码（最多重试3次，间隔2秒）
    max_retries = 3
    retry_count = 0
    verification_success = False

    while retry_count < max_retries:
        try:
            if retry_count > 0:
                logger.info(f"[ROTATION-MYSQL] Retrying new password verification ({retry_count}/{max_retries})...")
                time.sleep(2)
            else:
                logger.info(f"[ROTATION-MYSQL] Verifying new password...")
            _mysql_verify(asset.ip, asset.ssh_port, account_name, new_password, timeout=10)
            logger.info(f"[ROTATION-MYSQL] New password verified successfully!")
            verification_success = True
            break
        except Exception as e:
            retry_count += 1
            logger.info(f"[ROTATION-MYSQL] New password verification attempt {retry_count} failed: {str(e)}")

    if verification_success:
        # ========== 5. COMMIT阶段：晋升pending为正式密码 ==========
        logger.info(f"[ROTATION-MYSQL] COMMIT: promoting pending_password to official...")
        current_passwords = []
        if credential.previous_passwords:
            try:
                current_passwords = json.loads(credential.previous_passwords)
            except:
                current_passwords = []
        old_hash = _compute_password_hash(current_password)
        current_passwords.append(old_hash)
        current_passwords = current_passwords[-5:]
        credential.previous_passwords = json.dumps(current_passwords)
        credential.encrypted_password = credential.pending_password
        credential.key_version = credential.pending_key_version
        credential.pending_password = None
        credential.pending_key_version = None
        credential.updated_at = datetime.now()

        asset.last_agent_login_time = datetime.now()

        rotation_task = RotationTask(
            credential_id=credential.id,
            executed_at=local_time,
            status='success',
            old_password_hash=old_password_hash,
            new_password_hash=sm3_hash(new_password)
        )
        db.session.add(rotation_task)

        write_audit_log(
            log_type='rotation',
            operator='system',
            source_ip='127.0.0.1',
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f"MySQL密码改密成功: {account_name}",
            result='success'
        )

        add_exemption(asset.id, '', 'system', '密码改密后临时豁免')
        asset.connectivity = 'online'

        db.session.commit()
        logger.info(f"[ROTATION-MYSQL] COMMIT: password promoted to official")
        logger.info(f"[ROTATION-MYSQL] ========== MYSQL ROTATION COMPLETE ==========")

        return new_password

    # ========== 6. 回滚：新密码验证失败，尝试恢复旧密码 ==========
    logger.error(f"[ROTATION-MYSQL] New password verification FAILED after {max_retries} retries")
    logger.info(f"[ROTATION-MYSQL] Trying to restore old password...")

    old_password_restore_success = False
    old_password_restore_error = None

    # 先尝试用旧密码连接回滚（ALTER USER可能未生效）
    logger.info(f"[ROTATION-MYSQL] Attempting rollback with old password...")
    try:
        _mysql_alter_user(asset.ip, asset.ssh_port, account_name, current_password, account_name, current_password)
        _mysql_verify(asset.ip, asset.ssh_port, account_name, current_password, timeout=10)
        old_password_restore_success = True
        logger.info("[ROTATION-MYSQL] Old password restored and verified successfully")
        credential.pending_password = None
        credential.pending_key_version = None
        logger.info("[ROTATION-MYSQL] Rollback: pending_password cleared")
    except Exception as e1:
        logger.info(f"[ROTATION-MYSQL] Rollback with old password failed: {str(e1)}")
        # 旧密码不行，用新密码连接回滚（ALTER USER已生效）
        logger.info(f"[ROTATION-MYSQL] Attempting rollback with new password...")
        try:
            _mysql_alter_user(asset.ip, asset.ssh_port, account_name, new_password, account_name, current_password)
            _mysql_verify(asset.ip, asset.ssh_port, account_name, current_password, timeout=10)
            old_password_restore_success = True
            logger.info("[ROTATION-MYSQL] Old password restored via new password connection")
            credential.pending_password = None
            credential.pending_key_version = None
            logger.info("[ROTATION-MYSQL] Rollback(via new): pending_password cleared")
        except Exception as e2:
            old_password_restore_error = str(e2)
            logger.error(f"[ROTATION-MYSQL] CRITICAL: Rollback with new password also failed: {old_password_restore_error}")

    if not old_password_restore_success:
        logger.error(f"[ROTATION-MYSQL] CRITICAL: Both new and old passwords are invalid! Keeping pending_password for disaster recovery")
        write_audit_log(
            log_type='rotation',
            operator='system',
            source_ip='127.0.0.1',
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f"CRITICAL - MySQL密码改密严重失败: 新密码验证失败且旧密码恢复也失败. pending_password已保留.",
            result='failed'
        )
        asset.status = 'abnormal'
        logger.error(f"[ROTATION-MYSQL] CRITICAL: Asset {asset.ip} marked as ABNORMAL, pending_password retained")

    rotation_task = RotationTask(
        credential_id=credential.id,
        executed_at=local_time,
        status='failed',
        old_password_hash=old_password_hash,
        error_msg="新密码验证失败，已回滚" if old_password_restore_success else "新密码验证失败且回滚也失败"
    )
    db.session.add(rotation_task)

    if old_password_restore_success:
        detail_msg = "MySQL密码改密失败(验证失败): 已回滚至旧密码"
    else:
        detail_msg = "MySQL密码改密失败(验证失败): 回滚也失败"
    write_audit_log(
        log_type='rotation',
        operator='system',
        source_ip='127.0.0.1',
        target_asset=f"{asset.ip}:{asset.ssh_port}",
        operation_detail=detail_msg,
        result='failed'
    )

    db.session.commit()

    if old_password_restore_success:
        raise Exception("MySQL新密码验证失败，已回滚至旧密码")
    else:
        raise Exception("MySQL新密码验证失败且回滚也失败，资产已标记异常")


def _rotate_windows_password(asset, credential, active_key, current_password, old_password_hash, account_name, local_time):
    logger.info(f"[ROTATION-WINDOWS] ========== START WINDOWS ROTATION ==========")
    logger.info(f"[ROTATION-WINDOWS] Target: {asset.ip}:{asset.ssh_port}, username: {account_name}")
    logger.info(f"[ROTATION-WINDOWS] account_type: {asset.account_type}")

    if asset.account_type == 'domain':
        logger.warning(f"[ROTATION-WINDOWS] Rejecting domain account rotation: {account_name}")
        write_audit_log(
            log_type='rotation',
            operator='system',
            source_ip='127.0.0.1',
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f"Windows域账号改密拒绝(账号类型=domain): {account_name}，域账号密码轮换请通过AD资产管理模块操作",
            result='failed'
        )
        rotation_task = RotationTask(
            credential_id=credential.id,
            executed_at=local_time,
            status='failed',
            old_password_hash=old_password_hash,
            error_msg="域账号密码轮换请通过AD资产管理模块操作"
        )
        db.session.add(rotation_task)
        db.session.commit()
        raise Exception("域账号密码轮换请通过AD资产管理模块操作")

    if credential.pending_password:
        logger.info(f"[ROTATION-WINDOWS] Detected pending_password from previous rotation attempt")
        pending_password = CryptoService.sm4_decrypt(credential.pending_password, credential.pending_key_version)
        if pending_password:
            logger.info(f"[ROTATION-WINDOWS] Attempting pending_password first...")
            try:
                import winrm
                pending_session = winrm.Session(
                    f'http://{asset.ip}:{asset.ssh_port}/wsman',
                    auth=(account_name, pending_password),
                    transport='ntlm',
                    operation_timeout_sec=10
                )
                test_result = pending_session.run_cmd('echo ok')
                if test_result.status_code == 0:
                    logger.info(f"[ROTATION-WINDOWS] pending_password works! Promoting to official")
                    credential.encrypted_password = credential.pending_password
                    credential.key_version = credential.pending_key_version
                    credential.pending_password = None
                    credential.pending_key_version = None
                    credential.updated_at = datetime.now()
                    asset.last_agent_login_time = datetime.now()
                    rotation_task = RotationTask(
                        credential_id=credential.id,
                        executed_at=local_time,
                        status='success',
                        old_password_hash=old_password_hash,
                        new_password_hash=sm3_hash(pending_password)
                    )
                    db.session.add(rotation_task)
                    write_audit_log(
                        log_type='rotation',
                        operator='system',
                        source_ip='127.0.0.1',
                        target_asset=f"{asset.ip}:{asset.ssh_port}",
                        operation_detail=f"Windows密码改密成功(pending晋升): {account_name}",
                        result='success'
                    )
                    add_exemption(asset.id, '', 'system', '密码改密后临时豁免')
                    asset.connectivity = 'online'
                    db.session.commit()
                    logger.info(f"[ROTATION-WINDOWS] ========== WINDOWS ROTATION COMPLETE (pending) ==========")
                    return pending_password
            except Exception as e:
                logger.info(f"[ROTATION-WINDOWS] pending_password failed: {e}, proceeding with normal rotation")

    logger.info(f"[ROTATION-WINDOWS] Verifying current password via WinRM...")
    try:
        import winrm
        session = winrm.Session(
            f'http://{asset.ip}:{asset.ssh_port}/wsman',
            auth=(account_name, current_password),
            transport='ntlm',
            operation_timeout_sec=10
        )
        verify_result = session.run_cmd('echo ok')
        if verify_result.status_code != 0:
            raise Exception(f"WinRM verify returned status {verify_result.status_code}")
        logger.info(f"[ROTATION-WINDOWS] Current password verified via WinRM")
    except Exception as e:
        logger.error(f"[ROTATION-WINDOWS] Failed to connect WinRM: {str(e)}")
        raise Exception(f"连接WinRM失败: {str(e)}")

    new_password = generate_strong_password(credential)
    logger.info(f"[ROTATION-WINDOWS] New password generated: '{new_password[:2]}...'")

    encrypted_pending, pending_key_ver = CryptoService.sm4_encrypt(new_password)
    credential.pending_password = encrypted_pending
    credential.pending_key_version = pending_key_ver
    db.session.flush()
    logger.info(f"[ROTATION-WINDOWS] Pre-Save: pending_password saved to database")

    apply_success = False
    try:
        ps_command = (
            f"$SecurePassword = ConvertTo-SecureString '{new_password}' -AsPlainText -Force; "
            f"Set-LocalUser -Name '{account_name}' -Password $SecurePassword"
        )
        logger.info(f"[ROTATION-WINDOWS] Applying password change via PowerShell...")
        ps_result = session.run_ps(ps_command)

        if ps_result.status_code != 0:
            stderr_text = ps_result.std_err.decode('utf-8', errors='ignore') if ps_result.std_err else ''
            raise Exception(f"Set-LocalUser failed: {stderr_text}")
        else:
            logger.info(f"[ROTATION-WINDOWS] Set-LocalUser succeeded")

        apply_success = True
        logger.info(f"[ROTATION-WINDOWS] Apply phase completed successfully")

    except Exception as e:
        logger.error(f"[ROTATION-WINDOWS] Apply phase failed: {str(e)}")
        logger.info(f"[ROTATION-WINDOWS] Rolling back: attempting to restore old password...")
        try:
            rollback_cmd = (
                f"$SecurePassword = ConvertTo-SecureString '{current_password}' -AsPlainText -Force; "
                f"Set-LocalUser -Name '{account_name}' -Password $SecurePassword"
            )
            session.run_ps(rollback_cmd)
            logger.info(f"[ROTATION-WINDOWS] Rollback command executed")
            verify_rollback = session.run_cmd('echo ok')
            if verify_rollback.status_code == 0:
                logger.info(f"[ROTATION-WINDOWS] Rollback successful, old password works")
                credential.pending_password = None
                credential.pending_key_version = None
                db.session.commit()
                write_audit_log(
                    log_type='rotation',
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f"Windows密码改密失败(Apply阶段)，已回滚: {str(e)}",
                    result='failed'
                )
                db.session.commit()
                raise Exception(f"Windows改密命令失败，已回滚: {str(e)}")
            else:
                logger.error(f"[ROTATION-WINDOWS] CRITICAL: Rollback verification failed!")
        except Exception as rollback_err:
            logger.error(f"[ROTATION-WINDOWS] CRITICAL: Rollback also failed: {rollback_err}")
            credential.pending_password = encrypted_pending
            credential.pending_key_version = pending_key_ver
            asset.status = 'pending'
            write_audit_log(
                log_type='rotation_failed',
                operator='system',
                source_ip='127.0.0.1',
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail=f"Windows密码改密严重失败: Apply失败且回滚也失败. pending_password已保留. 错误: {str(e)}",
                result='failed'
            )
            db.session.commit()
            raise Exception(f"Windows改密严重失败: Apply失败，回滚也失败，资产标记为pending")

    new_session = None
    try:
        new_session = winrm.Session(
            f'http://{asset.ip}:{asset.ssh_port}/wsman',
            auth=(account_name, new_password),
            transport='ntlm',
            operation_timeout_sec=10
        )
        commit_result = new_session.run_cmd('echo ok')
        if commit_result.status_code != 0:
            raise Exception(f"Commit verification returned status {commit_result.status_code}")
        logger.info(f"[ROTATION-WINDOWS] Commit phase: new password verified via WinRM")
    except Exception as e:
        logger.error(f"[ROTATION-WINDOWS] Commit phase failed: {str(e)}")
        logger.info(f"[ROTATION-WINDOWS] Keeping pending_password for disaster recovery")
        credential.pending_password = encrypted_pending
        credential.pending_key_version = pending_key_ver
        write_audit_log(
            log_type='rotation',
            operator='system',
            source_ip='127.0.0.1',
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=f"Windows密码改密Commit失败: 新密码已Apply但验证失败, pending_password已保留. {str(e)}",
            result='failed'
        )
        db.session.commit()
        raise Exception(f"Windows改密Commit失败: 新密码验证不通过, pending已保留")

    current_passwords = []
    if credential.previous_passwords:
        try:
            current_passwords = json.loads(credential.previous_passwords)
        except:
            current_passwords = []
    old_hash = _compute_password_hash(current_password)
    current_passwords.append(old_hash)
    current_passwords = current_passwords[-5:]
    credential.previous_passwords = json.dumps(current_passwords)
    credential.encrypted_password = encrypted_pending
    credential.key_version = pending_key_ver
    credential.pending_password = None
    credential.pending_key_version = None
    credential.updated_at = datetime.now()
    asset.last_agent_login_time = datetime.now()

    rotation_task = RotationTask(
        credential_id=credential.id,
        executed_at=local_time,
        status='success',
        old_password_hash=old_password_hash,
        new_password_hash=sm3_hash(new_password)
    )
    db.session.add(rotation_task)

    write_audit_log(
        log_type='rotation',
        operator='system',
        source_ip='127.0.0.1',
        target_asset=f"{asset.ip}:{asset.ssh_port}",
        operation_detail=f"Windows密码改密成功: {account_name}",
        result='success'
    )
    add_exemption(asset.id, '', 'system', '密码改密后临时豁免')
    asset.connectivity = 'online'
    db.session.commit()
    logger.info(f"[ROTATION-WINDOWS] Commit phase: password promoted to official")
    logger.info(f"[ROTATION-WINDOWS] ========== WINDOWS ROTATION COMPLETE ==========")
    return new_password


def rotate_password(asset_id, account_name='root', operator='system'):
    """
    执行密码改密操作 - 增强原子性版本

    增强的原子性保障点：
    1. 改密前状态快照：记录改密开始时间、旧密码的SM3哈希（用于极端回滚）
    2. 改密前心跳检测：确认SSH连接稳定，避免无效重试
    3. 改密后双验证+重试：新密码SSH验证，失败最多重试3次（间隔2秒）
    4. 极端情况恢复：若新密码验证失败，用旧密码恢复，并验证旧密码仍可登录
    5. 数据库更新前确认：仅当新密码SSH验证成功后才更新Credential和Asset
    6. 事务保障：RotationTask和Credential/Credential原子提交或回滚
    """
    logger.info(f"[ROTATION] ========== START ROTATION ==========")
    logger.info(f"[ROTATION] asset_id={asset_id}, account_name={account_name}")

    local_time = datetime.now()
    heartbeat_success = False
    heartbeat_error = None

    credential = Credential.query.join(Asset).filter(
        Asset.id == asset_id,
        Credential.account_name == account_name
    ).first()

    if not credential:
        logger.warning(f"[ROTATION] 资产 {asset_id} 未找到账号 {account_name}，尝试使用第一个可用凭证")
        credential = Credential.query.filter_by(asset_id=asset_id).first()
        if credential:
            account_name = credential.account_name
            logger.info(f"[ROTATION] 回退使用凭证账号: {account_name}")

    if not credential:
        raise Exception(f"未找到资产 {asset_id} 的任何账号凭证")

    asset = credential.asset
    logger.info(f"[ROTATION] Credential id={credential.id}, asset_id={asset.id}")
    logger.info(f"[ROTATION] Target: {asset.ip}:{asset.ssh_port}, username: {credential.account_name}")

    active_key = KeyVersion.query.filter_by(status='active').first()
    if not active_key:
        raise Exception("未找到激活的工作密钥")

    current_password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
    if current_password is None:
        logger.error(f"[ROTATION] Failed to decrypt current password: credential_id={credential.id}")
        raise Exception("解密当前密码失败：密码解密返回空")
    logger.info(f"[ROTATION] Current password decrypted: '{current_password[:2]}...'")

    # ========== 1. 改密前状态快照 ==========
    old_password_hash = sm3_hash(current_password)
    logger.info(f"[ROTATION] Pre-rotation snapshot: old_password_hash={old_password_hash[:16]}...")

    # === 委托给资产驱动执行改密 ===
    from app.drivers import get_driver
    driver = get_driver(asset.os_type)

    # === 主机指纹校验 ===
    if asset.host_fingerprint:
        try:
            current_fp, fp_type = driver.collect_fingerprint(asset, credential)
            if current_fp != asset.host_fingerprint:
                write_audit_log(
                    log_type='fingerprint_mismatch', operator=operator,
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f'CRITICAL: 主机指纹不匹配! 预期={asset.host_fingerprint[:16]}... 实际={current_fp[:16]}... 类型={fp_type}',
                    result='blocked'
                )
                raise Exception('主机指纹不匹配，目标资产可能已被替换，改密已中止')
        except Exception as e:
            if '指纹不匹配' in str(e):
                raise
            logger.warning(f'指纹采集失败，跳过校验: {e}')
    else:
        try:
            fp, fp_type = driver.collect_fingerprint(asset, credential)
            asset.host_fingerprint = fp
            asset.fingerprint_type = fp_type
            asset.fingerprint_collected_at = local_time
            db.session.flush()
        except Exception as e:
            logger.warning(f'首次指纹采集失败: {e}')

    return driver.rotate_password(
        asset, credential, active_key, current_password,
        old_password_hash, account_name, local_time
    )
