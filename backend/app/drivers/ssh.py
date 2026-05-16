"""SSH/Linux资产驱动"""
import paramiko
import socket
import time
import hashlib
from datetime import datetime
from app.drivers.base import AssetDriver
from app.utils.logger import get_logger

logger = get_logger('app.drivers.ssh')


class SSHDriver(AssetDriver):
    os_type = 'linux'
    default_port = 22
    default_account_name = 'root'

    def test_connection(self, host, port, username, password, timeout=5):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host, port=port, username=username, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False
            )
            client.close()
            logger.info(f"SSH连接测试成功: {host}:{port} user={username}")
            return {"success": True, "message": "连接成功"}
        except paramiko.AuthenticationException:
            logger.info(f"SSH连接测试认证失败: {host}:{port} user={username}")
            return {"success": False, "message": "连接失败: 认证失败"}
        except socket.timeout:
            logger.info(f"SSH连接测试超时: {host}:{port}")
            return {"success": False, "message": "连接失败: 连接超时"}
        except socket.error as e:
            logger.info(f"SSH连接测试Socket错误: {host}:{port} - {str(e)}")
            return {"success": False, "message": f"连接失败: {str(e)}"}
        except Exception as e:
            logger.info(f"SSH连接测试异常: {host}:{port} - {str(e)}")
            return {"success": False, "message": f"连接失败: {str(e)}"}

    def get_password_change_cmd(self, os_type, account_name, new_password):
        os_lower = (os_type or '').lower()
        if os_lower in ['ubuntu', 'debian']:
            return f"echo '{account_name}:{new_password}' | chpasswd\n"
        elif os_lower in ['centos', 'rhel']:
            return f"echo '{new_password}' | passwd --stdin {account_name}\n"
        else:
            raise Exception(f"不支持的操作系统类型: {os_type}")

    def rotate_password(self, asset, credential, active_key, current_password,
                        old_password_hash, account_name, local_time):
        import json
        from app import db
        from app.models import RotationTask
        from app.services.crypto_service import CryptoService
        from app.services.audit_service import write_audit_log
        from app.services.password_rotation import (
            generate_strong_password, sm3_hash, ssh_heartbeat_check,
            _compute_password_hash
        )
        from app.services.bypass_exemption import add_exemption

        logger.info(f"[ROTATION-SSH] ========== START SSH ROTATION ==========")
        logger.info(f"[ROTATION-SSH] Target: {asset.ip}:{asset.ssh_port}, username: {account_name}")

        # 1. Heartbeat check
        logger.info(f"[ROTATION-SSH] Performing pre-rotation heartbeat check...")
        heartbeat_success, heartbeat_error = ssh_heartbeat_check(
            asset.ip, asset.ssh_port, account_name, current_password
        )
        if not heartbeat_success:
            logger.info(f"[ROTATION-SSH] Heartbeat check failed: {heartbeat_error}")
            logger.info(f"[ROTATION-SSH] Proceeding with rotation anyway (heartbeat is optional)...")
        else:
            logger.info(f"[ROTATION-SSH] Heartbeat check passed, connection is stable")

        # 2. Connect and verify current password
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            logger.info(f"[ROTATION-SSH] Connecting to {asset.ip}:{asset.ssh_port}...")
            client.connect(
                hostname=asset.ip, port=asset.ssh_port, username=account_name,
                password=current_password, timeout=10, allow_agent=False, look_for_keys=False
            )
            logger.info(f"[ROTATION-SSH] SSH connected successfully, current password verified")
        except Exception as e:
            logger.error(f"[ROTATION-SSH] Failed to connect: {str(e)}", exc_info=True)
            raise Exception(f"连接目标主机失败: {str(e)}")
        finally:
            client.close()

        # 3. PREPARE: Generate new password and save as pending
        new_password = generate_strong_password(credential)
        logger.info(f"[ROTATION-SSH] New password generated: '{new_password[:2]}...'")
        encrypted_pending, pending_key_ver = CryptoService.sm4_encrypt(new_password)
        credential.pending_password = encrypted_pending
        credential.pending_key_version = pending_key_ver
        db.session.flush()
        logger.info(f"[ROTATION-SSH] PREPARE: pending_password saved to database")

        # 4. APPLY: Execute password change command
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        os_type_lower = (asset.os_type or '').lower()

        try:
            logger.info(f"[ROTATION-SSH] Connecting again to execute password change...")
            client.connect(
                hostname=asset.ip, port=asset.ssh_port, username=account_name,
                password=current_password, timeout=10, allow_agent=False, look_for_keys=False
            )
            shell = client.invoke_shell()
            time.sleep(1)
            _ = shell.recv(1024)

            command = self.get_password_change_cmd(asset.os_type, account_name, new_password)
            safe_cmd = command.replace(new_password, '***')
            logger.info(f"[ROTATION-SSH] Executing command: {repr(safe_cmd)}")
            shell.send(command)
            time.sleep(2)
            output = b''
            while shell.recv_ready():
                output += shell.recv(4096)
            output_str = output.decode('utf-8')
            logger.info(f"[ROTATION-SSH] Command output: {repr(output_str)}")
            if 'error' in output_str.lower() or 'failed' in output_str.lower():
                raise Exception(f"改密命令执行失败: {output_str}")
            client.close()

            # 5. Verify new password with retries
            test_client = paramiko.SSHClient()
            test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            max_retries = 3
            retry_count = 0
            verification_success = False

            try:
                while retry_count < max_retries:
                    try:
                        if retry_count > 0:
                            logger.info(f"[ROTATION-SSH] Retrying new password verification ({retry_count}/{max_retries})...")
                            time.sleep(2)
                        else:
                            logger.info(f"[ROTATION-SSH] Verifying new password...")
                        test_client.connect(
                            hostname=asset.ip, port=asset.ssh_port, username=account_name,
                            password=new_password, timeout=10, allow_agent=False, look_for_keys=False
                        )
                        logger.info(f"[ROTATION-SSH] New password verified successfully!")
                        verification_success = True
                        break
                    except Exception as e:
                        retry_count += 1
                        logger.info(f"[ROTATION-SSH] Verification attempt {retry_count} failed: {str(e)}")
                        test_client.close()
                        test_client = paramiko.SSHClient()
                        test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                if not verification_success:
                    raise Exception(f"新密码验证失败，已重试 {max_retries} 次")

                # 6. COMMIT: Promote pending to official
                logger.info(f"[ROTATION-SSH] COMMIT: promoting pending_password to official...")
                current_passwords = []
                if credential.previous_passwords:
                    try:
                        current_passwords = json.loads(credential.previous_passwords)
                    except Exception:
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
                    credential_id=credential.id, executed_at=local_time,
                    status='success', old_password_hash=old_password_hash,
                    new_password_hash=sm3_hash(new_password)
                )
                db.session.add(rotation_task)
                write_audit_log(
                    log_type='rotation', operator='system', source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f"密码改密成功: {account_name}", result='success'
                )
                add_exemption(asset.id, '', 'system', '密码改密后临时豁免')
                asset.connectivity = 'online'
                db.session.commit()
                logger.info(f"[ROTATION-SSH] ========== SSH ROTATION COMPLETE ==========")
                return new_password

            except Exception as e:
                # 7. Rollback: Restore old password
                logger.error(f"[ROTATION-SSH] New password verification FAILED: {str(e)}")
                logger.info(f"[ROTATION-SSH] Trying to restore old password...")

                restore_client = paramiko.SSHClient()
                restore_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                old_password_restore_success = False
                old_password_restore_error = None

                try:
                    restore_client.connect(
                        hostname=asset.ip, port=asset.ssh_port, username=account_name,
                        password=current_password, timeout=10, allow_agent=False, look_for_keys=False
                    )
                    shell = restore_client.invoke_shell()
                    time.sleep(1)
                    _ = shell.recv(1024)
                    restore_command = self.get_password_change_cmd(asset.os_type, account_name, current_password)
                    safe_restore = restore_command.replace(current_password, '***')
                    logger.info(f"[ROTATION-SSH] Restore command: {repr(safe_restore)}")
                    shell.send(restore_command)
                    time.sleep(2)
                    _ = shell.recv(4096)
                    logger.info(f"[ROTATION-SSH] Verifying old password restoration...")
                    verify_client = paramiko.SSHClient()
                    verify_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        verify_client.connect(
                            hostname=asset.ip, port=asset.ssh_port, username=account_name,
                            password=current_password, timeout=10, allow_agent=False, look_for_keys=False
                        )
                        verify_client.close()
                        old_password_restore_success = True
                        logger.info("[ROTATION-SSH] Old password restored and verified")
                        credential.pending_password = None
                        credential.pending_key_version = None
                        logger.info("[ROTATION-SSH] Rollback: pending_password cleared")
                    except Exception as verify_err:
                        old_password_restore_error = str(verify_err)
                        logger.error(f"[ROTATION-SSH] CRITICAL: Old password restoration FAILED: {old_password_restore_error}")
                        logger.error(f"[ROTATION-SSH] CRITICAL: Both passwords invalid! Keeping pending_password")
                        write_audit_log(
                            log_type='rotation', operator='system', source_ip='127.0.0.1',
                            target_asset=f"{asset.ip}:{asset.ssh_port}",
                            operation_detail=f"CRITICAL - 密码改密严重失败: 新密码验证失败且旧密码恢复也失败. pending_password已保留. 错误: {str(e)}, 恢复验证错误: {old_password_restore_error}",
                            result='failed'
                        )
                        asset.status = 'abnormal'
                        logger.error(f"[ROTATION-SSH] CRITICAL: Asset {asset.ip} marked as ABNORMAL")
                except Exception as restore_error:
                    old_password_restore_error = str(restore_error)
                    logger.error(f"[ROTATION-SSH] CRITICAL: Failed to restore old password: {str(restore_error)}")
                    write_audit_log(
                        log_type='rotation', operator='system', source_ip='127.0.0.1',
                        target_asset=f"{asset.ip}:{asset.ssh_port}",
                        operation_detail=f"CRITICAL - 密码改密严重失败: 新密码验证失败且旧密码恢复也失败. pending_password已保留. 原始错误: {str(e)}, 恢复错误: {old_password_restore_error}",
                        result='failed'
                    )
                    asset.status = 'abnormal'
                    logger.error(f"[ROTATION-SSH] CRITICAL: Asset {asset.ip} marked as ABNORMAL")
                finally:
                    restore_client.close()

                rotation_task = RotationTask(
                    credential_id=credential.id, executed_at=local_time,
                    status='failed', old_password_hash=old_password_hash, error_msg=str(e)
                )
                db.session.add(rotation_task)
                write_audit_log(
                    log_type='rotation', operator='system', source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f"密码改密失败: {str(e)}", result='failed'
                )
                db.session.commit()
                raise Exception(f"新密码验证失败: {str(e)}")
            finally:
                test_client.close()

        except Exception as e:
            logger.error(f"[ROTATION-SSH] Outer exception: {str(e)}")
            credential.pending_password = None
            credential.pending_key_version = None
            logger.info(f"[ROTATION-SSH] APPLY/outer failed: pending_password cleared")
            rotation_task = RotationTask(
                credential_id=credential.id, executed_at=local_time,
                status='failed', old_password_hash=old_password_hash, error_msg=str(e)
            )
            db.session.add(rotation_task)
            write_audit_log(
                log_type='rotation', operator='system', source_ip='127.0.0.1',
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail=f"密码改密失败: {str(e)}", result='failed'
            )
            db.session.commit()
            raise Exception(f"执行改密命令失败: {str(e)}")
        finally:
            client.close()

    def detect_bypass(self, asset):
        from app.services.bypass_detector import _detect_ssh_bypass
        return _detect_ssh_bypass(asset)

    def check_connectivity(self, asset, credential):
        from app.services.crypto_service import CryptoService
        try:
            password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
            if not password:
                return {"success": False, "message": "密码解密失败"}
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=asset.ip, port=asset.ssh_port, username=credential.account_name,
                password=password, timeout=5, allow_agent=False, look_for_keys=False
            )
            _, stdout, _ = client.exec_command('echo ok', timeout=5)
            result = stdout.read().decode().strip()
            client.close()
            if result == 'ok':
                return {"success": True, "message": "连接成功"}
            return {"success": False, "message": f"unexpected output: {result}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def collect_fingerprint(self, asset, credential):
        from app.services.crypto_service import CryptoService
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        client.connect(hostname=asset.ip, port=asset.ssh_port, username=credential.account_name,
                       password=password, timeout=10, allow_agent=False, look_for_keys=False)
        key = client.get_transport().get_remote_server_key()
        fingerprint = hashlib.sha256(str(key).encode()).hexdigest()
        client.close()
        return fingerprint, 'ssh-host-key-sha256'

    def recover_pending_password(self, asset, credential):
        from app import db
        from app.services.crypto_service import CryptoService
        from app.services.audit_service import write_audit_log
        from datetime import datetime
        try:
            pending_pwd = CryptoService.sm4_decrypt(credential.pending_password, credential.pending_key_version)
            if not pending_pwd:
                return False
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=asset.ip, port=asset.ssh_port, username=credential.account_name,
                password=pending_pwd, timeout=10, allow_agent=False, look_for_keys=False
            )
            client.close()
            logger.info(f"[RECOVERY-SSH] pending_password works for {asset.ip}, promoting to official")
            credential.encrypted_password = credential.pending_password
            credential.key_version = credential.pending_key_version
            credential.pending_password = None
            credential.pending_key_version = None
            credential.updated_at = datetime.now()
            asset.last_agent_login_time = datetime.now()
            asset.connectivity = 'online'
            db.session.commit()
            write_audit_log(
                log_type='system_notice', operator='system', source_ip='127.0.0.1',
                target_asset=f"{asset.ip}:{asset.ssh_port}",
                operation_detail=f"资产 {asset.ip} pending_password 容灾恢复成功（已晋升为正式密码）",
                result='success'
            )
            return True
        except Exception:
            try:
                official_pwd = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
                if official_pwd:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        hostname=asset.ip, port=asset.ssh_port, username=credential.account_name,
                        password=official_pwd, timeout=10, allow_agent=False, look_for_keys=False
                    )
                    client.close()
                    credential.pending_password = None
                    credential.pending_key_version = None
                    db.session.commit()
                    logger.info(f"[RECOVERY-SSH] pending_password invalid, official password works for {asset.ip}, cleared pending")
            except Exception:
                pass
            return False
