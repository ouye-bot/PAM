"""Windows/WinRM资产驱动"""
import winrm
import socket
from datetime import datetime
from app.drivers.base import AssetDriver
from app.utils.logger import get_logger

logger = get_logger('app.drivers.windows')


class WindowsDriver(AssetDriver):
    os_type = 'windows'
    default_port = 5985
    default_account_name = 'Administrator'

    def get_log_type_prefix(self) -> str:
        return '_WINDOWS'

    def test_connection(self, host, port, username, password, timeout=5):
        try:
            session = winrm.Session(
                f'http://{host}:{port}/wsman',
                auth=(username, password),
                transport='ntlm',
                operation_timeout_sec=timeout
            )
            result = session.run_cmd('echo "PAM connection test"')
            if result.status_code == 0:
                logger.info(f"WinRM连接测试成功: {host}:{port} user={username}")
                return {"success": True, "message": "连接成功"}
            else:
                err_msg = result.std_err.decode('utf-8', errors='ignore')
                logger.info(f"WinRM连接测试失败: {host}:{port} - {err_msg}")
                return {"success": False, "message": f"连接失败: {err_msg}"}
        except winrm.exceptions.AuthenticationError:
            logger.info(f"WinRM连接测试认证失败: {host}:{port} user={username}")
            return {"success": False, "message": "连接失败: 认证失败，用户名或密码错误"}
        except (ConnectionRefusedError, socket.error):
            logger.info(f"WinRM连接测试拒绝连接: {host}:{port}")
            return {"success": False, "message": "连接失败: 目标主机拒绝连接或端口不可达"}
        except socket.timeout:
            logger.info(f"WinRM连接测试超时: {host}:{port}")
            return {"success": False, "message": "连接超时: 目标主机无响应"}
        except Exception as e:
            err_str = str(e)
            if password and password in err_str:
                err_str = err_str.replace(password, '***')
            logger.info(f"WinRM连接测试异常: {host}:{port} - {err_str}")
            return {"success": False, "message": f"连接失败: {err_str}"}

    def rotate_password(self, asset, credential, active_key, current_password,
                        old_password_hash, account_name, local_time):
        from app.services.password_rotation import _rotate_windows_password
        return _rotate_windows_password(
            asset, credential, active_key, current_password,
            old_password_hash, account_name, local_time
        )

    def detect_bypass(self, asset):
        from app.services.bypass_detector import detect_windows_bypass
        return detect_windows_bypass(asset)

    def check_connectivity(self, asset, credential):
        from app.services.crypto_service import CryptoService
        try:
            password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
            if not password:
                return {"success": False, "message": "密码解密失败"}
            import winrm as wr
            ws = wr.Session(
                f'http://{asset.ip}:{asset.ssh_port}/wsman',
                auth=(credential.account_name, password),
                transport='ntlm',
                operation_timeout_sec=10
            )
            del password
            r = ws.run_cmd('echo ok')
            if r.status_code == 0:
                return {"success": True, "message": "连接成功"}
            return {"success": False, "message": f"status_code={r.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def collect_fingerprint(self, asset, credential):
        from app.services.crypto_service import CryptoService
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        session = winrm.Session(f'http://{asset.ip}:{asset.ssh_port}/wsman',
                                auth=(credential.account_name, password), transport='ntlm')
        r = session.run_ps('(Get-CimInstance Win32_ComputerSystemProduct).UUID')
        uuid_val = r.std_out.decode('utf-8').strip()
        return uuid_val, 'windows-system-uuid'

    def recover_pending_password(self, asset, credential):
        from app import db
        from app.services.crypto_service import CryptoService
        from app.services.audit_service import write_audit_log
        from datetime import datetime
        try:
            pending_pwd = CryptoService.sm4_decrypt(credential.pending_password, credential.pending_key_version)
            if not pending_pwd:
                return False
            ws = winrm.Session(
                f'http://{asset.ip}:{asset.ssh_port}/wsman',
                auth=(credential.account_name, pending_pwd),
                transport='ntlm',
                operation_timeout_sec=10
            )
            r = ws.run_cmd('echo ok')
            if r.status_code == 0:
                logger.info(f"[RECOVERY-WINDOWS] pending_password works for {asset.ip}, promoting to official")
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
                    operation_detail=f"Windows资产 {asset.ip} pending_password 容灾恢复成功（已晋升为正式密码）",
                    result='success'
                )
                return True
        except Exception:
            pass
        try:
            official_pwd = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
            if official_pwd:
                ws = winrm.Session(
                    f'http://{asset.ip}:{asset.ssh_port}/wsman',
                    auth=(credential.account_name, official_pwd),
                    transport='ntlm',
                    operation_timeout_sec=10
                )
                r = ws.run_cmd('echo ok')
                if r.status_code == 0:
                    credential.pending_password = None
                    credential.pending_key_version = None
                    db.session.commit()
                    logger.info(f"[RECOVERY-WINDOWS] pending_password invalid, official password works for {asset.ip}, cleared pending")
        except Exception:
            pass
        return False
