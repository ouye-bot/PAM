"""MySQL资产驱动"""
import pymysql
import socket
from datetime import datetime
from app.drivers.base import AssetDriver
from app.utils.logger import get_logger

logger = get_logger('app.drivers.mysql')


class MySQLDriver(AssetDriver):
    os_type = 'mysql'
    default_port = 3306
    default_account_name = 'root'
    supports_exemption = False

    def get_log_type_prefix(self) -> str:
        return '_MYSQL'

    def test_connection(self, host, port, username, password, timeout=5):
        try:
            conn = pymysql.connect(
                host=host, port=port, user=username, password=password,
                connect_timeout=timeout, read_timeout=timeout
            )
            conn.close()
            logger.info(f"MySQL连接测试成功: {host}:{port} user={username}")
            return {"success": True, "message": "连接成功"}
        except pymysql.err.OperationalError as e:
            code, msg = e.args if len(e.args) == 2 else (0, str(e))
            logger.info(f"MySQL连接测试失败: {host}:{port} - {msg}")
            return {"success": False, "message": f"连接失败: {msg}"}
        except Exception as e:
            logger.info(f"MySQL连接测试异常: {host}:{port} - {str(e)}")
            return {"success": False, "message": f"连接失败: {str(e)}"}

    def rotate_password(self, asset, credential, active_key, current_password,
                        old_password_hash, account_name, local_time):
        from app.services.password_rotation import _rotate_mysql_password
        return _rotate_mysql_password(
            asset, credential, active_key, current_password,
            old_password_hash, account_name, local_time
        )

    def detect_bypass(self, asset):
        from app.services.bypass_detector import detect_bypass_for_mysql_asset
        return detect_bypass_for_mysql_asset(asset)

    def check_connectivity(self, asset, credential):
        from app.services.crypto_service import CryptoService
        try:
            password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
            if not password:
                return {"success": False, "message": "密码解密失败"}
            conn = pymysql.connect(
                host=asset.ip, port=asset.ssh_port or 3306,
                user=credential.account_name, password=password,
                connect_timeout=5
            )
            conn.close()
            return {"success": True, "message": "连接成功"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def collect_fingerprint(self, asset, credential):
        from app.services.crypto_service import CryptoService
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        conn = pymysql.connect(host=asset.ip, port=asset.ssh_port or 3306,
                               user=credential.account_name, password=password, connect_timeout=10)
        cursor = conn.cursor()
        cursor.execute("SELECT @@server_uuid")
        uuid_val = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return uuid_val, 'mysql-server-uuid'

    def recover_pending_password(self, asset, credential):
        from app import db
        from app.services.crypto_service import CryptoService
        from app.services.audit_service import write_audit_log
        from datetime import datetime
        try:
            pending_pwd = CryptoService.sm4_decrypt(credential.pending_password, credential.pending_key_version)
            if not pending_pwd:
                return False
            conn = pymysql.connect(
                host=asset.ip, port=asset.ssh_port or 3306,
                user=credential.account_name, password=pending_pwd,
                connect_timeout=5
            )
            conn.close()
            logger.info(f"[RECOVERY-MYSQL] pending_password works for {asset.ip}, promoting to official")
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
                operation_detail=f"MySQL资产 {asset.ip} pending_password 容灾恢复成功（已晋升为正式密码）",
                result='success'
            )
            return True
        except Exception:
            try:
                official_pwd = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
                if official_pwd:
                    conn = pymysql.connect(
                        host=asset.ip, port=asset.ssh_port or 3306,
                        user=credential.account_name, password=official_pwd,
                        connect_timeout=5
                    )
                    conn.close()
                    credential.pending_password = None
                    credential.pending_key_version = None
                    db.session.commit()
                    logger.info(f"[RECOVERY-MYSQL] pending_password invalid, official password still works for {asset.ip}, cleared pending")
            except Exception:
                pass
            return False
