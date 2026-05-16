"""资产驱动抽象基类 —— 定义统一接口，子类各自实现具体协议"""

from abc import ABC, abstractmethod


class AssetDriver(ABC):
    os_type: str = 'linux'
    default_port: int = 22
    default_account_name: str = 'root'
    supports_exemption: bool = True

    @abstractmethod
    def test_connection(self, host: str, port: int, username: str,
                        password: str, timeout: int = 5) -> dict:
        """连接测试，返回 {'success': bool, 'message': str}"""
        ...

    @abstractmethod
    def rotate_password(self, asset, credential, active_key, current_password: str,
                        old_password_hash: str, account_name: str,
                        local_time) -> str:
        """执行改密操作，返回新密码"""
        ...

    @abstractmethod
    def detect_bypass(self, asset) -> tuple:
        """绕行检测，返回 (detected: bool, detail: str)"""
        ...

    @abstractmethod
    def check_connectivity(self, asset, credential) -> dict:
        """连通性检查，返回 {'success': bool, 'message': str}"""
        ...

    @abstractmethod
    def recover_pending_password(self, asset, credential) -> bool:
        """尝试用 pending_password 恢复连接，成功返回 True"""
        ...

    def get_log_type_prefix(self) -> str:
        return ''
