"""资产驱动注册与工厂"""

from app.drivers.base import AssetDriver

_DRIVER_MAP: dict[str, AssetDriver] = {}


def register_driver(driver: AssetDriver):
    """注册驱动"""
    _DRIVER_MAP[driver.os_type.lower()] = driver


def get_driver(os_type: str) -> AssetDriver:
    """根据 os_type 获取驱动实例"""
    if not os_type:
        from app.drivers.ssh import SSHDriver
        return SSHDriver()
    key = os_type.lower()
    if key in _DRIVER_MAP:
        return _DRIVER_MAP[key]
    # 未知类型回退到 SSH 驱动
    from app.drivers.ssh import SSHDriver
    return SSHDriver()


# 自动注册
from app.drivers.ssh import SSHDriver
from app.drivers.mysql import MySQLDriver
from app.drivers.windows import WindowsDriver

register_driver(SSHDriver())
register_driver(MySQLDriver())
register_driver(WindowsDriver())
