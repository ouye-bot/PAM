from app.drivers import get_driver
from app.utils.logger import get_logger

logger = get_logger('app.services.connection_tester')


def test_connection(asset_type, host, port, username, password, connect_timeout=5):
    """统一连接测试函数（委托给资产驱动）"""
    driver = get_driver(asset_type)
    return driver.test_connection(host, port, username, password, connect_timeout)
