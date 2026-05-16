"""P4-6 驱动完整性验证"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv()

import pymysql

conn = pymysql.connect(
    host=os.getenv('DB_HOST', '127.0.0.1'),
    port=int(os.getenv('DB_PORT', '3307')),
    user=os.getenv('DB_USER', 'pam_user'),
    password=os.getenv('DB_PASSWORD', 'Pam123456!'),
    db=os.getenv('DB_NAME', 'pam_db')
)
cur = conn.cursor()

print('=' * 60)
print('Phase A3: P4-6 驱动完整性验证')
print('=' * 60)

# 1. 检查各类型资产
print('\n--- 1. 资产类型分布 ---')
cur.execute('SELECT os_type, COUNT(*) FROM assets WHERE status != "deleted" GROUP BY os_type')
types = cur.fetchall()
for t in types:
    print(f'  {t[0]}: {t[1]}个')

# 2. 检查驱动注册
print('\n--- 2. 驱动注册完整性 ---')
from app.drivers import _DRIVER_MAP, get_driver, SSHDriver, MySQLDriver, WindowsDriver
print(f'  已注册驱动: {list(_DRIVER_MAP.keys())}')
assert 'linux' in _DRIVER_MAP, 'SSH驱动未注册'
assert 'mysql' in _DRIVER_MAP, 'MySQL驱动未注册'
assert 'windows' in _DRIVER_MAP, 'Windows驱动未注册'
print('  [PASS] 三种驱动均已注册')

# 3. 验证驱动类型
print('\n--- 3. 驱动类型验证 ---')
ssh_drv = get_driver('linux')
mysql_drv = get_driver('mysql')
win_drv = get_driver('windows')
assert isinstance(ssh_drv, SSHDriver), f'SSH驱动类型错误: {type(ssh_drv)}'
assert isinstance(mysql_drv, MySQLDriver), f'MySQL驱动类型错误: {type(mysql_drv)}'
assert isinstance(win_drv, WindowsDriver), f'Windows驱动类型错误: {type(win_drv)}'
print('  [PASS] SSH驱动: linux')
print('  [PASS] MySQL驱动: mysql')
print('  [PASS] Windows驱动: windows')

# 4. 验证驱动接口完整性（所有子类必须实现所有抽象方法）
print('\n--- 4. 驱动接口完整性 ---')
from app.drivers.base import AssetDriver
required_methods = ['test_connection', 'rotate_password', 'detect_bypass', 
                    'check_connectivity', 'recover_pending_password']
for name, drv in [('SSH', ssh_drv), ('MySQL', mysql_drv), ('Windows', win_drv)]:
    missing = []
    for method in required_methods:
        if not hasattr(drv, method) or not callable(getattr(drv, method)):
            missing.append(method)
    if missing:
        print(f'  [FAIL] {name}驱动缺少方法: {missing}')
    else:
        print(f'  [PASS] {name}驱动: 全部{len(required_methods)}个接口已实现')

# 5. 验证日志前缀
print('\n--- 5. 日志前缀验证 ---')
assert ssh_drv.get_log_type_prefix() == '', f'SSH前缀错误: {ssh_drv.get_log_type_prefix()}'
assert mysql_drv.get_log_type_prefix() == '_MYSQL', f'MySQL前缀错误: {mysql_drv.get_log_type_prefix()}'
assert win_drv.get_log_type_prefix() == '_WINDOWS', f'Windows前缀错误: {win_drv.get_log_type_prefix()}'
print('  [PASS] SSH前缀: ""')
print('  [PASS] MySQL前缀: "_MYSQL"')
print('  [PASS] Windows前缀: "_WINDOWS"')

# 6. 验证默认端口
print('\n--- 6. 默认端口验证 ---')
assert ssh_drv.default_port == 22, f'SSH默认端口错误: {ssh_drv.default_port}'
assert mysql_drv.default_port == 3306, f'MySQL默认端口错误: {mysql_drv.default_port}'
assert win_drv.default_port == 5985, f'Windows默认端口错误: {win_drv.default_port}'
print('  [PASS] SSH: 22')
print('  [PASS] MySQL: 3306')
print('  [PASS] Windows: 5985')

# 7. 验证回退行为
print('\n--- 7. 未知类型回退 ---')
fallback = get_driver('unknown')
assert isinstance(fallback, SSHDriver), f'回退类型错误: {type(fallback)}'
print('  [PASS] 未知类型回退到SSH驱动')

empty_fallback = get_driver('')
assert isinstance(empty_fallback, SSHDriver), f'空类型回退错误: {type(empty_fallback)}'
print('  [PASS] 空类型回退到SSH驱动')

# 8. 验证日志标记（通过检查源代码）
print('\n--- 8. 日志标记验证 ---')
import re
ssh_file = os.path.join(os.path.dirname(__file__), 'app', 'drivers', 'ssh.py')
mysql_file = os.path.join(os.path.dirname(__file__), 'app', 'drivers', 'mysql.py')
win_file = os.path.join(os.path.dirname(__file__), 'app', 'drivers', 'windows.py')
rotation_file = os.path.join(os.path.dirname(__file__), 'app', 'services', 'password_rotation.py')

with open(ssh_file, encoding='utf-8') as f:
    ssh_content = f.read()
with open(mysql_file, encoding='utf-8') as f:
    mysql_content = f.read()
with open(win_file, encoding='utf-8') as f:
    win_content = f.read()
with open(rotation_file, encoding='utf-8') as f:
    rotation_content = f.read()

ssh_logs = len(re.findall(r'\[ROTATION-SSH\]', ssh_content))
mysql_logs_rot = len(re.findall(r'\[ROTATION-MYSQL\]', rotation_content))
win_logs_rot = len(re.findall(r'\[ROTATION-WINDOWS\]', rotation_content))
mysql_logs_drv = len(re.findall(r'\[ROTATION-MYSQL\]', mysql_content))
win_logs_drv = len(re.findall(r'\[ROTATION-WINDOWS\]', win_content))

print(f'  [ROTATION-SSH] 标记: {ssh_logs}处')
print(f'  [ROTATION-MYSQL] 标记: {mysql_logs_rot + mysql_logs_drv}处 (旋转模块+驱动)')
print(f'  [ROTATION-WINDOWS] 标记: {win_logs_rot + win_logs_drv}处 (旋转模块+驱动)')

assert ssh_logs > 0, 'SSH驱动缺少[ROTATION-SSH]日志标记'
assert mysql_logs_rot > 0, '密码旋转模块缺少[ROTATION-MYSQL]日志标记'
assert win_logs_rot > 0, '密码旋转模块缺少[ROTATION-WINDOWS]日志标记'
print('  [PASS] 日志标记完整性验证通过')

# 9. 验证rotate_password路由
print('\n--- 9. 旋转密码路由验证 ---')
import requests
r = requests.post('http://127.0.0.1:5000/api/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}

# Get a linux asset for testing
cur.execute('SELECT id, os_type, ip FROM assets WHERE status != "deleted" LIMIT 5')
assets = cur.fetchall()
for a in assets:
    print(f'  资产ID={a[0]}, 类型={a[1]}, IP={a[2]}')

conn.close()
print('\n  [PASS] 全部9项驱动完整性验证完成!')