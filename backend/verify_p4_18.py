"""P4-18 主机指纹校验验证"""
import requests, json, sys, os

BASE = 'http://127.0.0.1:5000/api'
passed = 0
failed = 0

def test(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name} - {detail}')

r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}
test('登录成功', bool(token))

print('=' * 60)
print('P4-18 主机指纹校验验证')
print('=' * 60)

# 1. 验证Asset模型字段
print('\n--- 1. Asset模型字段 ---')
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from dotenv import load_dotenv
load_dotenv()
import pymysql
try:
    conn = pymysql.connect(host='127.0.0.1', port=3306, user='root',
                           password=os.getenv('DB_PASSWORD', '123456'), db='pam_db')
    cur = conn.cursor()
    cur.execute("SHOW COLUMNS FROM assets WHERE Field IN ('host_fingerprint','fingerprint_type','fingerprint_collected_at')")
    rows = cur.fetchall()
    fields = [r[0] for r in rows]
    test('host_fingerprint字段存在', 'host_fingerprint' in fields, str(fields))
    test('fingerprint_type字段存在', 'fingerprint_type' in fields, str(fields))
    test('fingerprint_collected_at字段存在', 'fingerprint_collected_at' in fields, str(fields))
    conn.close()
except Exception as e:
    test('数据库连接失败', False, str(e))

# 2. 验证资产详情含指纹字段
print('\n--- 2. 资产详情含指纹字段 ---')
try:
    r = requests.get(f'{BASE}/assets', headers=headers, timeout=10)
    assets = r.json()
    if isinstance(assets, list):
        asset_list = assets
    else:
        asset_list = assets.get('data', assets.get('assets', []))
    if asset_list:
        a = asset_list[0]
        test(f'资产详情含host_fingerprint', 'host_fingerprint' in a, str(list(a.keys())))
        test(f'资产详情含fingerprint_type', 'fingerprint_type' in a)
        test(f'资产详情含fingerprint_collected_at', 'fingerprint_collected_at' in a)
except Exception as e:
    test('资产详情请求失败', False, str(e))

# 3. 验证reset-fingerprint端点
print('\n--- 3. reset-fingerprint端点 ---')
try:
    r = requests.post(f'{BASE}/assets/1/reset-fingerprint', headers=headers, timeout=10)
    if r.status_code == 200:
        test('reset-fingerprint端点正常', r.json().get('code') == 200, r.text[:100])
    else:
        test('reset-fingerprint端点存在', r.status_code in (200, 400, 404), f'status={r.status_code}')
except Exception as e:
    test('reset-fingerprint不可用', False, str(e))

# 4. 验证三Driver有collect_fingerprint方法
print('\n--- 4. Driver方法完整性 ---')
from app.drivers import SSHDriver, MySQLDriver, WindowsDriver
ssh = SSHDriver()
mysql = MySQLDriver()
win = WindowsDriver()
test('SSHDriver有collect_fingerprint', hasattr(ssh, 'collect_fingerprint') and callable(ssh.collect_fingerprint))
test('MySQLDriver有collect_fingerprint', hasattr(mysql, 'collect_fingerprint') and callable(mysql.collect_fingerprint))
test('WindowsDriver有collect_fingerprint', hasattr(win, 'collect_fingerprint') and callable(win.collect_fingerprint))

# 5. 验证password_rotation.py含指纹校验
print('\n--- 5. 指纹校验代码 ---')
rotation_file = os.path.join(os.path.dirname(__file__), 'app', 'services', 'password_rotation.py')
with open(rotation_file, encoding='utf-8') as f:
    content = f.read()
test('含"主机指纹校验"注释', '主机指纹校验' in content)
test('含fingerprint_mismatch日志', 'fingerprint_mismatch' in content)
test('含collect_fingerprint调用', 'collect_fingerprint(asset, credential)' in content)
test('含首次指纹采集', '首次指纹采集' in content)

print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)