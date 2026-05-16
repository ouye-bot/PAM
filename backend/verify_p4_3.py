"""P4-3 审计哈希链可视化验证"""
import requests, json, sys

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

# Login
r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}
test('登录成功', bool(token))

print('=' * 60)
print('P4-3 审计哈希链可视化验证')
print('=' * 60)

# 1. 验证端点可用
print('\n--- 1. 验证端点 ---')
try:
    r = requests.get(f'{BASE}/audit/verify', headers=headers, timeout=10)
    test('verify返回200', r.status_code == 200, str(r.status_code))
    if r.status_code == 200:
        data = r.json().get('data', {})
        test('返回valid字段', 'valid' in data, str(data))
        test('返回total_logs字段', 'total_logs' in data, str(data))
        test('返回latest_timestamp字段', 'latest_timestamp' in data, str(data))
        test('哈希链完整', data.get('valid') == True, f'broken_at={data.get("broken_at")}')
        test('无断裂点', data.get('broken_at') is None, str(data))
        print(f'  总日志数: {data.get("total_logs")}')
        print(f'  最新日志: {data.get("latest_timestamp")}')
except Exception as e:
    test('verify请求失败', False, str(e))

# 2. 验证审计日志列表
print('\n--- 2. 审计日志列表 ---')
try:
    r = requests.get(f'{BASE}/audit/logs', headers=headers, params={'page':1, 'page_size':5}, timeout=10)
    test('日志列表返回200', r.status_code == 200, str(r.status_code))
    if r.status_code == 200:
        data = r.json()
        items = data.get('data', {}).get('items', data.get('items', []))
        test('可获取日志列表', len(items) > 0, f'共{len(items)}条')
        if items:
            log = items[0]
            test('日志含previous_hash', 'previous_hash' in log, str(list(log.keys())[:5]))
            test('日志含current_hash', 'current_hash' in log, str(list(log.keys())[:5]))
except Exception as e:
    test('日志列表请求失败', False, str(e))

# 3. 验证前端编译产物
print('\n--- 3. 前端编译 ---')
import os
dist_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist', 'assets')
audit_files = [f for f in os.listdir(dist_dir) if 'AuditLog' in f]
test('AuditLog前端编译产物存在', len(audit_files) > 0, str(audit_files))
for f in audit_files:
    size = os.path.getsize(os.path.join(dist_dir, f))
    print(f'  编译产物: {f} ({size} bytes)')

# 汇总
print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)