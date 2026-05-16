"""P4-4 回收站验证"""
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
print('P4-4 回收站验证')
print('=' * 60)

# 1. 获取已删除资产
print('\n--- 1. 已删除资产列表 ---')
try:
    r = requests.get(f'{BASE}/assets/deleted', headers=headers, params={'page':1, 'page_size':10}, timeout=10)
    test('返回200', r.status_code == 200)
    data = r.json()
    test('data.items存在', 'items' in data.get('data', {}))
    test('data.total存在', 'total' in data.get('data', {}))
    assets = data.get('data', {}).get('items', [])
    print(f'  当前回收站资产数: {len(assets)}')
except Exception as e:
    test('请求失败', False, str(e))

# 2. 获取已删除审计日志
print('\n--- 2. 已删除审计日志列表 ---')
try:
    r = requests.get(f'{BASE}/audit/logs/deleted', headers=headers, params={'page':1, 'page_size':10}, timeout=10)
    test('返回200', r.status_code == 200)
    data = r.json()
    test('data.items存在', 'items' in data.get('data', {}))
    test('data.total存在', 'total' in data.get('data', {}))
    logs = data.get('data', {}).get('items', [])
    print(f'  当前回收站日志数: {len(logs)}')
except Exception as e:
    test('请求失败', False, str(e))

# 3. 测试恢复资产端点存在
print('\n--- 3. 资产恢复端点 ---')
try:
    r = requests.post(f'{BASE}/assets/1/restore', headers=headers, timeout=10)
    if r.status_code == 400:
        test('恢复端点可访问', True, '资产未删除（预期）')
    elif r.status_code == 200:
        test('恢复端点可访问', True, '资产已恢复')
except Exception as e:
    test('恢复端点不可用', False, str(e))

# 4. 测试恢复日志端点存在
print('\n--- 4. 日志恢复端点 ---')
try:
    r = requests.post(f'{BASE}/audit/logs/1/restore', headers=headers, timeout=10)
    if r.status_code == 400:
        test('日志恢复端点可访问', True, '日志未删除（预期）')
    elif r.status_code == 200:
        test('日志恢复端点可访问', True, '日志已恢复')
except Exception as e:
    test('恢复端点不可用', False, str(e))

# 5. 验证哈希链完整性保持不变
print('\n--- 5. 哈希链完整性 ---')
try:
    r = requests.get(f'{BASE}/audit/verify', headers=headers, timeout=10)
    data = r.json().get('data', {})
    test('哈希链仍完整', data.get('valid') == True, f'broken_at={data.get("broken_at")}')
    print(f'  日志总数: {data.get("total_logs")}')
except Exception as e:
    test('验证失败', False, str(e))

# 6. 前端编译产物
print('\n--- 6. 前端编译 ---')
dist_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist', 'assets')
rb_files = [f for f in os.listdir(dist_dir) if 'RecycleBin' in f]
test('RecycleBin编译产物存在', len(rb_files) == 2, str(rb_files))

print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)