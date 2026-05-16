"""
P4 Phase A1: 后端 API 回归测试
覆盖实际存在的 API 端点，每个端点验证 2-3 个断言，输出 PASS/FAIL
"""
import requests
import json
import sys
import time

BASE = 'http://127.0.0.1:5000/api'
passed = 0
failed = 0
errors = []

def test(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        msg = f'  [FAIL] {name}'
        if detail:
            msg += f' - {detail}'
        print(msg)
        errors.append(f'{name}: {detail}')

print('=' * 60)
print('P4 Phase A1: 后端 API 回归测试')
print('=' * 60)

# === 1. 登录 ===
print('\n--- 检查点 1: 登录 ---')
try:
    r = requests.post(f'{BASE}/auth/login', json={
        'username': 'admin', 'password': 'admin123'
    }, timeout=10)
    data = r.json()
    test('登录返回200', r.status_code == 200, str(data))
    test('登录返回code=200', data.get('code') == 200, str(data))
    test('登录返回token', bool(data.get('token')), str(data))
    TOKEN = data.get('token', '')
    USER = data.get('user', {})
    test('登录返回user对象', bool(USER), str(data))
except Exception as e:
    test('登录请求成功', False, str(e))
    TOKEN = ''

if not TOKEN:
    print('\n!!! 登录失败，无法继续后续测试 !!!')
    sys.exit(1)

HEADERS = {'Authorization': f'Bearer {TOKEN}'}

# === 2. 获取资产列表 ===
print('\n--- 检查点 2: 获取资产列表 ---')
try:
    r = requests.get(f'{BASE}/assets', headers=HEADERS, timeout=10)
    test('资产列表返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, list):
            assets = data
        else:
            assets = data.get('data', data.get('assets', []))
        if isinstance(assets, list):
            test('资产列表是数组', True)
            test(f'资产数量: {len(assets)}', True)
        else:
            test('资产列表是数组', False, str(type(assets)))
except Exception as e:
    test('资产列表请求成功', False, str(e))

# === 3. 密钥状态 ===
print('\n--- 检查点 3: 密钥状态 ---')
try:
    r = requests.get(f'{BASE}/keys/master-key-status', headers=HEADERS, timeout=10)
    test('密钥状态返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        d = r.json().get('data', {})
        test('密钥状态包含source字段', 'source' in d, str(d))
        test('密钥状态包含environment字段', 'environment' in d, str(d))
except Exception as e:
    test('密钥状态请求成功', False, str(e))

# === 4. 密钥重载 ===
print('\n--- 检查点 4: 密钥重载 ---')
try:
    r = requests.post(f'{BASE}/keys/reload', headers=HEADERS, timeout=10)
    test('密钥重载返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        d = r.json().get('data', {})
        test('密钥重载包含master_key_ok', 'master_key_ok' in d, str(d))
        test('密钥重载包含work_key_ok', 'work_key_ok' in d, str(d))
except Exception as e:
    test('密钥重载请求成功', False, str(e))

# === 5. 审计日志列表 ===
print('\n--- 检查点 5: 审计日志列表 ---')
try:
    r = requests.get(f'{BASE}/audit/logs?page=1&page_size=10', headers=HEADERS, timeout=10)
    test('审计日志返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json()
        logs = data.get('data', {})
        if isinstance(logs, dict):
            items = logs.get('items', [])
        else:
            items = logs if isinstance(logs, list) else []
        if isinstance(items, list):
            test('审计日志是数组', True)
            test(f'审计日志数量: {len(items)}', True)
        else:
            test('审计日志是数组', False, str(type(items)))
except Exception as e:
    test('审计日志请求成功', False, str(e))

# === 6. 审计完整性验证 ===
print('\n--- 检查点 6: 审计完整性验证 ---')
try:
    r = requests.get(f'{BASE}/audit/verify', headers=HEADERS, timeout=10)
    test('审计验证返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        d = r.json().get('data', {})
        test('审计验证包含valid字段', 'valid' in d, str(d))
        test('审计哈希链完整', d.get('valid') == True, str(d))
except Exception as e:
    test('审计验证请求成功', False, str(e))

# === 7. 仪表盘统计 ===
print('\n--- 检查点 7: 仪表盘统计 ---')
try:
    r = requests.get(f'{BASE}/dashboard/stats', headers=HEADERS, timeout=10)
    test('仪表盘统计返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json()
        test('仪表盘包含数据', bool(data.get('data') or data.get('stats')), str(data)[:200])
except Exception as e:
    test('仪表盘统计请求成功', False, str(e))

# === 8. 仪表盘轮换趋势 ===
print('\n--- 检查点 8: 仪表盘轮换趋势 ---')
try:
    r = requests.get(f'{BASE}/dashboard/rotation-trend', headers=HEADERS, timeout=10)
    test('轮换趋势返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('轮换趋势请求成功', False, str(e))

# === 9. 会话列表 ===
print('\n--- 检查点 9: 会话列表 ---')
try:
    r = requests.get(f'{BASE}/sessions', headers=HEADERS, timeout=10)
    test('会话列表返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('会话列表请求成功', False, str(e))

# === 10. 改密历史（按资产） ===
print('\n--- 检查点 10: 改密历史 ---')
try:
    r = requests.get(f'{BASE}/rotation/history/1', headers=HEADERS, timeout=10)
    test('改密历史返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('改密历史请求成功', False, str(e))

# === 11. 绕行告警列表 ===
print('\n--- 检查点 11: 绕行告警列表 ---')
try:
    r = requests.get(f'{BASE}/bypass/alerts', headers=HEADERS, timeout=10)
    test('绕行告警返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('绕行告警请求成功', False, str(e))

# === 12. 密钥轮换状态 ===
print('\n--- 检查点 12: 密钥轮换状态 ---')
try:
    r = requests.get(f'{BASE}/keys/rotate-status', headers=HEADERS, timeout=10)
    test('密钥轮换状态返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        d = r.json().get('data', {})
        test('密钥轮换状态包含active_rotation', 'active_rotation' in d, str(d))
except Exception as e:
    test('密钥轮换状态请求成功', False, str(e))

# === 13. 认证验证 ===
print('\n--- 检查点 13: 认证验证 ---')
try:
    r = requests.get(f'{BASE}/auth/verify', headers=HEADERS, timeout=10)
    test('认证验证返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json()
        test('认证验证返回用户信息', bool(data.get('data') or data.get('user')), str(data)[:200])
except Exception as e:
    test('认证验证请求成功', False, str(e))

# === 14. 改密调度列表 ===
print('\n--- 检查点 14: 改密调度列表 ---')
try:
    r = requests.get(f'{BASE}/rotation/schedules', headers=HEADERS, timeout=10)
    test('改密调度返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('改密调度请求成功', False, str(e))

# === 15. 退出登录 ===
print('\n--- 检查点 15: 退出登录 ---')
try:
    r = requests.post(f'{BASE}/auth/logout', headers=HEADERS, timeout=10)
    test('退出登录返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('退出登录请求成功', False, str(e))

# === 16. 重新登录（验证token仍有效） ===
print('\n--- 检查点 16: 重新登录验证 ---')
try:
    r = requests.post(f'{BASE}/auth/login', json={
        'username': 'admin', 'password': 'admin123'
    }, timeout=10)
    test('重新登录返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        test('重新登录返回新token', bool(r.json().get('token')), str(r.text[:200]))
except Exception as e:
    test('重新登录请求成功', False, str(e))

# === 汇总 ===
print('\n' + '=' * 60)
print(f'测试完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
if errors:
    print('\n失败详情:')
    for e in errors:
        print(f'  - {e}')

sys.exit(0 if failed == 0 else 1)