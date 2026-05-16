"""
Phase A2: P4-11 平滑轮换快速验证（无长时间等待）
"""
import requests
import json
import sys

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

def pjson(data):
    return json.dumps(data, ensure_ascii=False, indent=2)

# Login
r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
data = r.json()
TOKEN = data.get('token')
HEADERS = {'Authorization': f'Bearer {TOKEN}'}
test('登录成功', bool(TOKEN), str(data)[:200])

print('\n' + '=' * 60)
print('Phase A2: P4-11 平滑轮换快速验证')
print('=' * 60)

# === 步骤1: 检查当前密钥状态 ===
print('\n--- 步骤1: 检查当前密钥状态 ---')
try:
    r = requests.get(f'{BASE}/keys/master-key-status', headers=HEADERS, timeout=10)
    test('密钥状态返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json().get('data', {})
        print(f'  密钥源: {data.get("source", "?")}')
        print(f'  环境变量已配置: {data.get("environment", {}).get("configured")}')
except Exception as e:
    test('密钥状态请求失败', False, str(e))

# === 步骤2: 检查当前轮换状态 ===
print('\n--- 步骤2: 检查当前轮换状态 ---')
try:
    r = requests.get(f'{BASE}/keys/rotate-status', headers=HEADERS, timeout=10)
    test('轮换状态返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json().get('data', {})
        active = data.get('active_rotation', False)
        test('不应有活跃轮换', not active, str(data))
        print(f'  当前状态: {"活跃轮换中" if active else "无活跃轮换"}')
except Exception as e:
    test('轮换状态请求失败', False, str(e))

# === 步骤3: 触发密钥轮换 ===
print('\n--- 步骤3: 触发密钥轮换 ---')
try:
    r = requests.post(f'{BASE}/keys/rotate', headers=HEADERS, timeout=10)
    test('轮换返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json().get('data', {})
        test('返回status=rotating', data.get('status') == 'rotating', str(data))
        test('返回new_key_id', bool(data.get('new_key_id')), str(data))
        test('返回total_credentials>=0', data.get('total_credentials', -1) >= 0, str(data))
        NEW_KEY_ID = data.get('new_key_id')
        TOTAL_CREDS = data.get('total_credentials', 0)
        print(f'  新密钥ID: {NEW_KEY_ID}')
        print(f'  总凭证数: {TOTAL_CREDS}')
except Exception as e:
    test('轮换请求失败', False, str(e))

# === 步骤4: 再次检查轮换状态 ===
print('\n--- 步骤4: 验证轮换已激活 ---')
try:
    r = requests.get(f'{BASE}/keys/rotate-status', headers=HEADERS, timeout=10)
    if r.status_code == 200:
        data = r.json().get('data', {})
        test('active_rotation=True', data.get('active_rotation') == True, str(data))
        test('返回migrated_count', 'migrated_count' in data, str(data))
        test('返回progress_pct', 'progress_pct' in data, str(data))
        print(f'  已迁移: {data.get("migrated_count", 0)}/{data.get("total_credentials", 0)}')
        print(f'  进度: {data.get("progress_pct", 0)}%')
except Exception as e:
    test('状态验证失败', False, str(e))

# === 步骤5: 验证资产列表可正常访问 ===
print('\n--- 步骤5: 验证资产列表 ---')
try:
    r = requests.get(f'{BASE}/assets', headers=HEADERS, timeout=10)
    assets = r.json()
    if isinstance(assets, list):
        asset_list = assets
    else:
        asset_list = assets.get('data', assets.get('assets', []))
    test('资产列表可获取', isinstance(asset_list, list), f'类型: {type(asset_list).__name__}')
    print(f'  共 {len(asset_list)} 个资产')
    for asset in asset_list[:3]:
        aid = asset.get('id', asset.get('asset_id', '?'))
        print(f'  资产ID {aid}: {asset.get("name", asset.get("asset_name", "?"))}')
except Exception as e:
    test('资产列表请求失败', False, str(e))

# === 步骤6: 验证调度器任务记录 ===
print('\n--- 步骤6: 验证调度器任务 ---')
try:
    r = requests.get(f'{BASE}/scheduler/jobs', headers=HEADERS, timeout=10)
    if r.status_code == 200:
        data = r.json()
        jobs = data if isinstance(data, list) else data.get('data', data.get('jobs', []))
        re_encrypt_jobs = [j for j in jobs if 're_encrypt' in str(j.get('id', '')).lower()]
        test('渐进式重加密任务存在', len(re_encrypt_jobs) > 0, f'任务: {re_encrypt_jobs}')
        print(f'  调度器任务数: {len(jobs)}')
        for j in jobs:
            print(f'    ID: {j.get("id", "?")}, Next: {j.get("next_run_time", "?")}')
except Exception as e:
    test('调度器任务查询（可能无权限）', False, str(e))

# === 汇总 ===
print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)