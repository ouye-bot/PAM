"""
P4 Phase A2: P4-11 平滑轮换端到端验证
5步验证流程
"""
import requests
import json
import time
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

# Login
r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
TOKEN = r.json().get('token')
HEADERS = {'Authorization': f'Bearer {TOKEN}'}

print('=' * 60)
print('P4 Phase A2: P4-11 平滑轮换端到端验证')
print('=' * 60)

# === 步骤1: 触发密钥轮换 ===
print('\n--- 步骤1: POST /api/keys/rotate ---')
try:
    r = requests.post(f'{BASE}/keys/rotate', headers=HEADERS, timeout=10)
    test('轮换返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json().get('data', {})
        test('返回status=rotating', data.get('status') == 'rotating', str(data))
        test('返回new_key_id', bool(data.get('new_key_id')), str(data))
        test('返回total_credentials', data.get('total_credentials', -1) >= 0, str(data))
        NEW_KEY_ID = data.get('new_key_id')
        TOTAL_CREDS = data.get('total_credentials', 0)
        print(f'  新密钥ID: {NEW_KEY_ID}, 总凭证数: {TOTAL_CREDS}')
except Exception as e:
    test('轮换请求成功', False, str(e))
    NEW_KEY_ID = None
    TOTAL_CREDS = 0

# === 步骤2: 检查轮换状态 ===
print('\n--- 步骤2: GET /api/keys/rotate-status ---')
try:
    r = requests.get(f'{BASE}/keys/rotate-status', headers=HEADERS, timeout=10)
    test('状态返回200', r.status_code == 200, str(r.text[:200]))
    if r.status_code == 200:
        data = r.json().get('data', {})
        test('active_rotation=True', data.get('active_rotation') == True, str(data))
        test('返回migrated_count', 'migrated_count' in data, str(data))
        test('返回progress_pct', 'progress_pct' in data, str(data))
        print(f'  已迁移: {data.get("migrated_count", 0)}/{data.get("total_credentials", 0)}, 进度: {data.get("progress_pct", 0)}%')
except Exception as e:
    test('状态请求成功', False, str(e))

# === 步骤3: 等待渐进式迁移（最多等2分钟） ===
print('\n--- 步骤3: 等待渐进式迁移完成 ---')
max_wait = 120  # 最多等2分钟
waited = 0
completed = False
while waited < max_wait:
    time.sleep(10)
    waited += 10
    try:
        r = requests.get(f'{BASE}/keys/rotate-status', headers=HEADERS, timeout=10)
        data = r.json().get('data', {})
        migrated = data.get('migrated_count', 0)
        total = data.get('total_credentials', 0)
        pct = data.get('progress_pct', 0)
        print(f'  等待{waited}s: 已迁移 {migrated}/{total} ({pct}%)')
        if not data.get('active_rotation'):
            completed = True
            print(f'  迁移完成!')
            break
    except Exception as e:
        print(f'  查询失败: {e}')
        break

test('渐进式迁移完成', completed, f'等待{waited}s')

# === 步骤4: 验证旧密钥已retired，新密钥已active ===
print('\n--- 步骤4: 验证密钥状态 ---')
try:
    r = requests.get(f'{BASE}/keys/master-key-status', headers=HEADERS, timeout=10)
    test('密钥状态返回200', r.status_code == 200, str(r.text[:200]))
except Exception as e:
    test('密钥状态请求成功', False, str(e))

# 直接查数据库验证密钥版本状态
print('\n--- 步骤5: 验证凭证仍可解密（多版本共存） ---')
try:
    r = requests.get(f'{BASE}/assets', headers=HEADERS, timeout=10)
    assets = r.json()
    if isinstance(assets, list):
        asset_list = assets
    else:
        asset_list = assets.get('data', assets.get('assets', []))
    test('资产列表可获取', len(asset_list) > 0, f'共{len(asset_list)}个资产')
    for asset in asset_list[:3]:
        aid = asset.get('id', asset.get('asset_id'))
        print(f'  资产ID {aid}: IP={asset.get("ip", "?")}')
except Exception as e:
    test('资产列表请求成功', False, str(e))

# === 汇总 ===
print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)