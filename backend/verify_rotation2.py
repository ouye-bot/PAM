"""验证轮换后凭证可解密（使用正确的API路由）"""
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
print('Phase A2: P4-11 轮换后验证')
print('=' * 60)

# === 验证1: 获取所有资产和凭证ID ===
print('\n--- 验证1: 获取资产和凭证ID映射 ---')
try:
    r = requests.get(f'{BASE}/assets', headers=headers, timeout=10)
    assets = r.json()
    if isinstance(assets, list):
        asset_list = assets
    else:
        asset_list = assets.get('data', assets.get('assets', []))
    test(f'资产列表可获取', len(asset_list) > 0, f'共{len(asset_list)}个资产')
    
    # 从每个资产获取credential_id
    cred_ids = []
    for asset in asset_list[:3]:
        aid = asset.get('id')
        # Try the credential list endpoint
        r2 = requests.get(f'{BASE}/assets/{aid}', headers=headers, timeout=10)
        if r2.status_code == 200:
            detail = r2.json()
            print(f'  资产ID {aid} 详情: {json.dumps(detail, ensure_ascii=False)[:200]}')
except Exception as e:
    test('资产列表请求失败', False, str(e))

# === 验证2: 直接用数据库Flask命令检查凭证 ===
print('\n--- 验证2: 尝试通过API查看凭证 ---')
try:
    r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
    token = r.json().get('token')
    headers = {'Authorization': f'Bearer {token}'}
    
    # Try to get credentials list first
    r2 = requests.get(f'{BASE}/assets', headers=headers, timeout=10)
    assets = r2.json()
    if isinstance(assets, list):
        asset_list = assets
    else:
        asset_list = assets.get('data', assets.get('assets', []))
    
    for asset in asset_list[:2]:
        aid = asset.get('id')
        if aid:
            r3 = requests.post(f'{BASE}/assets/credentials/{aid}/view', headers=headers, timeout=10)
            print(f'  POST /assets/credentials/{aid}/view -> Status={r3.status_code}')
            if r3.status_code == 200:
                data = r3.json()
                test(f'资产{aid}凭证可解密', data.get('code') == 200 and bool(data.get('password')), str(data)[:100])
            else:
                print(f'  响应: {r3.text[:200]}')
except Exception as e:
    test('凭证查看请求失败', False, str(e))

# === 验证3: 检查密钥状态 ===
print('\n--- 验证3: 密钥版本状态 ---')
try:
    r = requests.get(f'{BASE}/keys/master-key-status', headers=headers, timeout=10)
    test('密钥状态返回200', r.status_code == 200)
    if r.status_code == 200:
        data = r.json().get('data', {})
        print(f'  密钥源: {data.get("source")}')
        print(f'  环境已配置: {data.get("environment", {}).get("configured")}')
except Exception as e:
    test('密钥状态请求失败', False, str(e))

# === 验证4: 检查轮换状态（已完成） ===
print('\n--- 验证4: 轮换状态 ---')
try:
    r = requests.get(f'{BASE}/keys/rotate-status', headers=headers, timeout=10)
    test('轮换状态返回200', r.status_code == 200)
    if r.status_code == 200:
        data = r.json().get('data', {})
        active = data.get('active_rotation', False)
        test('轮换已完成', not active, f'active_rotation={active}')
        print(f'  活跃轮换: {active}')
except Exception as e:
    test('轮换状态请求失败', False, str(e))

# === 汇总 ===
print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)